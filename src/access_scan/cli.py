"""命令行入口（M1+M2+M3）：静态召回（规则 A/B）→ L4 过滤 → LLM 判定 + 缓存 → 报告。

用法：
  python -m access_scan.cli <path> [--format text|json|sarif] [-o out]
      [--llm | --no-llm] [--no-adversarial] [--cache cache.db]
      [--state state.db]                       # 增量扫描基线（M3.2）
  python -m access_scan.cli tag --findings out.json --key <endpoint.id 子串>
      --decision fp|confirm [--entity NAME]     # 打标回写所有权模型（M3.1）

LLM 默认策略：检测到 ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY 时自动启用（默认模型 deepseek-v4-pro）；
不可用/失败时候选保留为 LIKELY，静态证据不丢失（方案 §9.5）。
"""
import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .cache import ScanState, VerdictCache
from .config import record_ownership_feedback, load_feature_flags
from .dataflow.hierarchy import Hierarchy, merge_into
from .dataflow.symexec import CtxResolver, symbolic_reachability
from .extractor.base import FRONTENDS, link_guards
from .extractor.java import (JavaExtractor, guard_from_dict, guard_to_dict)
from .extractor import go, node  # noqa: F401  注册语言前端（Java / Go / JS）
from .extractor.java import collect_custom_auth_annotations
from .ir import (Candidate, Finding, candidate_from_dict, candidate_to_dict,
                 resource_from_dict, resource_to_dict)
from .llm.client import LLMJudge
from .llm.verdict import VerdictPipeline, promote_with_counterexample, unreachable_finding
from .report.sarif import render as render_sarif
from .report.markdown import render as render_markdown
from .rules.build_reachability import dead_sink_reason, file_build_excluded
from .rules.build_manifest import collect_build_facts, module_build_excluded, module_of_file
from .rules.data_facts import data_fact_hints
from .rules.filter import apply_filters, gateway_finding
from .rules.registration import collect_mounts, unmounted_reason
from .rules.spring_registration import (collect_spring_facts, java_unregistered_reason,
                                        project_blockers)
from .rules.idor import recall_idor
from .rules.massign import recall_massign
from .rules.exposure import recall_exposure
from .rules.reflection import reflection_hint, reflection_sites
from .rules.reachability import collect_flag_refs
from .rules.repo_config import collect_repo_flags
from .rules.vertical import recall_vertical

# 支持的后缀 → 语言（多语言前端分派：Java / Go / JavaScript(TypeScript)）
_SUFFIX_LANG = {
    ".java": "java", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
}


def _ser(obj: Any) -> Any:
    """把 IR 对象转成可 JSON 序列化的原生结构（Enum → value）。"""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (list, tuple)):
        return [_ser(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _ser(v) for k, v in obj.items()}
    if is_dataclass(obj):
        return _ser(asdict(obj))
    return obj


def _prescan_custom_auth(files) -> set:
    """D5：预扫描 Java 切面，收集自定义鉴权注解（@Before("@annotation(Xxx)") + 鉴权逻辑）。"""
    texts = []
    for f in files:
        if f.suffix.lower() != ".java":
            continue
        try:
            texts.append(("java", f.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            pass
    return collect_custom_auth_annotations(texts)


def _reachability_hints(cand: Candidate, ctx, lang: str, file_excluded: bool,
                        mounted, whole_project: bool, spring_facts=None,
                        build_facts=None) -> dict:
    """构建可达 + 注册可达的确定性提示，供 verdict 层自动关闭 / 降级。"""
    hints: dict = {}
    if file_excluded:
        hints["build"] = "整个文件被构建标记排除（//go:build ignore），不参与编译"
        return hints
    reason = dead_sink_reason(ctx.node, cand.access.sink_line, lang)
    if reason:
        hints["build"] = reason
    manifest_reason = module_build_excluded(cand.endpoint.file, build_facts, whole_project)
    if manifest_reason and "build" not in hints:
        hints["build"] = manifest_reason
    reg = unmounted_reason(lang, cand.endpoint.container, mounted, whole_project)
    if lang == "java" and not reg:
        reg = java_unregistered_reason(cand.endpoint.container, spring_facts,
                                       whole_project, cand.endpoint.file)
        if reg:
            hints["registration_deterministic"] = "1"  # Spring 扫描事实：无需 LLM 即关闭
    if reg:
        hints["registration"] = reg
    hints.update(data_fact_hints(cand))
    if getattr(cand.access, "dynamic_sites", None):
        hints["reflection"] = reflection_hint(cand.access.dynamic_sites)
    return hints


def scan(path: Path, extractor=None,
         state: Optional[ScanState] = None,
         guards_out: Optional[List] = None) -> Tuple[List[Candidate], List[Candidate]]:
    """静态召回 + L4 过滤（多语言：按文件后缀分派前端，M4）。

    state 非空时启用增量：未变更文件的候选/守卫/链路/资源直接复用基线。
    guards_out 非空时，把 link 后的全局守卫清单回填进去（供 LLM 判定作框架上下文）。
    返回 (kept, gateway_downgrade)。
    """
    if extractor is None:
        if path.is_file():
            files = [path] if path.suffix.lower() in _SUFFIX_LANG else []
        else:
            files = sorted(p for p in path.rglob("*")
                           if p.is_file() and p.suffix.lower() in _SUFFIX_LANG)
        ext_cache: dict = {}
        custom_auth = _prescan_custom_auth(files)

        def ext_for(f: Path):
            lang = _SUFFIX_LANG[f.suffix.lower()]
            if lang not in ext_cache:
                ext_cache[lang] = FRONTENDS[lang]()
                if lang == "java":
                    ext_cache[lang].custom_auth_annotations = custom_auth  # D5
            return ext_cache[lang]
    else:
        files = [path] if path.is_file() else sorted(path.rglob("*.java"))
        extractor.custom_auth_annotations = _prescan_custom_auth(files)  # D5
        ext_for = lambda f: extractor  # noqa: E731

    # Go 项目级路由索引：registrar 函数 + 跨文件中间件继承（大型 Gin/Echo 工程的常见形态）
    go.reset_project()
    if extractor is None and not path.is_file() and state is None:
        go_sources: dict = {}
        for f in files:
            if f.suffix.lower() == ".go":
                try:
                    go_sources[str(f)] = f.read_bytes()
                except OSError:
                    continue
        if go_sources:
            go.build_project(go_sources)

    # 第一遍：解析全部文件；未变更文件复用 state 基线
    # 注册/构建可达仅在「全量目录冷扫描」判定：单文件/增量无法确认别处，避免误关
    whole_project = extractor is None and not path.is_file() and state is None
    build_facts = collect_build_facts(path) if whole_project else None
    guards, chains, units, resources = [], [], [], []
    hierarchy = Hierarchy()                   # Java 类型继承链（全量扫描建立，增量退回命名约定）
    class_index: dict = {}                    # 类简单名 -> 字段事实（规则 B6 字段敏感性）
    src_map: dict = {}                       # fkey -> (lang, 源码文本)，供构建可达判定
    texts: List[Tuple[str, str]] = []        # (lang, 源码文本)，供注册可达收集挂载调用
    for f in files:
        fkey = str(f)
        ext = ext_for(f)
        if ext is None:
            continue
        try:
            src = f.read_bytes()
        except OSError as e:
            print(f"[warn] 无法读取 {f}: {e}", file=sys.stderr)
            continue
        content_hash = hashlib.sha256(src).hexdigest()
        st = state.get(fkey) if state is not None else None
        if st is not None and st.get("hash") == content_hash:
            guards += [guard_from_dict(g) for g in st.get("guards", [])]
            chains += list(st.get("chains", []))
            units.append((fkey, [candidate_from_dict(x) for x in st.get("candidates", [])],
                          {}, None))
            resources += [resource_from_dict(r) for r in st.get("resources", [])]
            continue
        ast = ext.parse(src)
        lang = getattr(ext, "language", "java")
        text = src.decode("utf-8", errors="replace")
        src_map[fkey] = (lang, text)
        texts.append((lang, text))
        module = module_of_file(fkey, build_facts)
        g, c = ext.extract_guards(ast, fkey)
        for guard in g:
            if not guard.module:  # 前端已给出作用域（Go 按包目录）时不覆盖
                guard.module = module  # D1：守卫只在所属构建模块内生效
        guards.extend(g)
        chains.extend((ref, pats, module) for ref, pats in c)  # 注册链也带模块
        eps = ext.extract_endpoints(ast, fkey)
        for ep in eps:
            if not ep.module:
                ep.module = module
        ctxs = ext.endpoint_contexts(ast, fkey, src)
        res = ext.extract_resources(ast, fkey)
        if lang == "java":
            merge_into(hierarchy, ext.extract_hierarchy(ast, fkey))
        units.append((fkey, eps, ctxs, (content_hash, g, c, res)))
        resources.extend(res)
        if lang == "java":
            class_index.update(ext.collect_class_fields(ast))

    guards = link_guards(guards, chains)
    if build_facts is not None and build_facts.modules:
        # 多模块工程：有源文件的守卫按文件归属；合成守卫沿用注册链所在模块；其余不覆盖任何模块
        for guard in guards:
            if guard.file:
                guard.module = module_of_file(guard.file, build_facts)
            elif not guard.module:
                guard.module = "?"
    if guards_out is not None:
        guards_out.extend(guards)

    # 全局方法体索引（Java 跨过程）：合并每个文件的 {ClassName.methodName: ctx}。
    # 增量命中（ctxs 为空）的文件不贡献，跨过程会退回该文件的单层 sink 判定。
    method_index: dict = {}
    for _fkey, _eps, ctxs, _meta in units:
        if ctxs:
            method_index.update(ctxs)

    # 第二遍：规则 A + 规则 B（全局守卫参与），并将变更文件的产物写入基线
    feature_flags = load_feature_flags()
    mounted = collect_mounts(texts)  # 注册可达：全工程挂载调用（register_blueprint/app.use）
    spring_facts = None
    if whole_project and any(lang == "java" for lang, _ in texts):
        blockers = project_blockers(
            p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in (".xml", ".factories", ".imports"))
        spring_facts = collect_spring_facts(texts, blockers)
    repo_flags = collect_repo_flags(path) if whole_project else {}
    candidates: List[Candidate] = []
    records: List[Tuple[str, List[Candidate], Any]] = []
    from .config import load_sensitive_fields
    sensitive_fields = load_sensitive_fields()
    for fkey, eps, ctxs, meta in units:
        if meta is None:
            file_cands = list(eps)  # 增量复用：基线里已是规则产物（含 reachability hints）
        else:
            lang, text = src_map.get(fkey, ("java", ""))
            file_excluded = file_build_excluded(text, lang)
            file_cands = []
            for ep in eps:
                ctx = ctxs.get(ep.handler)
                if ctx is None:
                    continue
                ep_cands = (recall_idor(ep, ctx, method_index, hierarchy) +
                            recall_vertical(ep, ctx, guards) +
                            recall_massign(ep, ctx) +
                            recall_exposure(ep, ctx, class_index, sensitive_fields))
                dyn_sites = reflection_sites(ctx.node, lang)
                for c in ep_cands:
                    if dyn_sites:
                        c.access.dynamic = True
                        c.access.dynamic_sites = dyn_sites
                    c.flag_refs = collect_flag_refs(ctx.node, feature_flags, repo_flags)
                    c.reachability_hints = _reachability_hints(
                        c, ctx, lang, file_excluded, mounted, whole_project,
                        spring_facts, build_facts)
                file_cands.extend(ep_cands)
        candidates.extend(file_cands)
        records.append((fkey, file_cands, meta))

    if state is not None:
        for fkey, file_cands, meta in records:
            if meta is None:
                continue  # 未变更文件，基线已是最新
            content_hash, g, c, res = meta
            state.put(fkey, content_hash, {
                "candidates": [candidate_to_dict(x) for x in file_cands],
                "guards": [guard_to_dict(x) for x in g],
                "chains": c,
                "resources": [resource_to_dict(r) for r in res],
            })

    from .config import load_rules
    return apply_filters(candidates, load_rules(), resources)


def run(path: Path, extractor: JavaExtractor = None, judge=None, cache=None,
        adversarial: bool = True, state: Optional[ScanState] = None,
        symbolic: bool = True, samples: int = 3, limit: int = 0,
        max_seconds: float = 0.0, parallel_samples: bool = False,
        ) -> Tuple[List[Finding], VerdictPipeline]:
    """静态召回 + L4 过滤 + LLM 判定流水线 + 符号执行反例，返回 (findings, pipeline)。"""
    guards_out: List = []
    candidates, gateway = scan(path, extractor, state=state, guards_out=guards_out)
    if limit > 0:
        candidates = candidates[:limit]  # D10：--limit 控制 LLM 轮候选数
    pipeline = VerdictPipeline(judge=judge, cache=cache, adversarial=adversarial,
                               samples=samples, guards=guards_out,
                               max_seconds=max_seconds, parallel_samples=parallel_samples)
    findings = pipeline.run(candidates, root=path)
    findings += [gateway_finding(c) for c in gateway]
    if symbolic:
        findings = attach_counterexamples(findings)
    return findings, pipeline


_SEVERITY = {"CONFIRMED": 2, "LIKELY": 1, "UNCERTAIN": 0}


def _replace_finding(f: Finding, ev: dict) -> Finding:
    return Finding(candidate=f.candidate, verdict=f.verdict, subtype=f.subtype,
                   confidence=f.confidence, llm_reasoning=f.llm_reasoning,
                   evidence=ev, poc=f.poc, fix_suggestion=f.fix_suggestion,
                   reachability_class=f.reachability_class, disposition=f.disposition)


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """D8：同一端点（method + path + handler）的多条 finding 合并为一条。

    保留 severity/confidence 最高的判定，证据里合并 merged_sinks（去重后的 sink 列表）
    与 merged_count，避免报告里同一端点重复多行。
    """
    order: List[tuple] = []
    best: dict = {}
    for f in findings:
        ep = f.candidate.endpoint
        key = (ep.method, ep.path, ep.handler)
        if key not in best:
            order.append(key)
            ev = dict(f.evidence)
            sinks = [ev["sink_snippet"]] if ev.get("sink_snippet") else []
            ev["merged_sinks"] = sinks
            ev["merged_count"] = 1
            best[key] = _replace_finding(f, ev)
            continue
        cur = best[key]
        sinks = list((cur.evidence or {}).get("merged_sinks") or [])
        sink = f.evidence.get("sink_snippet")
        if sink and sink not in sinks:
            sinks.append(sink)
        take_new = (_SEVERITY.get(f.verdict, 0), f.confidence) > (
            _SEVERITY.get(cur.verdict, 0), cur.confidence)
        chosen = f if take_new else cur
        # 判定与证据必须来自同一候选：否则会出现「gate_verification=passed + disposition=keep」
        # 这类混搭，报告读起来自相矛盾（合并只共享 sink 列表）。
        ev = dict(chosen.evidence)
        ev["merged_sinks"] = sinks
        ev["merged_count"] = len(sinks)
        best[key] = _replace_finding(chosen, ev)
    return [best[k] for k in order]


def attach_counterexamples(findings: List[Finding]) -> List[Finding]:
    """为 A1 的 LIKELY 候选做「数据可达」符号执行三态判定（维度二）。

    sat（约束可满足）→ 反例/PoC 落证据，满足门槛则升级 CONFIRMED；
    unsat（约束不可满足）→ 确定性证明不可触发，自动关闭；
    unsound（循环/未解释条件跑不动）→ 未知，保持 LIKELY 不动。
    """
    resolver = CtxResolver()
    out: List[Finding] = []
    for f in findings:
        if f.verdict == "LIKELY" and f.subtype == "A1":
            ep = f.candidate.endpoint
            acc = f.candidate.access
            ctx, lang = resolver.resolve(ep.file, ep.handler)
            if ctx is not None and acc.sink_line > 0:
                reach = symbolic_reachability(ctx.node, acc.identifier_param,
                                              acc.sink_line, ep, lang)
                status = reach.get("status")
                if status == "sat":
                    f = promote_with_counterexample(
                        f, {"counterexample": reach["counterexample"], "poc": reach["poc"]})
                elif status == "unsat":
                    f = unreachable_finding(f, reach)
        out.append(f)
    return out


def _render_text(findings: List[Finding], pipeline: Optional[VerdictPipeline] = None,
                 llm_note: str = "") -> str:
    if not findings:
        return "未发现越权候选。"
    stats = Counter(f.verdict for f in findings)
    head = (f"越权检测结果：CONFIRMED {stats['CONFIRMED']} / "
            f"LIKELY {stats['LIKELY']} / UNCERTAIN {stats['UNCERTAIN']}")
    if pipeline is not None and pipeline.cache_hits:
        head += f"（LLM 缓存命中 {pipeline.cache_hits}）"
    if llm_note:
        head += f"　【{llm_note}】"
    lines = [head]
    for i, f in enumerate(findings, 1):
        ep = f.candidate.endpoint
        lines.append(
            f"\n[{i}] [{f.verdict}][{f.subtype}] {ep.method} {ep.path}  "
            f"({ep.file}:{ep.line_start}-{ep.line_end}) 置信度 {f.confidence:.2f}"
        )
        lines.append(f"    证据链: {' | '.join(f.candidate.access.flow)}")
        lines.append(f"    sink: {f.candidate.access.sink_snippet}")
        if f.llm_reasoning:
            r = f.llm_reasoning.replace("\n", " ")
            lines.append(f"    LLM: {r[:200]}{'...' if len(r) > 200 else ''}")
        if f.fix_suggestion:
            lines.append(f"    修复: {f.fix_suggestion}")
        if f.poc:
            lines.append(f"    PoC: {f.poc.replace(chr(10), ' ; ')}")
    return "\n".join(lines)


def main(argv: List[str] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "tag":
        return tag_main(argv[1:])
    if argv and argv[0] == "scan":
        argv = argv[1:]

    parser = argparse.ArgumentParser(
        prog="access-scan",
        description="白盒越权检测（M1 静态召回 + M2 LLM 判定/缓存 + M3 过滤/增量/SARIF）",
    )
    parser.add_argument("path", help="Java 文件或目录")
    parser.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    parser.add_argument("-o", "--output", help="结果输出文件")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--llm", dest="llm", action="store_true", default=None,
                       help="启用 LLM 判定（默认：检测到 ANTHROPIC_AUTH_TOKEN 即启用）")
    group.add_argument("--no-llm", dest="llm", action="store_false",
                       help="禁用 LLM 判定（仅静态证据，全部 LIKELY）")
    parser.add_argument("--no-adversarial", action="store_true", help="跳过对抗复核")
    parser.add_argument("--no-symbolic", action="store_true", help="禁用符号执行反例/PoC（M3.3）")
    parser.add_argument("--samples", type=int, default=3,
                        help="LLM 判定采样投票次数（reasoning 模型非确定性 → 多数投票，默认 3）")
    parser.add_argument("--cache", help="LLM 缓存 DB 路径（默认 .access_scan_cache.db）")
    parser.add_argument("--state", help="增量扫描基线 DB 路径（M3.2）")
    parser.add_argument("--limit", type=int, default=0,
                        help="D10：只对前 N 个候选做 LLM 判定（0=不限）")
    parser.add_argument("--llm-timeout", type=float, default=30.0,
                        help="D10：单次 LLM 请求超时秒数（默认 30）")
    parser.add_argument("--llm-retries", type=int, default=1,
                        help="D10：LLM 失败重试次数（默认 1）")
    parser.add_argument("--llm-max-seconds", type=float, default=0.0,
                        help="D10：LLM 轮总时长预算（秒，0=不限；超预算余量降级为静态 LIKELY）")
    parser.add_argument("--llm-parallel", action="store_true",
                        help="D10：采样投票并发（默认顺序）")
    args = parser.parse_args(argv)

    use_llm = args.llm if args.llm is not None else bool(
        os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY"))
    judge = (LLMJudge(timeout=args.llm_timeout, max_retries=args.llm_retries)
             if use_llm else None)
    llm_enabled = judge is not None and judge.available
    llm_note = ("LLM 判定已启用" if llm_enabled
                else "LLM 不可用（缺 API Key/SDK）→ 仅静态证据，全部 LIKELY")
    if judge is not None and not judge.available and use_llm:
        print(f"[warn] {llm_note}", file=sys.stderr)

    cache = VerdictCache(args.cache) if (use_llm or args.cache) else None
    scan_state = ScanState(args.state) if args.state else None
    try:
        findings, pipeline = run(Path(args.path), judge=judge, cache=cache,
                                 adversarial=not args.no_adversarial, state=scan_state,
                                 symbolic=not args.no_symbolic, samples=args.samples,
                                 limit=args.limit, max_seconds=args.llm_max_seconds,
                                 parallel_samples=args.llm_parallel)
    finally:
        if cache is not None:
            cache.close()
        if scan_state is not None:
            scan_state.close()

    findings = dedupe_findings(findings)  # D8：同端点合并，报告不再重复
    if pipeline.budget_exhausted:
        llm_note += "（D10：达到时长预算，余量已降级为静态 LIKELY）"

    stats = {k: sum(1 for f in findings if f.verdict == k)
             for k in ("CONFIRMED", "LIKELY", "UNCERTAIN")}
    if args.format == "sarif":
        payload = json.dumps(render_sarif(findings), ensure_ascii=False, indent=2)
    elif args.format == "markdown":
        payload = render_markdown(findings)
    elif args.format == "json":
        payload = json.dumps({
            "findings": _ser(findings),
            "stats": stats,
            "cache_hits": pipeline.cache_hits,
            "llm": "enabled" if llm_enabled else "disabled",
        }, ensure_ascii=False, indent=2)
    else:
        payload = _render_text(findings, pipeline, llm_note)

    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
        print(f"已写入 {args.output}")
    else:
        print(payload)
    return 0


def tag_main(argv: List[str]) -> int:
    """人工打标（M3.1）：fp（误报，资源公开）/ confirm（确认，私有），回写所有权模型。"""
    parser = argparse.ArgumentParser(prog="access-scan tag", description="打标回写所有权模型")
    parser.add_argument("--findings", required=True, help="scan --format json 输出的文件")
    parser.add_argument("--key", required=True, help="用于匹配 finding 的 endpoint.id 子串")
    parser.add_argument("--decision", required=True, choices=["fp", "confirm"],
                        help="fp=误报(资源公开) / confirm=确认真实漏洞(资源私有)")
    parser.add_argument("--entity", help="实体名；缺省取该 finding 的 entity")
    args = parser.parse_args(argv)

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    matched = [f for f in data["findings"] if args.key in f["candidate"]["endpoint"]["id"]]
    if not matched:
        print(f"未匹配到任何 finding（key={args.key}）")
        return 1
    f = matched[0]
    entity = args.entity or f["candidate"]["access"].get("entity")
    if not entity:
        print("该 finding 无实体名，请用 --entity 指定")
        return 1
    privacy = "PUBLIC" if args.decision == "fp" else "PRIVATE"
    out = record_ownership_feedback(entity, privacy,
                                    reason=f"tag:{args.decision}:{args.key}")
    print(f"已回写所有权模型: {entity} → {privacy}（{out}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())