"""LLM 判定层基线（真实 LLM，方案 §9 / §11）。

运行：
  python tests/benchmark/run_llm_baseline.py                 # 全量（samples=3 + 对抗复核）
  python tests/benchmark/run_llm_baseline.py --samples 1     # 快速跑（成本约 1/3）
  python tests/benchmark/run_llm_baseline.py --limit 3       # 只跑前 3 个候选（连通性验证）
  python tests/benchmark/run_llm_baseline.py --no-cache      # 不使用缓存

输出：
  1) verdict 分布（CONFIRMED / LIKELY / UNCERTAIN）与 reachability/disposition 分布；
  2) evidence_lines 缺失率（复用 tests/test_evidence_gap.compute_evidence_gap）；
  3) LLM 判定层相对 ground_truth 的召回/精确率，与静态召回层对照；
  4) 被 LLM 误杀的正样本（静态检出 → LLM 判 UNCERTAIN）与对抗复核否定数。

注意：基线走 VerdictPipeline（含 LLM 判定 + 对抗复核），与 run_benchmark.py 的
纯静态召回层是两层口径，可对照看「LLM 层把静态候选压制了多少」。
"""
import argparse
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))
sys.path.insert(0, str(_REPO / "tests"))

import yaml  # noqa: E402

from access_scan import cli  # noqa: E402
from access_scan.cache import VerdictCache  # noqa: E402
from access_scan.llm.client import LLMJudge  # noqa: E402
from access_scan.llm.verdict import VerdictPipeline  # noqa: E402
from test_evidence_gap import compute_evidence_gap  # noqa: E402

_BENCH = Path(__file__).parent
_FIXTURES = _REPO / "tests" / "fixtures"


def _norm(p) -> str:
    return str(p).replace("\\", "/")


def _load_gt():
    data = yaml.safe_load((_BENCH / "ground_truth.yaml").read_text(encoding="utf-8"))
    return data["targets"], data.get("negative", [])


def _match(target, endpoint, subtype) -> bool:
    f = _norm(endpoint.file)
    return (f.endswith(target["file"]) and endpoint.path == target["path"]
            and (target.get("subtype") is None or subtype == target["subtype"]))


def _llm_layer_eval(findings, targets):
    """LLM 判定层口径：只有 LIKELY/CONFIRMED 才算告警。"""
    positives = [t for t in targets if t["vulnerable"]]
    alerts = [f for f in findings if f.verdict in ("LIKELY", "CONFIRMED")]
    hit, misses = [], []
    for t in positives:
        if any(_match(t, f.candidate.endpoint, f.subtype) for f in alerts):
            hit.append(t)
        else:
            misses.append(t)
    fp_alerts = [f for f in alerts
                 if not any(_match(t, f.candidate.endpoint, f.subtype) for t in positives)]
    tp = len(hit)
    total = len(positives)
    precision = tp / (tp + len(fp_alerts)) if (tp + len(fp_alerts)) else 0.0
    return {
        "tp": tp, "fn": len(misses), "total": total,
        "alerts": len(alerts), "fp_alerts": fp_alerts,
        "recall": tp / total if total else 0.0, "precision": precision,
        "misses": misses, "static_recall": tp, "suppressed": len(findings) - len(alerts),
    }


def _static_layer_recall(candidates, targets) -> int:
    positives = [t for t in targets if t["vulnerable"]]
    return sum(1 for t in positives
               if any(_match(t, c.endpoint, c.subtype) for c in candidates))


def _count(fs, attr) -> dict:
    out: dict = {}
    for f in fs:
        k = getattr(f, attr, None) or "-"
        out[k] = out.get(k, 0) + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="真实 LLM 判定层基线")
    ap.add_argument("--dir", default=str(_FIXTURES), help="扫描目录（默认 tests/fixtures）")
    ap.add_argument("--model", default="", help="覆盖 LLM 模型（默认取 config/llm.yaml）")
    ap.add_argument("--samples", type=int, default=3, help="采样投票次数（默认 3）")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 个候选（0=全部）")
    ap.add_argument("--no-adversarial", action="store_true", help="关闭对抗复核")
    ap.add_argument("--no-cache", action="store_true", help="不使用判定缓存")
    ap.add_argument("--cache", default="", help="缓存文件路径（默认按 samples 区分）")
    args = ap.parse_args()

    scan_dir = Path(args.dir)
    targets, _negatives = _load_gt()

    guards = []
    t0 = time.perf_counter()
    all_candidates, _gateway = cli.scan(scan_dir, guards_out=guards)
    scan_dt = time.perf_counter() - t0
    candidates = all_candidates[: args.limit] if args.limit > 0 else all_candidates

    judge = LLMJudge(model=args.model or None)
    print(f"模型: {judge.model}  端点: {judge.base_url}  SDK 可用: {judge.available}")
    print(f"采样: {args.samples}  对抗复核: {not args.no_adversarial}  "
          f"候选: {len(candidates)}  静态扫描: {scan_dt:.2f}s")
    if not judge.available:
        print("LLM 不可用（缺少 SDK/token），退化为静态 LIKELY，基线无意义。")
        return 2

    cache = None
    if not args.no_cache:
        cache_path = Path(args.cache) if args.cache else (
            _BENCH / ".cache"
            / f"llm_{judge.model.replace('/', '_')}_s{args.samples}"
              f"{'_adv' if not args.no_adversarial else ''}.db")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache = VerdictCache(str(cache_path))
        print(f"缓存: {cache_path}")

    pipeline = VerdictPipeline(judge=judge, cache=cache,
                               adversarial=not args.no_adversarial,
                               samples=args.samples, guards=guards)
    print("-" * 78)
    findings = []
    t1 = time.perf_counter()
    for i, c in enumerate(candidates, 1):
        f = pipeline.run([c])[0]
        findings.append(f)
        print(f"[{i:>2}/{len(candidates)}] {c.subtype} {c.endpoint.method} "
              f"{c.endpoint.path} ({Path(c.endpoint.file).name}) → {f.verdict} "
              f"({f.reachability_class or '-'}/{f.disposition or '-'}) "
              f"conf={f.confidence:.2f}", flush=True)
    findings = cli.attach_counterexamples(findings)
    llm_dt = time.perf_counter() - t1

    gap = compute_evidence_gap(findings)
    m = _llm_layer_eval(findings, targets)
    static_tp = _static_layer_recall(all_candidates, targets)

    print("=" * 78)
    print("LLM 判定层基线结果（真实 LLM）")
    print("=" * 78)
    print(f"耗时: {llm_dt:.1f}s  API 调用: {judge.calls}  缓存命中: {pipeline.cache_hits}")
    print(f"verdict: CONFIRMED={gap['confirmed']}  LIKELY={gap['likely']}  "
          f"UNCERTAIN={gap['uncertain']}  (经 LLM 判定 {gap['judged']})")
    print(f"evidence_lines 缺失率: {gap['missing_rate']:.1%} "
          f"({gap['evidence_missing']}/{gap['total_vuln']} 条判漏洞)")
    print(f"reachability_class: {_count(findings, 'reachability_class')}")
    print(f"disposition:        {_count(findings, 'disposition')}")
    print("")
    print(f"LLM 层告警: {m['alerts']}  TP={m['tp']}  FN={m['fn']}  FP={len(m['fp_alerts'])}")
    print(f"LLM 层召回   = {m['recall']:.1%}  ({m['tp']}/{m['total']})   "
          f"静态层召回 = {static_tp}/{m['total']} ({static_tp / m['total']:.1%})")
    print(f"LLM 层精确率 = {m['precision']:.1%}")
    print(f"被 LLM 压制（静态候选 → UNCERTAIN）: {len(candidates) - m['alerts']}")
    if args.limit > 0:
        print(f"\n（--limit 模式：仅评估前 {len(candidates)}/{len(all_candidates)} 个候选，"
              f"下方漏报列表不代表真实水平）")
    if m["misses"]:
        print("\n--- LLM 层漏报 / 误杀（静态已检出） ---")
        for t in m["misses"]:
            print(f"  ✗ {t.get('subtype', '?')} {t['path']}  ({t['file']})")
    if m["fp_alerts"]:
        print("\n--- LLM 层误报（告警但不匹配 ground truth） ---")
        for f in m["fp_alerts"]:
            print(f"  ! [{f.subtype}] {f.candidate.endpoint.method} "
                  f"{f.candidate.endpoint.path}  ({Path(f.candidate.endpoint.file).name})")

    uncertain = [f for f in findings if f.verdict == "UNCERTAIN"]
    if uncertain:
        print("\n--- UNCERTAIN 的判定理由（截断） ---")
        for f in uncertain:
            reason = (f.llm_reasoning or "").replace("\n", " ")[:110]
            print(f"  · [{f.subtype}] {Path(f.candidate.endpoint.file).name} "
                  f"{f.candidate.endpoint.path} → {reason}")

    if cache is not None:
        cache.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
