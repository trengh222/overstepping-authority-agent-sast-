"""零候选漏报的逐阶段定位（基准集 CD 用）。

对 run_suite.py 产物里「漏报且 items 为空」的用例，重新走一遍抽取→规则闸门，
定位候选死在哪一阶段：

  E0  端点未抽出
  P0  端点抽出但参数列表为空
  P1  有参数但都不满足 is_resource_identifier（命名/类型不是资源标识）
  S1  有资源标识参数但 trace_to_sinks 追不到 sink
  G1  特权闸门 privilege_op=False（只认写操作的误伤）
  G2  特权通过但守卫/公开路径/内联鉴权放行
  F1  B6 无实体字段事实
  X   其它

用法：python tests/benchmark/bac_owasp/diag_zero.py --run runs/bac_owasp_full1
输出：<run>/analysis/zero_diag.md
"""
import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from access_scan.cli import _SUFFIX_LANG
from access_scan.dataflow.taint import trace_to_sinks
from access_scan.extractor.base import FRONTENDS, link_guards
from access_scan.rules.idor import is_resource_identifier
from access_scan.rules.vertical import recall_vertical


def _load(run: str, name: str) -> Dict[str, Any]:
    p = os.path.join(run, name)
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _src_files(case_dir: Path) -> List[Path]:
    return sorted(p for p in case_dir.rglob("*")
                  if p.is_file() and p.suffix.lower() in _SUFFIX_LANG)


def _probe(case_dir: Path):
    endpoints, guards, chains, ctxmap = [], [], [], {}
    ext_cache: Dict[str, Any] = {}
    for f in _src_files(case_dir):
        lang = _SUFFIX_LANG[f.suffix.lower()]
        if lang not in ext_cache:
            ext_cache[lang] = FRONTENDS[lang]()
        ext = ext_cache[lang]
        src = f.read_bytes()
        ast = ext.parse(src)
        endpoints.extend(ext.extract_endpoints(ast, str(f)))
        g, ch = ext.extract_guards(ast, str(f))
        guards.extend(g)
        chains.extend(ch)
        ctxmap.update(ext.endpoint_contexts(ast, str(f), src))
    return endpoints, link_guards(guards, chains), ctxmap


def _classify(cat: str, endpoints, guards, ctxmap) -> str:
    if not endpoints:
        return "E0 端点未抽出"
    ep = endpoints[0]
    if cat in ("A2-Vertical", "A3-Unauth", "A4-ClientAuth"):
        if not ep.privilege_op:
            return "G1 特权闸门 privilege_op=False"
        ctx = ctxmap.get(ep.handler)
        return "G3 规则放行(公开路径/内联鉴权/守卫覆盖)" if ctx is not None else "G4 无上下文"
    if cat == "B6-FieldExposure":
        return "F1 无实体字段事实"
    # A1
    if not ep.params:
        return "P0 参数列表为空"
    idp = [p for p in ep.params if is_resource_identifier(p.name, p.type)]
    if not idp:
        return "P1 参数非资源标识(" + ",".join(p.name for p in ep.params[:4]) + ")"
    ctx = ctxmap.get(ep.handler)
    if ctx is None:
        return "C1 无 handler 上下文"
    hits = sum(1 for p in idp
               for _ in trace_to_sinks(ctx.node, p.name, ctx))
    return "S1 追不到 sink" if hits == 0 else "X 其它"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    args = ap.parse_args(argv)
    per = {r["case_id"]: r for r in _load(args.run, "per_case.json")["results"]}
    sc = _load(args.run, "score.json")
    zero = [cid for cid in sc["false_negatives"]
            if not (per.get(cid, {}).get("result") or {}).get("items")]
    corpus = Path(args.run).resolve().parents[1] / "tests" / "benchmark" / "bac_owasp" / "corpus"
    rows, agg = [], Counter()
    for cid in zero:
        exp = per[cid]["expected"]
        lang, cat = exp["language"], exp["category"]
        eps, guards, ctxmap = _probe(corpus / lang / cid)
        stage = _classify(cat, eps, guards, ctxmap)
        rows.append((lang, cat, cid, stage, len(eps)))
        agg[(lang, cat, stage.split()[0])] += 1
    out = os.path.join(args.run, "analysis")
    os.makedirs(out, exist_ok=True)
    lines = ["# 零候选漏报的阶段定位", "",
             f"共 {len(rows)} 例（漏报且没有任何候选）", ""]
    lines += ["| 语言 | 类别 | 阶段 | 例数 |", "|---|---|---|---|"]
    for (lang, cat, st), n in sorted(agg.items()):
        lines.append(f"| {lang} | {cat} | {st} | {n} |")
    lines += ["", "## 明细", "", "| case | 类别 | 终点阶段 | 端点数 |", "|---|---|---|---|"]
    for lang, cat, cid, stage, n in rows:
        lines.append(f"| `{cid}` | {cat} | {stage} | {n} |")
    with open(os.path.join(out, "zero_diag.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"zero-candidate cases: {len(rows)} -> {out}\\zero_diag.md")
    for (lang, cat, st), n in sorted(agg.items()):
        print(f"{lang:7} {cat:17} {st:4} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
