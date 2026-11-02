"""run_suite.py 产物分析：语料模式对照 + 漏报/误报明细（供人工复核根因）。

用法：
  python tests/benchmark/bac_owasp/analyze.py --run runs/bac_owasp_full1
输出：<run>/analysis/corpus_delta.md、<run>/analysis/fn_fp_detail.md
"""
import argparse
import json
import os
from typing import Any, Dict, List


def _load(run: str, name: str) -> Dict[str, Any]:
    p = os.path.join(run, name)
    if not os.path.exists(p):
        return {}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _records(pc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {r.get("case_id"): r for r in (pc.get("results") or [])}


def _result(rec: Dict[str, Any]) -> Dict[str, Any]:
    return rec.get("result") or {}


def corpus_delta(pc: Dict[str, Any], cs: Dict[str, Any]) -> str:
    per = _records(pc)
    flagged = {cid for cid, r in per.items() if _result(r).get("flagged")}
    corp = {cid for cid, fs in (cs.get("per_case_flagged") or {}).items() if fs}
    lost = sorted(flagged - corp)
    gained = sorted(corp - flagged)
    lines = ["# 语料模式对照（隔离逐例 vs 整目录一次扫描）", "",
             f"- 逐例标红：{len(flagged)} 例；整目录标红：{len(corp)} 例",
             f"- 整目录 finding 数：{cs.get('findings_total')}；未归属：{cs.get('unattributed')}",
             "", f"## 整目录扫描后消失的标红（{len(lost)}）", ""]
    for cid in lost:
        exp = (per.get(cid) or {}).get("expected") or {}
        lines.append(f"- `{cid}`（{exp.get('category')}/{exp.get('language')}，"
                     f"expected={exp.get('real_vulnerability')}）")
    lines += ["", f"## 整目录扫描新增的标红（{len(gained)}）", ""]
    for cid in gained:
        exp = (per.get(cid) or {}).get("expected") or {}
        lines.append(f"- `{cid}`（{exp.get('category')}/{exp.get('language')}，"
                     f"expected={exp.get('real_vulnerability')}）")
    return "\n".join(lines) + "\n"


def _brief(item: Dict[str, Any]) -> str:
    return (f"{item.get('method')} {item.get('path')} · {item.get('subtype')} · "
            f"{item.get('verdict')} · reachability={item.get('reachability_class')}"
            f"/{item.get('disposition')} · symbolic={item.get('symbolic_reachability')}"
            f" · gate={item.get('gate_verification') or '-'}"
            f" · keys={','.join(item.get('evidence_keys') or [])}")


def fn_fp_detail(pc: Dict[str, Any], sc: Dict[str, Any]) -> str:
    per = _records(pc)
    lines = ["# 漏报 / 误报明细（含候选摘要，供根因复核）", ""]
    for title, rows in (("漏报（正例未标红）", sc.get("false_negatives") or []),
                        ("误报（负例被标红）", sc.get("false_positives") or [])):
        lines += [f"## {title}（{len(rows)}）", ""]
        for item in rows:
            cid = item.get("case_id") if isinstance(item, dict) else item
            rec = per.get(cid) or {}
            exp = rec.get("expected") or {}
            res = _result(rec)
            lines.append(f"### `{cid}` · {exp.get('category')} / {exp.get('language')}")
            lines.append("")
            lines.append(f"- 期望：real_vulnerability={exp.get('real_vulnerability')} "
                         f"endpoint=`{exp.get('endpoint_path')}` source=`{exp.get('source_file')}`")
            note = (exp.get("note") or "").strip()
            if note:
                lines.append(f"- 标注说明：{note[:300]}")
            lines.append(f"- 判定分布：{res.get('verdicts') or '{}'}"
                         f" subtypes={res.get('subtypes') or '{}'}")
            for it in (res.get("items") or [])[:3]:
                lines.append(f"- 候选：{_brief(it)}")
            lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    args = ap.parse_args(argv)
    pc = _load(args.run, "per_case.json")
    cs = _load(args.run, "corpus_scan.json")
    sc = _load(args.run, "score.json")
    out = os.path.join(args.run, "analysis")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "corpus_delta.md"), "w", encoding="utf-8") as fh:
        fh.write(corpus_delta(pc, cs))
    with open(os.path.join(out, "fn_fp_detail.md"), "w", encoding="utf-8") as fh:
        fh.write(fn_fp_detail(pc, sc))
    print(f"analysis -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
