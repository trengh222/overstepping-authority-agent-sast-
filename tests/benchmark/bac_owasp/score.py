"""越权基准集计分器（OWASP Benchmark 口径）。

输入：``run_suite.py`` 产出的 ``per_case.json``。
输出：``score.md``（人读）+ ``score.json``（机读）。

指标（与 OWASP Benchmark 一致）::

    TPR = TP / (TP + FN)      # 真实越权被报出
    FPR = FP / (FP + TN)      # 安全用例被误报
    Score = TPR - FPR         # 官方 ranking 指标，取值 [-1, 1]

额外给出精确率、FN/FP 清单（便于人工复核标注）、按 category / language / origin
（authored=人工撰写，generated=生成器批量生成）的分解。
"""
import argparse
import json
from pathlib import Path

_CAT_ORDER = ["A1-IDOR", "A2-Vertical", "A3-Unauth", "A4-ClientAuth", "B6-FieldExposure"]
_LANG_ORDER = ["java", "js", "go"]


def _metrics(pairs):
    """pairs: [(real_vuln:int, flagged:int)] -> dict"""
    tp = sum(1 for e, f in pairs if e == 1 and f == 1)
    fn = sum(1 for e, f in pairs if e == 1 and f == 0)
    fp = sum(1 for e, f in pairs if e == 0 and f == 1)
    tn = sum(1 for e, f in pairs if e == 0 and f == 0)
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "tpr": round(tpr, 4), "fpr": round(fpr, 4),
            "score": round(tpr - fpr, 4), "precision": round(prec, 4),
            "positives": tp + fn, "negatives": fp + tn}


def _group(rows, key):
    groups = {}
    for r in rows:
        groups.setdefault(r[key] or "(未标注)", []).append(r)
    return groups


def _origin(case_id: str) -> str:
    return "generated" if case_id.startswith("gen-") else "authored"


def _table(title: str, groups: dict, order=None) -> list:
    keys = sorted(groups, key=lambda k: (order.index(k) if order and k in order else 99, k))
    lines = [f"### {title}", "",
             "| 分组 | 正例 | 负例 | TP | FN | FP | TN | TPR | FPR | Score | 精确率 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k in keys:
        m = _metrics([(r["real"], r["flagged"]) for r in groups[k]])
        lines.append(f"| {k} | {m['positives']} | {m['negatives']} | {m['tp']} | {m['fn']} | "
                     f"{m['fp']} | {m['tn']} | {m['tpr']:.1%} | {m['fpr']:.1%} | "
                     f"{m['score']:+.3f} | {m['precision']:.1%} |")
    return lines + [""]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="越权基准集计分")
    ap.add_argument("--run", required=True, help="run_suite.py 产物目录（含 per_case.json）")
    ap.add_argument("--out", default="", help="输出目录（默认同 --run）")
    args = ap.parse_args(argv)

    run_dir = Path(args.run).resolve()
    out = Path(args.out).resolve() if args.out else run_dir
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((run_dir / "per_case.json").read_text(encoding="utf-8"))

    rows, unlabeled, errors = [], [], []
    for r in data["results"]:
        exp = r.get("expected")
        if not exp:
            unlabeled.append(r["case_id"])
            continue
        if r["result"].get("error"):
            errors.append(r["case_id"])
        rows.append({"case_id": r["case_id"],
                     "category": exp["category"],
                     "language": exp["language"],
                     "origin": _origin(r["case_id"]),
                     "real": int(exp["real_vulnerability"]),
                     "flagged": int(bool(r["result"]["flagged"])),
                     "verdicts": r["result"]["verdicts"],
                     "items": r["result"]["items"],
                     "note": exp.get("note", "")})

    overall = _metrics([(r["real"], r["flagged"]) for r in rows])
    per_cat = _group(rows, "category")
    per_lang = _group(rows, "language")
    per_origin = _group(rows, "origin")

    fns = [r for r in rows if r["real"] == 1 and not r["flagged"]]
    fps = [r for r in rows if r["real"] == 0 and r["flagged"]]

    md = [f"# 越权基准集计分报告（OWASP Benchmark 口径）", "",
          f"- 运行目录：`{run_dir}`",
          f"- 用例数：{len(rows)}（正例 {overall['positives']} / 负例 {overall['negatives']}）；"
          f"未标注 {len(unlabeled)}；扫描异常 {len(errors)}",
          f"- **TPR {overall['tpr']:.1%} · FPR {overall['fpr']:.1%} · "
          f"Score {overall['score']:+.3f} · 精确率 {overall['precision']:.1%}**", ""]
    md += _table("总体", {"ALL": rows})
    md += _table("按类别", per_cat, _CAT_ORDER)
    md += _table("按语言", per_lang, _LANG_ORDER)
    md += _table("按来源", per_origin)

    md += ["### 漏报（正例未被标红）", ""]
    md += [f"- `{r['case_id']}` {r['category']} / {r['language']}：{r['note']}；verdicts={r['verdicts']}"
           for r in fns] or ["- （无）"]
    md += ["", "### 误报（负例被标红）", ""]
    md += [f"- `{r['case_id']}` {r['category']} / {r['language']}：{r['note']}；"
           f"命中 {[i['subtype'] for i in r['items'] if i['verdict'] in ('LIKELY', 'CONFIRMED')]}"
           for r in fps] or ["- （无）"]
    if unlabeled:
        md += ["", f"### 未标注用例（不计分）", ""] + [f"- `{c}`" for c in unlabeled]
    if errors:
        md += ["", f"### 扫描异常用例", ""] + [f"- `{c}`" for c in errors]

    (out / "score.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    payload = {"overall": overall,
               "by_category": {k: _metrics([(r["real"], r["flagged"]) for r in v])
                               for k, v in per_cat.items()},
               "by_language": {k: _metrics([(r["real"], r["flagged"]) for r in v])
                               for k, v in per_lang.items()},
               "by_origin": {k: _metrics([(r["real"], r["flagged"]) for r in v])
                             for k, v in per_origin.items()},
               "false_negatives": [r["case_id"] for r in fns],
               "false_positives": [r["case_id"] for r in fps],
               "unlabeled": unlabeled, "errors": errors}
    (out / "score.json").write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                                    encoding="utf-8")
    print("\n".join(md[:8]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
