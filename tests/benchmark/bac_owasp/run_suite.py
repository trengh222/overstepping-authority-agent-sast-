"""越权基准集运行器：**逐用例隔离扫描** + 结果落盘（OWASP Benchmark 计分法的输入）。

为什么要逐用例隔离：本套件里很多负例靠「目录内的全局守卫/拦截器」表达安全语义；
整目录一次扫描时守卫会跨用例泄漏（实测 D1），用例间会互相污染标签。逐用例
`cli.run(case_dir)` 既隔离了语义，也更接近「每个 BenchmarkTest 独立部署」的
OWASP Benchmark 原意；整目录扫描作为对照（`--corpus-mode`）用于量化泄漏。

用法（Windows PowerShell）::

    cd tests/benchmark/bac_owasp
    $env:PYTHONPATH = "$PWD\..\..\..\src"
    python run_suite.py --out ..\..\..\runs\bac_owasp_<timestamp>

产物：``<out>/per_case.json``、``<out>/per_case.csv``、``<out>/corpus_scan.json``、``<out>/run.log``。
"""
import argparse
import csv
import json
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

SUITE = Path(__file__).resolve().parent
CORPUS = SUITE / "corpus"
FRAGMENTS = SUITE / "fragments"

import access_scan.cli as cli  # noqa: E402

_FLAGGED = ("LIKELY", "CONFIRMED")


def _log(path: Path, text: str) -> None:
    line = f"{datetime.now().strftime('%H:%M:%S')} {text}"
    print(line)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_expected() -> dict:
    """合并 fragments/*.csv（子代理按语言分片写入，表头一致）。"""
    rows = {}
    for path in sorted(FRAGMENTS.glob("*.csv")):
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                cid = (r.get("case_id") or "").strip()
                if not cid:
                    continue
                if cid in rows:
                    raise SystemExit(f"expected 重复: {cid}（{path.name}）")
                rows[cid] = {
                    "case_id": cid,
                    "category": (r.get("category") or "").strip(),
                    "language": (r.get("language") or "").strip().lower(),
                    "real_vulnerability": int((r.get("real_vulnerability") or "0").strip()),
                    "endpoint_path": (r.get("endpoint_path") or "").strip(),
                    "source_file": (r.get("source_file") or "").strip(),
                    "note": (r.get("note") or "").strip(),
                }
    return rows


def _summarize(findings) -> dict:
    out = {"verdicts": {}, "subtypes": {}, "flagged": False, "items": []}
    for f in findings:
        out["verdicts"][f.verdict] = out["verdicts"].get(f.verdict, 0) + 1
        out["subtypes"][f.subtype] = out["subtypes"].get(f.subtype, 0) + 1
        if f.verdict in _FLAGGED:
            out["flagged"] = True
        ev = f.evidence or {}
        out["items"].append({
            "subtype": f.subtype,
            "verdict": f.verdict,
            "confidence": round(float(f.confidence), 3),
            "method": f.candidate.endpoint.method,
            "path": f.candidate.endpoint.path,
            "handler": f.candidate.endpoint.handler,
            "reachability_class": f.reachability_class,
            "disposition": f.disposition,
            "evidence_keys": sorted(ev.keys()),
            "gate_verification": ev.get("gate_verification", ""),
            "dynamic_sites": ev.get("dynamic_sites", []),
            "symbolic_reachability": ev.get("symbolic_reachability", ""),
        })
    return out


def run_case(case_dir: Path) -> dict:
    t0 = time.perf_counter()
    try:
        findings, _ = cli.run(case_dir, judge=None, adversarial=False, symbolic=True)
        res = _summarize(findings)
    except Exception:  # 单用例失败不拖垮整轮
        res = {"verdicts": {}, "subtypes": {}, "flagged": False, "items": [],
               "error": traceback.format_exc(limit=3)}
    res["elapsed"] = round(time.perf_counter() - t0, 3)
    return res


def corpus_mode(rows: dict) -> dict:
    """整目录一次扫描：把 finding 归属到用例目录，用于量化守卫跨用例泄漏（D1）。"""
    try:
        findings, _ = cli.run(CORPUS, judge=None, adversarial=False, symbolic=False)
    except Exception:
        return {"error": traceback.format_exc(limit=3), "per_case_flagged": {}}
    per_case = {}
    unattributed = 0
    for f in findings:
        if f.verdict not in _FLAGGED:
            continue
        file = str(f.candidate.endpoint.file).replace("\\", "/")
        marker = "/corpus/"
        idx = file.lower().find(marker)
        hit = None
        if idx >= 0:
            rest = file[idx + len(marker):]
            parts = rest.split("/")
            if len(parts) >= 2:
                hit = parts[1]
        if hit is None:
            unattributed += 1
            continue
        per_case.setdefault(hit, []).append({
            "subtype": f.subtype, "path": f.candidate.endpoint.path,
            "verdict": f.verdict, "file": file,
        })
    return {"per_case_flagged": per_case, "unattributed": unattributed,
            "findings_total": len(findings)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="越权基准集运行器")
    ap.add_argument("--out", required=True, help="产物目录")
    ap.add_argument("--only", default="", help="只跑某个 case_id 前缀（调试）")
    ap.add_argument("--corpus-mode", action="store_true", help="额外跑一次整目录扫描（对照）")
    args = ap.parse_args(argv)

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / "run.log"
    _log(log_path, f"=== bac_owasp run {datetime.now().isoformat(timespec='seconds')} ===")

    expected = load_expected()
    cases = []
    for lang_dir in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        for case_dir in sorted(p for p in lang_dir.iterdir() if p.is_dir()):
            if args.only and not case_dir.name.startswith(args.only):
                continue
            cases.append(case_dir)
    _log(log_path, f"expected={len(expected)} case_dirs={len(cases)}")

    results = []
    missing = []
    for i, case_dir in enumerate(cases, 1):
        cid = case_dir.name
        exp = expected.get(cid)
        if exp is None:
            missing.append(cid)
        res = run_case(case_dir)
        results.append({"case_id": cid, "dir": str(case_dir.relative_to(REPO)),
                        "expected": exp, "result": res})
        flag = "FLAG" if res["flagged"] else "----"
        _log(log_path, f"[{i}/{len(cases)}] {cid:22s} {flag} "
                       f"{res['verdicts']} {res['elapsed']}s"
                       + (f"  ERROR: {res['error'].splitlines()[-1]}" if res.get("error") else ""))

    if missing:
        _log(log_path, f"WARNING 缺 expected 标注的用例 {len(missing)} 个: {missing[:8]}")

    with open(out / "per_case.json", "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now().isoformat(timespec="seconds"),
                   "suite": str(SUITE.relative_to(REPO)), "results": results}, f,
                  ensure_ascii=False, indent=1)

    with open(out / "per_case.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "category", "language", "real_vulnerability",
                    "flagged", "verdicts", "subtypes", "n_findings", "elapsed_s"])
        for r in results:
            exp = r["expected"] or {}
            res = r["result"]
            w.writerow([r["case_id"], exp.get("category", ""), exp.get("language", ""),
                        exp.get("real_vulnerability", ""), int(res["flagged"]),
                        json.dumps(res["verdicts"], ensure_ascii=False),
                        json.dumps(res["subtypes"], ensure_ascii=False),
                        len(res["items"]), res["elapsed"]])

    if args.corpus_mode:
        cm = corpus_mode(expected)
        with open(out / "corpus_scan.json", "w", encoding="utf-8") as f:
            json.dump(cm, f, ensure_ascii=False, indent=1)
        _log(log_path, f"corpus_mode findings={cm.get('findings_total')} "
                       f"attributed_cases={len(cm.get('per_case_flagged', {}))}")

    _log(log_path, f"=== done: {len(results)} cases -> {out} ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
