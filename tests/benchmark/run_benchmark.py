"""越权检测基准标定（方案 §11）。

运行：python tests/benchmark/run_benchmark.py

流程：扫描自建基准集（tests/fixtures，Java/JS/Go）→ 与 ground_truth.yaml 比对 →
计算召回率/精确率/F1；另扫 WebGoat 真实靶场记录前端 gap。

注：Python / PHP 的检测前端已从项目中移除（语言范围收敛为 Java/Go/JS），
因此 VAmPI（Flask）与 DVWA BAC（PHP）两节 gap 记录一并移除，历史结论保留在
``tests/benchmark/README.md`` 与 ``targets_real.yaml`` 的注释里。
"""
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

import yaml  # noqa: E402

from access_scan import cli  # noqa: E402
from access_scan.extractor.base import FRONTENDS  # noqa: E402

_BENCH = Path(__file__).parent
_FIXTURES = _REPO / "tests" / "fixtures"
_REAL_GT = _BENCH / "targets_real.yaml"
_SUFFIX_LANG = cli._SUFFIX_LANG


def _norm(p) -> str:
    return str(p).replace("\\", "/")


def _load_gt():
    data = yaml.safe_load((_BENCH / "ground_truth.yaml").read_text(encoding="utf-8"))
    return data["targets"], data.get("negative", [])


def _match(t, c) -> bool:
    f = _norm(c.endpoint.file)
    return (f.endswith(t["file"]) and c.endpoint.path == t["path"]
            and (t.get("subtype") is None or c.subtype == t["subtype"]))


def _evaluate(candidates, targets):
    positives = [t for t in targets if t["vulnerable"]]
    hit = [False] * len(positives)
    for c in candidates:
        for i, t in enumerate(positives):
            if _match(t, c):
                hit[i] = True
    tp = sum(hit)
    fn = len(positives) - tp
    # 误报 = 未匹配任何正样本的检出（不能用 len(candidates)-tp，重复匹配时会算错）
    false_pos = [c for c in candidates
                 if not any(_match(t, c) for t in positives)]
    fp = len(false_pos)
    recall = tp / len(positives) if positives else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * recall * precision / (recall + precision)) if (recall + precision) else 0.0
    misses = [t for i, t in enumerate(positives) if not hit[i]]
    return {
        "tp": tp, "fn": fn, "fp": fp, "total_gt": len(positives),
        "recall": recall, "precision": precision, "f1": f1,
        "misses": misses, "false_pos": false_pos,
    }


def _fmt_candidate(c) -> str:
    return f"[{c.subtype}] {c.endpoint.method} {c.endpoint.path} ({_norm(c.endpoint.file)})"


def _load_real_gt():
    data = yaml.safe_load(_REAL_GT.read_text(encoding="utf-8")) or {}
    return data.get("webgoat", {})


def _extract_endpoints(d, lang):
    """对目录 d 提取某语言全部端点（用于区分「端点 gap」与「规则/sink gap」）。"""
    eps = []
    ext = FRONTENDS[lang]()
    for f in d.rglob("*"):
        if f.is_file() and f.suffix.lower() in _SUFFIX_LANG and _SUFFIX_LANG[f.suffix.lower()] == lang:
            ast = ext.parse(f.read_bytes())
            eps.extend(ext.extract_endpoints(ast, str(f)))
    return eps


def _report_real_section():
    wg = _load_real_gt()
    print("\n" + "=" * 64)
    print("真实靶场 gap 记录（WebGoat IDOR，方案 §11.1）")
    print("=" * 64)

    # ---- WebGoat ----
    wg_dir = _BENCH / wg.get("dir", "")
    print("\n--- WebGoat IDOR lesson（Java）---")
    if not wg_dir.exists():
        print("  未检出（目录不存在）")
    else:
        eps = _extract_endpoints(wg_dir, "java")
        kept, gw = cli.scan(wg_dir)
        cands = kept + gw
        pos = wg.get("positives", [])
        hit = 0
        for t in pos:
            found = any(c.endpoint.method == t["method"] and c.endpoint.path == t["path"]
                        for c in cands)
            hit += int(found)
            if not found:
                print(f"    ✗ 漏报 {t['method']} {t['path']}  ({t.get('handler','')})")
        print(f"  端点提取: {len(eps)}  检出: {len(cands)}  召回: {hit}/{len(pos)}")
        print(f"  gap 根因: sink 定义不含「构造函数模拟 DB」({wg.get('dir','')})")


def _report_perf_section():
    print("\n" + "=" * 64)
    print("性能验收（方案 §11.2：全量冷启动 ≤10min / 10万行）")
    print("=" * 64)
    files = [p for p in _BENCH.rglob("*")
             if p.is_file() and p.suffix.lower() in _SUFFIX_LANG]
    total_lines = 0
    for p in files:
        try:
            total_lines += len(p.read_bytes().splitlines())
        except OSError:
            pass
    t0 = time.perf_counter()
    kept, gw = cli.scan(_BENCH)
    dt = time.perf_counter() - t0
    cands = kept + gw
    norm = dt / total_lines * 100_000 if total_lines else 0.0
    print(f"扫描文件: {len(files)}  代码行: {total_lines}  检出: {len(cands)}")
    print(f"耗时: {dt:.2f}s ({dt/60:.2f}min)")
    print(f"归一化(10万行): {norm:.2f}s")
    print(f"达标: {'✓ ≤10min' if dt <= 600 else '✗ 超时(>10min)'}")


def main():
    targets, negatives = _load_gt()
    kept, gateway = cli.scan(_FIXTURES)
    candidates = kept + gateway

    m = _evaluate(candidates, targets)

    print("=" * 64)
    print("越权检测基准标定（静态召回层）")
    print("=" * 64)
    print(f"基准正样本: {m['total_gt']}  扫描检出: {len(candidates)}")
    print(f"TP={m['tp']}  FN={m['fn']}  FP={m['fp']}")
    print(f"召回率 Recall   = {m['recall']:.1%}  (目标 ≥85%)")
    print(f"精确率 Precision = {m['precision']:.1%}  (目标 ≥70%)")
    print(f"F1              = {m['f1']:.1%}")

    if m["misses"]:
        print("\n--- 漏报 (FN) ---")
        for t in m["misses"]:
            print(f"  ✗ {t.get('subtype','?')} {t['path']}  ({t['file']})")
    if m["false_pos"]:
        print("\n--- 误报 (FP) ---")
        for c in m["false_pos"]:
            print(f"  ! {_fmt_candidate(c)}")

    print("\n--- 负样本核对（应均不出现） ---")
    for n in negatives:
        leaked = any(_norm(c.endpoint.file).endswith(n["file"]) and c.endpoint.path == n["path"]
                     for c in candidates)
        print(f"  {'✗ 误报' if leaked else '✓ 通过'}  {n['path']}  ({n['file']})")

    # ---- 真实靶场（WebGoat，Java）----
    _report_real_section()
    _report_perf_section()


if __name__ == "__main__":
    main()