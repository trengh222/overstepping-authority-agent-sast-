"""可达性剪枝（方向三，配置开关）——证据收集 + LLM 判定测试。

运行：python -m pytest tests/test_reachability.py -q
覆盖：开关名提取、flag_refs 证据收集（声明值/未声明）、scan 回填 flag_refs、
证据包注入 feature_flags、LLM 判定 unreachable 时降级 UNCERTAIN。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.llm.prompts import build_evidence_pkg
from access_scan.llm.verdict import decide
from access_scan.rules.reachability import collect_flag_refs, extract_flag_names


def test_extract_flag_names():
    src = "if not config['export.enabled']:\n    return 'disabled'"
    assert "export.enabled" in extract_flag_names(src)


def test_collect_flag_refs_declared():
    src = "if not config['export.enabled']:\n    return 'disabled'"
    refs = collect_flag_refs(src, {"export.enabled": False})
    assert refs == [{"name": "export.enabled", "declared": False}]


def test_collect_flag_refs_undeclared():
    src = "if not config['export.enabled']:\n    return 'disabled'"
    refs = collect_flag_refs(src, {})
    assert refs == [{"name": "export.enabled", "declared": None}]


def test_collect_flag_refs_no_flag():
    assert collect_flag_refs("return Order.query.get(oid)", {}) == []


_REACH = _REPO / "tests" / "fixtures" / "reachability"
_EXPORT = _REACH / "java_export"


def test_scan_flag_refs_field():
    cands, _ = cli.scan(_EXPORT)
    export = [c for c in cands if "export" in c.endpoint.path]
    assert export, "export 端点应被检出为 IDOR 候选"
    assert export[0].flag_refs, "应收集到配置开关引用"
    assert export[0].flag_refs[0]["name"] == "export.enabled"


def test_evidence_pkg_injects_feature_flags():
    cands, _ = cli.scan(_EXPORT)
    export = [c for c in cands if "export" in c.endpoint.path][0]
    pkg = build_evidence_pkg(export)
    assert "feature_flags" in pkg
    assert pkg["feature_flags"][0]["name"] == "export.enabled"
    assert pkg["feature_flags"][0]["declared"] is False


def test_decide_unreachable_downgrade():
    cands, _ = cli.scan(_EXPORT)
    export = [c for c in cands if "export" in c.endpoint.path][0]
    llm = {
        "is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
        "reasoning": "flags.isEnabled('export.enabled') 关闭，路径不可达",
        "evidence_lines": ["line 3: if (!flags.isEnabled(\"export.enabled\"))"],
        "reachability": "unreachable",
    }
    f = decide(export, llm)
    assert f.verdict == "UNCERTAIN", f"unreachable 应降级 UNCERTAIN，实际 {f.verdict}"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
