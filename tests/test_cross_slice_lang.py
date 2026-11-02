"""Node/Go 跨过程切片（chain_slices）单元测试。

运行：python -m pytest tests/test_cross_slice_lang.py -q
覆盖：两语言 handler→Service 跨过程收集方法体切片、切片注入证据包、
带归属约束的负样本不误报。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.llm.prompts import build_evidence_pkg


def _sliced(dir_name):
    cands, _ = cli.scan(_REPO / "tests" / "fixtures" / dir_name)
    return [c for c in cands if c.access.chain_slices]


def test_node_cross_chain_slices():
    sliced = _sliced("node_cross")
    assert sliced, "Node handler→Service 跨过程应收集方法体切片"
    sl = sliced[0].access.chain_slices[0]
    assert sl["call"] == "findById", f"切片 call 应为 findById，实际 {sl['call']}"
    assert "findUnique" in sl["code"], "切片应含 Service 方法体真实源码"
    assert sl["line_start"] > 0 and sl["line_end"] >= sl["line_start"]
    pkg = build_evidence_pkg(sliced[0])
    assert "call_chain_source" in pkg


def test_go_cross_chain_slices():
    sliced = _sliced("go_cross")
    assert sliced, "Go handler→Service 跨过程应收集方法体切片"
    sl = sliced[0].access.chain_slices[0]
    assert sl["call"] == "FindByID", f"切片 call 应为 FindByID，实际 {sl['call']}"
    assert "QueryRow" in sl["code"], "切片应含 Service 方法体真实源码"
    pkg = build_evidence_pkg(sliced[0])
    assert "call_chain_source" in pkg


def test_negative_ownership_no_cross_report():
    # 负样本：带 userId/user_id 归属约束的跨过程不应产出候选
    for dir_name in ("node_cross", "go_cross"):
        cands, _ = cli.scan(_REPO / "tests" / "fixtures" / dir_name)
        mine = [c for c in cands if "mine" in c.endpoint.path]
        assert not mine, f"{dir_name} 带归属约束的跨过程不应被误报"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
