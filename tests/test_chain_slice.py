"""方向一（子项）：Java 跨过程调用链真实源码切片（chain_slices）单元测试。

运行：python -m pytest tests/test_chain_slice.py -q
覆盖：跨过程候选带方法体源码切片、切片注入证据包 call_chain_source、
切片序列化往返、非跨过程（无切片）不注入。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.ir import candidate_from_dict, candidate_to_dict
from access_scan.llm.prompts import build_evidence_pkg

_CROSS = _REPO / "tests" / "fixtures" / "java_cross"


def _sliced_candidate():
    cands, _ = cli.scan(_CROSS)
    sliced = [c for c in cands if c.access.chain_slices]
    assert sliced, "java_cross 跨过程候选应带源码切片"
    return sliced[0]


def test_java_cross_collects_chain_slices():
    cands, _ = cli.scan(_CROSS)
    sliced = [c for c in cands if c.access.chain_slices]
    assert sliced, "Controller→Service 跨过程应收集方法体切片"
    sl = sliced[0].access.chain_slices[0]
    assert "OrderService" in sl["call"], f"切片 call 应指向 Service 方法，实际 {sl['call']}"
    assert "findById" in sl["code"] or "orderRepository" in sl["code"], "切片应含真实方法体源码"
    assert sl["line_start"] > 0 and sl["line_end"] >= sl["line_start"]
    assert not sl["truncated"], "短方法体不应被截断"


def test_evidence_pkg_injects_call_chain_source():
    cand = _sliced_candidate()
    pkg = build_evidence_pkg(cand)
    assert "call_chain_source" in pkg
    assert pkg["call_chain_source"][0]["call"] == cand.access.chain_slices[0]["call"]
    assert "findById" in pkg["call_chain_source"][0]["code"]


def test_chain_slices_roundtrip():
    cand = _sliced_candidate()
    back = candidate_from_dict(candidate_to_dict(cand))
    assert back.access.chain_slices == cand.access.chain_slices


def test_no_slices_no_injection():
    cands, _ = cli.scan(_REPO / "tests" / "fixtures" / "java" / "vertical" / "a3")
    assert cands
    for c in cands:
        assert not c.access.chain_slices, "无跨过程（同层 sink）不应有切片"
        assert "call_chain_source" not in build_evidence_pkg(c)


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()