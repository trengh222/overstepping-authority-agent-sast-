"""Java 真数据流验证：def-use 别名 + 跨过程调用链。运行：python tests/test_java_dataflow.py"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli

_FIXTURES = _REPO / "tests" / "fixtures" / "java_cross"


def test_cross_procedure_and_alias():
    kept, _ = cli.scan(_FIXTURES)
    a1s = [c for c in kept if c.subtype == "A1"]
    paths = {c.endpoint.path for c in a1s}
    assert "/api/order/{id}" in paths, f"跨过程正样本应检出: {paths}"
    assert "/api/order/alias/{id}" in paths, f"别名+跨过程应检出: {paths}"
    assert "/api/order/mine/{id}" not in paths, "归属约束应过滤负样本"
    assert len(a1s) == 2, f"应恰好 2 个 A1，实际 {len(a1s)}"


def test_cross_chain_flow_recorded():
    kept, _ = cli.scan(_FIXTURES)
    by_path = {c.endpoint.path: c for c in kept}
    flow = " | ".join(by_path["/api/order/{id}"].access.flow)
    assert "orderService.findById" in flow, flow
    assert "orderRepository.findById" in flow, flow
    # 实体应落到 Order（Repository 去后缀）
    assert by_path["/api/order/{id}"].access.entity == "Order"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()