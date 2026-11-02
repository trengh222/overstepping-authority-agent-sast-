"""M4 多语言前端验证。运行：python tests/test_m4_frontends.py

覆盖：JavaScript(Express)/Go(Gin) 的端点提取、规则 A 跨语言召回与别名传播。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli

_FIXTURES = _REPO / "tests" / "fixtures"


def test_node_express():
    kept, _ = cli.scan(_FIXTURES / "node")
    a1s = [c for c in kept if c.subtype == "A1"]
    assert len(a1s) == 1
    c = a1s[0]
    assert c.endpoint.path == "/api/order/:id"
    assert c.endpoint.params[0].name == "id"
    assert c.access.entity == "Order"


def test_go_gin():
    kept, _ = cli.scan(_FIXTURES / "go")
    a1s = [c for c in kept if c.subtype == "A1"]
    assert len(a1s) == 1
    assert a1s[0].access.entity == "t_order"
    assert a1s[0].endpoint.params[0].name == "id"


def test_node_alias_propagation():
    # uid = req.params.id → findUnique({where:{id:uid}}) 单跳别名也应命中
    kept, _ = cli.scan(_FIXTURES / "node_alias")
    a1s = [c for c in kept if c.subtype == "A1"]
    assert len(a1s) == 1
    assert a1s[0].access.entity == "Order"
    assert a1s[0].endpoint.params[0].name == "id"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()