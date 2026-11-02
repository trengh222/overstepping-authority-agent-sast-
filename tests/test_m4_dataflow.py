"""M4 真数据流验证：JS/Go 的跨语句别名传播 + kill 语义。运行：python tests/test_m4_dataflow.py"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.extractor.node import NodeExtractor
from access_scan.extractor.go import GoExtractor
from access_scan.dataflow.defuse import JsFlow, GoFlow

_js = NodeExtractor()
_go = GoExtractor()


def _first(root, types):
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in types:
            return n
        stack.extend(n.named_children)
    return None


def _js_fn(src):
    return _first(_js.parse(src.encode()).root_node,
                  ("arrow_function", "function_expression"))


def _go_fn(src):
    return _first(_go.parse(src.encode()).root_node, ("func_literal",))


# ---- JavaScript ----
def test_js_direct_source():
    fn = _js_fn("(req, res) => { return orderService.findById(req.params.id); }")
    assert JsFlow(fn, "id").analyze().calls, "直接 findById(req.params.id) 应命中"


def test_js_alias_propagation():
    fn = _js_fn(
        "(req, res) => { const uid = req.params.id;"
        " return prisma.order.findUnique({ where: { id: uid } }); }")
    assert JsFlow(fn, "id").analyze().calls, "别名 uid = req.params.id 后 findUnique 应被追踪"


def test_js_kill_no_report():
    fn = _js_fn(
        "(req, res) => { let uid = req.params.id; uid = 100;"
        " return prisma.order.findUnique({ where: { id: uid } }); }")
    assert not JsFlow(fn, "id").analyze().calls, "uid 重定义为干净值后不应再 taint"


# ---- Go ----
def test_go_alias_propagation():
    fn = _go_fn(
        'func(c *gin.Context) { id := c.Param("id");'
        ' db.QueryRow("SELECT name FROM t_order WHERE id = ?", id).Scan(&name) }')
    assert GoFlow(fn, "id").analyze().calls, "id := c.Param(\"id\") 后 db.QueryRow 应被追踪"


def test_go_kill_no_report():
    fn = _go_fn(
        'func(c *gin.Context) { id := c.Param("id"); id = "0";'
        ' db.QueryRow("SELECT name FROM t_order WHERE id = ?", id).Scan(&name) }')
    assert not GoFlow(fn, "id").analyze().calls, "id 重定义为干净值后不应再 taint"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()
