"""M3.3 多语言符号执行反例/PoC 验证（JavaScript / Go）。运行：python tests/test_m3_symexec_lang.py"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.dataflow.symexec import symbolic_counterexample
from access_scan.extractor.node import NodeExtractor
from access_scan.extractor.go import GoExtractor
from access_scan.ir import AuthInfo, AuthMechanism, Endpoint

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
    return _first(_js.parse(src.encode()).root_node, ("arrow_function",))


def _go_fn(src):
    return _first(_go.parse(src.encode()).root_node, ("func_literal",))


def _ep(path):
    return Endpoint(id="x", file="x", method="GET", path=path, handler="f",
                    params=[], auth=AuthInfo(False, AuthMechanism.NONE, None, "NONE"),
                    privilege_op=False, line_start=1, line_end=10)


# ---- JavaScript：别名 + 无条件反例 ----
def test_js_counterexample_alias():
    fn = _js_fn(
        "(req, res) => {\n    const uid = req.params.id;\n"
        "    return prisma.order.findUnique({ where: { id: uid } });\n}")
    ce = symbolic_counterexample(fn, "id", 3, _ep("/api/order/{id}"), "javascript")
    assert ce is not None, "JS 别名应产出反例"
    assert 1 <= ce["counterexample"] <= 2 ** 31 - 1
    assert "curl" in ce["poc"]


# ---- Go：短变量声明 + 条件约束 ----
def test_go_counterexample_with_constraint():
    fn = _go_fn(
        'func(c *gin.Context) {\n    id := c.Param("id")\n'
        '    if id > 1000 {\n        db.QueryRow("SELECT 1", id)\n    }\n}')
    ce = symbolic_counterexample(fn, "id", 4, _ep("/api/order/{id}"), "go")
    assert ce is not None, "Go 带约束 sink 应产出反例"
    assert ce["counterexample"] > 1000
    assert "curl" in ce["poc"]


# ---- JS 表达式体箭头函数（body 是 call_expression 而非 block）----
def test_js_expression_body_arrow():
    fn = _js_fn("(req, res) => orderService.findById(req.params.id)")
    ce = symbolic_counterexample(fn, "id", 1, _ep("/api/order/{id}"), "javascript")
    assert ce is not None, "表达式体箭头函数的 body 是表达式，应能产出反例"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()
