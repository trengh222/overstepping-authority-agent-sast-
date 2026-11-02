"""TypeScript 前端 + 跨文件工厂函数解析验证。"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.extractor.node import TypeScriptExtractor
from access_scan.dataflow.defuse import JsFlow


def _mk(tmp_path: Path, server_src: str, factory_src: str) -> Path:
    (tmp_path / "server.ts").write_text(server_src, encoding="utf-8")
    (tmp_path / "routes").mkdir(exist_ok=True)
    (tmp_path / "routes" / "thing.ts").write_text(factory_src, encoding="utf-8")
    return tmp_path / "server.ts"


def test_ts_factory_namespace_import(tmp_path):
    server = (
        "import * as thing from './routes/thing'\n"
        "app.get('/api/things/:id', thing.getThing())\n"
    )
    factory = (
        "export const getThing = () => (req: Request, res: Response) => {\n"
        "  ThingModel.findAll({ where: { id: req.params.id } })\n"
        "}\n"
    )
    f = _mk(tmp_path, server, factory)
    ext = TypeScriptExtractor()
    src = f.read_bytes()
    ast = ext.parse(src)
    eps = ext.extract_endpoints(ast, str(f))
    assert eps and eps[0].handler == "thing.getThing", "namespace 导入的工厂函数应识别"
    ctxs = ext.endpoint_contexts(ast, str(f), src)
    ctx = ctxs.get("thing.getThing")
    assert ctx is not None and ctx.node.type != "call_expression", "应解析到内层 handler"


def test_ts_factory_named_import(tmp_path):
    server = (
        "import { getThing } from './routes/thing'\n"
        "app.get('/api/things/:id', getThing())\n"
    )
    factory = (
        "export function getThing() {\n"
        "  return (req: Request, res: Response) => {\n"
        "    return ThingModel.findByPk(req.params.id)\n"
        "  }\n"
        "}\n"
    )
    f = _mk(tmp_path, server, factory)
    ext = TypeScriptExtractor()
    src = f.read_bytes()
    ast = ext.parse(src)
    eps = ext.extract_endpoints(ast, str(f))
    assert eps and eps[0].handler == "getThing", "命名导入的工厂函数应识别"
    ctxs = ext.endpoint_contexts(ast, str(f), src)
    ctx = ctxs.get("getThing")
    assert ctx is not None and ctx.node.type != "call_expression"
    flow = JsFlow(ctx.node, "id").analyze()
    assert flow.calls, "findByPk(req.params.id) 直接嵌套 source 应被追踪到 sink"


_ts_ext = TypeScriptExtractor()


def _walk_js(node):
    yield node
    for ch in node.named_children:
        yield from _walk_js(ch)


def _find_handler(src: str):
    a = _ts_ext.parse(src.encode())
    for node in _walk_js(a.root_node):
        if node.type == "arrow_function":
            p = node.child_by_field_name("parameters")
            if p is not None and b"req" in (p.text or b""):
                return node
    return None


def test_js_shorthand_try_catch_sink():
    src = (
        "const h = async (req, res) => {\n"
        "  try {\n"
        "    const id = req.params.id\n"
        "    return await BasketModel.findOne({ where: { id } })\n"
        "  } catch (e) { next(e) }\n"
        "}\n"
    )
    fn = _find_handler(src)
    assert fn is not None, "应找到含 req 参数的 handler"
    flow = JsFlow(fn, "id").analyze()
    assert flow.calls, "try-catch + shorthand {id} 里的 findOne 应被追踪到 sink"


def test_owner_col_in_args():
    from access_scan.dataflow.taint import _ownership_in_text
    # 只有「当前用户来源」才算归属约束
    assert _ownership_in_text("{ where: { id: req.params.id, userId: req.user.id } }")
    assert not _ownership_in_text("{ where: { id: req.params.id } }")
    # D2：客户端可控 userId 不构成归属约束（否则会漏报）
    assert not _ownership_in_text("{ where: { id: req.params.id, UserId: req.body.UserId } }")


def test_privileged_write_only_delete():
    from access_scan.rules.vertical import _has_privileged_write
    from access_scan.extractor.base import EndpointCtx

    def _ctx(src):
        return EndpointCtx(file="x.ts", lines=[], language="javascript",
                           node=_find_handler(src))

    # update/save 是普通写（操作自己资源），不算高权限
    assert not _has_privileged_write(_ctx(
        "const h = (req, res) => { review.update({ likedBy: req.body.x }) }"))
    # delete/destroy 是高权限写
    assert _has_privileged_write(_ctx(
        "const h = (req, res) => { UserModel.destroy({ where: { id: req.params.id } }) }"))
