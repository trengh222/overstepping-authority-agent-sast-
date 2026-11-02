"""规则 C（Mass Assignment / admin 提权）验证。运行：python tests/test_massign.py"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.extractor.base import EndpointCtx
from access_scan.rules.massign import recall_massign
from access_scan.ir import AuthInfo, AuthMechanism, Endpoint


def _ep(method="POST", path="/api/register"):
    return Endpoint(id="x", file="x.ts", method=method, path=path, handler="f",
                    params=[], auth=AuthInfo(False, AuthMechanism.NONE, None, "NONE"),
                    privilege_op=False, line_start=1, line_end=20)


def _a4_fields(cands):
    return {(c.subtype, c.access.identifier_param) for c in cands}


def test_java_setter_privesc():
    from access_scan import cli
    kept, _ = cli.scan(_REPO / "tests" / "fixtures" / "java_mass")
    a4_paths = {c.endpoint.path for c in kept if c.subtype == "A4"}
    assert "/api/register" in a4_paths, f"Java setter 提权应检出: {a4_paths}"
    assert "/api/register_safe" not in a4_paths, "硬编码 setAdmin(false) 不应检出"


# ---------- JavaScript/TypeScript ----------
from access_scan.extractor.node import TypeScriptExtractor

_ts_ext = TypeScriptExtractor()


def _walk_js(node):
    yield node
    for ch in node.named_children:
        yield from _walk_js(ch)


def _js_ctx(src: str) -> EndpointCtx:
    a = _ts_ext.parse(src.encode())
    for node in _walk_js(a.root_node):
        if node.type == "arrow_function":
            return EndpointCtx(file="x.ts", lines=src.splitlines(),
                               language="javascript", node=node)
    raise AssertionError("未找到 arrow_function")


_JS_CREATE = (
    "const h = (req, res) => {\n"
    "  UserModel.create({ username: req.body.username, role: req.body.role })\n"
    "}\n"
)

_JS_ASSIGN = (
    "const h = (req, res) => {\n"
    "  const u = await UserModel.findByPk(req.params.id)\n"
    "  u.role = req.body.role\n"
    "  u.save()\n"
    "}\n"
)

_JS_CHECK_ONLY = (
    "const h = (req, res) => {\n"
    "  if (req.body.role === 'admin') { next() }\n"
    "}\n"
)

_JS_NON_PRIV = (
    "const h = (req, res) => {\n"
    "  UserModel.create({ username: req.body.username })\n"
    "}\n"
)


def test_js_create_role_privesc():
    cands = recall_massign(_ep(), _js_ctx(_JS_CREATE))
    assert ("A4", "role") in _a4_fields(cands), f"JS create({role:req.body.role}) 应检出: {cands}"


def test_js_assign_role_privesc():
    cands = recall_massign(_ep(), _js_ctx(_JS_ASSIGN))
    assert ("A4", "role") in _a4_fields(cands), f"JS u.role=req.body.role+save 应检出: {cands}"


def test_js_check_only_not_reported():
    assert not recall_massign(_ep(), _js_ctx(_JS_CHECK_ONLY)), "仅检查 req.body.role 不应检出"


def test_js_non_priv_not_reported():
    assert not recall_massign(_ep(), _js_ctx(_JS_NON_PRIV)), "非权限字段不应检出"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()
