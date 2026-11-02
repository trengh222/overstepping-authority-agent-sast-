"""Node 前端：Express（M4，方案 §6.1）。

识别：app/router 的 get/post/put/delete/patch 路由、`:id` 路径参数、
req.params/req.query/req.body 读取、鉴权中间件参数、
app.use 鉴权中间件守卫（规则 B）。
"""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

from ..ir import AuthInfo, AuthMechanism, Endpoint, Param, ParamSource, Resource
from .base import EndpointCtx, Extractor, Guard, has_write_op, register
from .base import _text as text_of

_JS_LANGUAGE = Language(tree_sitter_javascript.language())
_TS_LANGUAGE = Language(tree_sitter_typescript.language_typescript())

_VERBS = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH"}
_AUTH_MW_RE = re.compile(r"(auth|login|verify|jwt|token|session|requireUser|ensure)", re.I)
# 鉴权/角色中间件方法名（security.isAuthorized()/isAccounting()/denyAll() 等 call 形式）
_AUTH_MW_METHOD_RE = re.compile(
    r"(isAuthorized|isAuthenticated|isAccounting|isAdmin|isAdministrator|denyAll|"
    r"appendUserId|requireAdmin|requireRole|hasRole|authenticate|authorize|"
    r"checkPermission|hasPermission)", re.I)
_CLIENT_INPUT_RE = re.compile(r"req\.(query|body|headers|cookies|params)")


@register("javascript")
class NodeExtractor(Extractor):
    language = "javascript"
    _LANG = _JS_LANGUAGE

    def __init__(self):
        self._imports: Dict[str, str] = {}                  # 模块名 → 相对路径（当前文件）
        self._factory_cache: Dict[Tuple[str, str, str], Any] = {}  # (file, obj, prop) → handler 节点

    def parse(self, src: bytes):
        if isinstance(src, str):
            src = src.encode("utf-8")
        return Parser(self._LANG).parse(src)

    # ---- 跨文件工厂函数解析（Express/TS：handler 常为 factory() 调用）----
    def _collect_imports(self, ast, file: str) -> Dict[str, str]:
        """import 映射：模块名 → 相对路径（namespace/命名/默认导入）。"""
        imports: Dict[str, str] = {}
        for node in _walk_all(ast.root_node):
            if node.type != "import_statement":
                continue
            source = node.child_by_field_name("source")
            mod = _string_of(source) if source is not None else None
            if not mod:
                continue
            txt = text_of(node)
            m = re.search(r"import\s+\*\s*as\s+(\w+)\s+from", txt)
            if m:
                imports[m.group(1)] = mod
                continue
            m = re.search(r"import\s*\{([^}]*)\}\s*from", txt)
            if m:
                for name in re.findall(r"\b(\w+)\b", m.group(1)):
                    imports[name] = mod
                continue
            m = re.search(r"import\s+(\w+)\s+from", txt)
            if m:
                imports[m.group(1)] = mod
        return imports

    def _factory_name(self, handler) -> Optional[str]:
        """工厂函数调用的函数名（unwrap asyncHandler 包装）。"""
        if handler.type != "call_expression":
            return None
        fn = handler.child_by_field_name("function")
        args = handler.child_by_field_name("arguments")
        if fn is not None and "asyncHandler" in text_of(fn):
            if args is not None and args.named_children:
                return self._factory_name(args.named_children[0])
        return text_of(fn).strip() if fn is not None else None

    def _unwrap_factory(self, handler, file: str):
        """跨文件解析工厂函数 handler → (内层 handler 节点, 其所在文件)。"""
        if handler.type != "call_expression":
            return handler, file
        fn = handler.child_by_field_name("function")
        args = handler.child_by_field_name("arguments")
        # utils.asyncHandler(X) 包装：递归到第一个参数
        if fn is not None and "asyncHandler" in text_of(fn):
            if args is not None and args.named_children:
                return self._unwrap_factory(args.named_children[0], file)
            return handler, file
        # obj.prop() 工厂函数（namespace 导入）
        if fn is not None and fn.type == "member_expression":
            obj = text_of(fn.child_by_field_name("object") or "").strip()
            prop = text_of(fn.child_by_field_name("property") or "").strip()
            if obj and prop:
                inner, hfile = self._resolve_factory(obj, prop, file)
                if inner is not None:
                    return inner, hfile
        # prop() 工厂函数（命名/默认导入）
        elif fn is not None and fn.type == "identifier":
            name = text_of(fn).strip()
            if name:
                inner, hfile = self._resolve_factory("", name, file)
                if inner is not None:
                    return inner, hfile
        return handler, file

    def _resolve_factory(self, obj: str, prop: str, file: str):
        key = (file, obj, prop)
        if key in self._factory_cache:
            return self._factory_cache[key]
        if obj:
            mod = self._imports.get(obj) or f"./routes/{obj}"
        else:
            mod = self._imports.get(prop)  # 命名导入：直接按函数名查 import
            if mod is None:
                self._factory_cache[key] = (None, file)
                return None, file
        resolved = self._load_factory(mod, prop, file)
        self._factory_cache[key] = resolved
        return resolved

    def _load_factory(self, mod: str, prop: str, file: str):
        base = Path(file).parent
        p = base / mod
        if not p.suffix:
            for ext in (".ts", ".js"):
                cand = p.with_suffix(ext)
                if cand.exists():
                    p = cand
                    break
        if not p.exists():
            return None, file
        try:
            src = p.read_bytes()
        except OSError:
            return None, file
        ast = self.parse(src)
        inner = self._find_factory_handler(ast.root_node, prop)
        return (inner, str(p)) if inner is not None else (None, file)

    def _find_factory_handler(self, root, prop: str):
        """找 export 工厂函数 prop，返回其内层 handler 节点。"""
        for node in _walk_all(root):
            if node.type == "function_declaration":
                if text_of(node.child_by_field_name("name") or "") == prop:
                    return self._handler_from_factory(node)
            if node.type == "lexical_declaration":
                for vd in node.named_children:
                    if vd.type == "variable_declarator" and \
                            text_of(vd.child_by_field_name("name") or "") == prop:
                        return self._handler_from_factory(vd.child_by_field_name("value"))
        return None

    @staticmethod
    def _handler_from_factory(node) -> Optional[Any]:
        """从工厂函数节点提取内层 handler（参数含 req/res 的箭头/函数优先）。"""
        if node is None:
            return None
        fns = [c for c in _walk_all(node)
               if c.type in ("arrow_function", "function_expression")]
        if not fns:
            return None
        for fn in fns:
            params = fn.child_by_field_name("parameters")
            ptxt = text_of(params) if params is not None else ""
            if "req" in ptxt or "request" in ptxt.lower():
                return fn
        return fns[-1]


    # ---- 端点 ----
    def extract_endpoints(self, ast, file: str) -> List[Endpoint]:
        self._imports = self._collect_imports(ast, file)
        out: List[Endpoint] = []
        for verb, path, handler, route_call in self._routes(ast.root_node):
            if path is None or handler is None:
                continue
            inner, hfile = self._unwrap_factory(handler, file)
            target = inner if inner is not None else handler
            params = self._params(target, path)
            handler_name = self._factory_name(handler) or self._handler_name(handler, path)
            fn_node = route_call.child_by_field_name("function")
            obj_node = fn_node.child_by_field_name("object") if fn_node is not None else None
            container = text_of(obj_node).strip() if obj_node is not None else None
            out.append(Endpoint(
                id=f"{file}:{handler_name}:{verb}:{path}", file=file, method=verb, path=path,
                handler=handler_name, params=params,
                auth=self._middleware_auth(route_call),
                privilege_op=has_write_op(target, "javascript"),
                line_start=route_call.start_point[0] + 1,
                line_end=route_call.end_point[0] + 1,
                container=container,  # 路由容器名（app/router），注册可达判定用
            ))
        return out

    def extract_resources(self, ast, file: str) -> List[Resource]:
        return []

    def endpoint_contexts(self, ast, file: str, src: bytes) -> Dict[str, EndpointCtx]:
        self._imports = self._collect_imports(ast, file)
        lines = src.decode("utf-8", errors="replace").splitlines()
        out: Dict[str, EndpointCtx] = {}
        # 全函数/方法索引（跨过程切片用）：命名函数/方法 + 箭头函数赋值
        for node in _walk_all(ast.root_node):
            if node.type in ("function_declaration", "method_definition"):
                n = node.child_by_field_name("name")
                if n is not None:
                    out[text_of(n)] = EndpointCtx(
                        file=file, lines=lines, language="javascript", node=node)
            elif node.type == "variable_declarator":
                n = node.child_by_field_name("name")
                v = node.child_by_field_name("value")
                if n is not None and v is not None and \
                        v.type in ("arrow_function", "function_expression"):
                    out[text_of(n)] = EndpointCtx(
                        file=file, lines=lines, language="javascript", node=v)
        # handler 上下文（ep.handler 用，后写入覆盖同名，保证 handler 本体优先）
        for verb, path, handler, _call in self._routes(ast.root_node):
            if path is None or handler is None:
                continue
            inner, hfile = self._unwrap_factory(handler, file)
            handler_name = self._factory_name(handler) or self._handler_name(handler, path)
            if inner is not None and hfile != file:
                try:
                    hlines = Path(hfile).read_bytes().decode("utf-8", errors="replace").splitlines()
                except OSError:
                    hlines = lines
                out[handler_name] = EndpointCtx(
                    file=hfile, lines=hlines, language="javascript", node=inner)
            else:
                out[handler_name] = EndpointCtx(
                    file=file, lines=lines, language="javascript", node=handler)
        return out

    # ---- 守卫：app.use 中间件 ----
    def extract_guards(self, ast, file: str) -> Tuple[List[Guard], list]:
        guards: List[Guard] = []
        for call in self._use_calls(ast.root_node):
            args = call.child_by_field_name("arguments").named_children
            if not args:
                continue
            target = self._resolve_fn(ast.root_node, args[0])
            logic = text_of(target)
            if not logic or not _AUTH_MW_RE.search(logic):
                continue
            name = text_of(args[0]).strip()
            guards.append(Guard(
                kind="MIDDLEWARE", name=name, patterns=[],
                has_auth_check=bool(_AUTH_MW_RE.search(logic)),
                depends_on_client_input=bool(_CLIENT_INPUT_RE.search(logic)),
                line=call.start_point[0] + 1, file=file,
            ))
        return guards, []

    # ---- 内部工具 ----
    @staticmethod
    def _routes(root):
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    verb = text_of(prop) if prop is not None else ""
                    if verb in _VERBS:
                        args = node.child_by_field_name("arguments").named_children
                        path = _string_of(args[0]) if args else None
                        # handler 是最后一个参数；中间件（security.isAccounting() 等）在前
                        handler = args[-1] if len(args) > 1 else None
                        if handler is not None and handler.type in ("arrow_function",
                                                                    "function_expression",
                                                                    "identifier",
                                                                    "call_expression"):
                            yield verb, path, handler, node
            stack.extend(node.named_children)

    def _use_calls(self, root):
        for node in _walk_all(root):
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    if prop is not None and text_of(prop) == "use":
                        yield node

    def _resolve_fn(self, root, arg):
        """标识符形式的中间件 → 解析文件内同名函数/变量；否则直接用参数节点。"""
        if arg.type != "identifier":
            return arg
        name = text_of(arg)
        for node in _walk_all(root):
            if node.type in ("function_declaration", "method_definition"):
                n = node.child_by_field_name("name")
                if n is not None and text_of(n) == name:
                    return node
            if node.type in ("variable_declarator", "lexical_declaration"):
                n = node.child_by_field_name("name")
                if n is not None and text_of(n) == name and node.child_by_field_name("value") is not None:
                    return node.child_by_field_name("value")
        return arg

    @staticmethod
    def _params(handler, path: str) -> List[Param]:
        params: List[Param] = []
        seen = set()
        for name in re.findall(r":(\w+)", path):
            seen.add(name)
            params.append(Param(name=name, source=ParamSource.PATH, type="string"))
        text = text_of(handler)
        for m in re.finditer(r"req\.params\.(\w+)", text):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                params.append(Param(name=m.group(1), source=ParamSource.PATH, type="string"))
        for m in re.finditer(r"req\.query\.(\w+)", text):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                params.append(Param(name=m.group(1), source=ParamSource.QUERY, type="string"))
        for m in re.finditer(r"req\.body\.(\w+)", text):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                params.append(Param(name=m.group(1), source=ParamSource.BODY, type="string"))
        return params

    @staticmethod
    def _middleware_auth(route_call) -> AuthInfo:
        args = route_call.child_by_field_name("arguments").named_children
        for a in args[1:-1]:
            name = text_of(a).strip()
            # identifier 形式：authenticate / authorize 等
            if a.type == "identifier" and _AUTH_MW_RE.search(name):
                return AuthInfo(present=True, mechanism=AuthMechanism.MIDDLEWARE,
                                role_or_perm=name, scope="METHOD",
                                line=route_call.start_point[0] + 1)
            # call_expression 形式：security.isAuthorized()/isAccounting()/denyAll() 等
            if a.type == "call_expression":
                fn = a.child_by_field_name("function")
                if fn is not None:
                    fname = text_of(fn).strip()
                    method = fname.split(".")[-1]
                    if _AUTH_MW_METHOD_RE.search(method):
                        return AuthInfo(present=True, mechanism=AuthMechanism.MIDDLEWARE,
                                        role_or_perm=fname, scope="METHOD",
                                        line=route_call.start_point[0] + 1)
        return AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                        role_or_perm=None, scope="NONE", line=-1)

    @staticmethod
    def _handler_name(handler, path: str) -> str:
        n = handler.child_by_field_name("name")
        if n is not None:
            return text_of(n)
        return f"handler:{path}"


@register("typescript")
class TypeScriptExtractor(NodeExtractor):
    """TypeScript 前端：AST 节点类型与 JS 一致，仅 grammar 不同（支持类型注解/泛型）。"""
    _LANG = _TS_LANGUAGE


def _string_of(node) -> Optional[str]:
    if node is None:
        return None
    vals = re.findall(r"['\"`]([^'\"`]*)['\"`]", text_of(node))
    return vals[0] if vals else None


def _walk_all(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.named_children)