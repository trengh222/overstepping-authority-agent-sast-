"""Go 前端：Gin / Echo（方案 §6.1）。

识别：
- 路由注册 `r.GET/POST/...`（selector_expression），支持
  `admin := r.Group("/admin")` 前缀合成、`e.Group("/admin", mw...)` 组级中间件、
  `admin.GET("/x", RequireRole("admin"), h)` 路由级中间件、命名 handler（`h.List`）；
- 参数：路径 `:id` / `*path`、handler 内
  `c.Param/Query/QueryParam/DefaultQuery/PostForm/FormValue/DefaultPostForm("x")` 读取；
- 鉴权事实：`.Use(...)` / `Group(prefix, mw...)` / 路由级中间件 → Guard（带路径前缀作用域，
  module 取文件所在目录，避免跨包/跨服务泄漏）；端点 `auth` 由覆盖它的中间件推出；
- 特权操作：方法名前缀 + 原生 SQL 写语句（DELETE FROM / UPDATE..SET / INSERT INTO…）
  + 路由写动词（DELETE/PUT/PATCH）。

G1/G2/G3/G5/G6/G9/G10：此前的实现只认 `func_literal` handler、丢 Group 前缀、
只采集 `.Use()`、auth 写死 present=False、特权操作只看方法名、Guard 无作用域。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

import tree_sitter_go
from tree_sitter import Language, Parser

from ..ir import AuthInfo, AuthMechanism, Endpoint, Param, ParamSource, Resource
from .base import EndpointCtx, Extractor, Guard, has_write_op, register
from .base import _text as text_of

_GO_LANGUAGE = Language(tree_sitter_go.language())

_VERBS = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH"}
_WRITE_VERBS = {"delete", "put", "patch"}
# 路由器构造：gin.Default()/gin.New()/echo.New()/mux.NewRouter()
_ROUTER_CTORS = {"Default", "New", "NewRouter"}
# 鉴权中间件：名字特征（G7：RequireAdmin/IsStaff 这类授权中间件也要命中）
_AUTH_MW_RE = re.compile(
    r"(auth|login|token|session|jwt|bearer|permit|authoriz|authentic|require|verify|"
    r"guard|acl|rbac|permission|scope|role|admin|staff|manager)", re.I)
# 角色/权限级中间件（授权而不只是认证）→ 供 A2 判定「授权是否足够」
_ROLE_MW_RE = re.compile(
    r"(admin|role|permission|perm|scope|rbac|claim|policy|grant|staff|manager|superuser|"
    r"tenant|acl|can[A-Z]\w*)", re.I)
# 中间件函数体内可证明「做了鉴权」的写法（注入身份 / 401/403 拒绝 / 解析 token）
_MW_BODY_AUTH_RE = re.compile(
    r"(AbortWithStatus|Abort\b|StatusUnauthorized|StatusForbidden|ErrUnauthorized|ErrForbidden"
    r"|jwt\.Parse|ParseWithClaims|MustGet|Set\(\s*[\"`](?:uid|user|userID|role|claims)"
    r"|GetHeader\(\s*[\"`](?:Authorization|X-Token|token))", re.I)
_CLIENT_INPUT_RE = re.compile(r"c\.(Query|PostForm|FormValue|GetHeader|Cookie)\b")
# 参数读取表达式 → 参数来源
_PARAM_READS = {
    "Param": ParamSource.PATH,
    "Query": ParamSource.QUERY,
    "QueryParam": ParamSource.QUERY,
    "DefaultQuery": ParamSource.QUERY,
    "PostForm": ParamSource.BODY,
    "FormValue": ParamSource.BODY,
    "DefaultPostForm": ParamSource.BODY,
}
# 原生 SQL 写语句（G6：Go 的写操作在字符串里，方法名是 Exec/QueryRow）
_SQL_WRITE_RE = re.compile(
    r"\b(?:DELETE\s+FROM|INSERT\s+INTO|REPLACE\s+INTO|UPDATE\s+[\w.`\"\[\]]+\s+SET|"
    r"DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE)\b", re.I)


@register("go")
class GoExtractor(Extractor):
    language = "go"

    def parse(self, src: bytes):
        if isinstance(src, str):
            src = src.encode("utf-8")
        return Parser(_GO_LANGUAGE).parse(src)

    # ---- 端点 ----
    def extract_endpoints(self, ast, file: str) -> List[Endpoint]:
        proj = _PROJECT
        if proj is not None and _norm_path(file) in proj.sources:
            return list(proj.endpoints.get(_norm_path(file), []))
        root = ast.root_node
        index = _func_index(root)
        model = _build_model(root)
        module = _dir_module(file)
        out: List[Endpoint] = []
        for verb, path, handler, call, recv, route_mw in _routes(model, root):
            node = _resolve_handler(handler, index)
            mw = (list(model.root_mw.get(recv, [])) + list(model.chain.get(recv, []))
                  + list(route_mw))
            out.append(Endpoint(
                id=f"{file}:handler:{_VERBS[verb]}:{path}", file=file, method=_VERBS[verb],
                path=path, handler=f"handler:{path}",
                params=self._params(node, path),
                auth=_auth_info(mw, index, call),
                privilege_op=_is_privileged(verb, node),
                line_start=call.start_point[0] + 1,
                line_end=call.end_point[0] + 1,
                module=module,
            ))
        return out

    def extract_resources(self, ast, file: str) -> List[Resource]:
        return []

    def endpoint_contexts(self, ast, file: str, src: bytes) -> Dict[str, EndpointCtx]:
        lines = src.decode("utf-8", errors="replace").splitlines()
        root = ast.root_node
        index = _func_index(root)
        out: Dict[str, EndpointCtx] = {}
        for name, node in index.items():
            out[name] = EndpointCtx(file=file, lines=lines, language="go", node=node)
        proj = _PROJECT
        if proj is not None and _norm_path(file) in proj.sources:
            for key, (hfile, hnode) in proj.handlers.get(_norm_path(file), {}).items():
                out[key] = EndpointCtx(
                    file=hfile, lines=proj.lines.get(hfile, lines), language="go",
                    node=hnode)
            return out
        model = _build_model(root)
        for _v, path, handler, _c, _r, _m in _routes(model, root):
            node = _resolve_handler(handler, index)
            out[f"handler:{path}"] = EndpointCtx(file=file, lines=lines, language="go", node=node)
        return out

    # ---- 守卫：.Use(...) / Group(prefix, mw...) / 路由级中间件 ----
    def extract_guards(self, ast, file: str) -> Tuple[List[Guard], list]:
        proj = _PROJECT
        if proj is not None and _norm_path(file) in proj.sources:
            return list(proj.guards.get(_norm_path(file), [])), []
        root = ast.root_node
        index = _func_index(root)
        model = _build_model(root)
        module = _dir_module(file)
        guards: List[Guard] = []
        for recv, chain in model.chain.items():
            if not chain:
                continue
            for text in chain:
                guards.append(_mk_guard(text, index, _scope_patterns(model.prefix.get(recv, "")),
                                        file, module))
        for recv, mws in model.root_mw.items():
            if not mws:
                continue
            for text in mws:
                guards.append(_mk_guard(text, index, _scope_patterns(model.prefix.get(recv, "")),
                                        file, module))
        seen = set()
        for _verb, path, _h, _c, _r, route_mw in _routes(model, root):
            for text in route_mw:
                if (text, path) in seen:
                    continue
                seen.add((text, path))
                guards.append(_mk_guard(text, index, [path], file, module))
        return guards, []

    # ---- 内部工具 ----
    @staticmethod
    def _params(handler, path: str, structs=None) -> List[Param]:
        out: List[Param] = []
        seen = set()
        for m in re.finditer(r"[:*](\w+)", path or ""):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            out.append(Param(name=name, source=ParamSource.PATH, type="string"))
        text = text_of(handler)
        for m in re.finditer(
                r"c\.(Param|Query|QueryParam|DefaultQuery|PostForm|FormValue|DefaultPostForm)"
                r"\(\s*[\"`](\w+)[\"`]", text):
            kind, name = m.group(1), m.group(2)
            if name in seen:
                continue
            seen.add(name)
            out.append(Param(name=name, source=_PARAM_READS[kind], type="string"))
        if structs:
            out.extend(_dto_params(text, structs, seen))
        return out


# ---------- 项目级索引（跨文件 registrar / 中间件继承 / handler 定位） ----------

# 策略引擎中间件（Casbin/OPA 等）：鉴权规则在数据里，静态不可判定 → 视为「授权决策点」
_POLICY_MW_RE = re.compile(r"(casbin|enforcer|opa|abac|cedar|authz|permission[_\s]?check)",
                           re.I)
# registrar 形参类型：`Router *gin.RouterGroup` / `e *echo.Group` / `r *gin.Engine`
_ENGINE_PARAM_RE = re.compile(r"\b(?:RouterGroup|Engine|Group)\b")
_BIND_RE = re.compile(r"(ShouldBind\w*|Bind\w*)\s*\(\s*&\s*(\w+)")
_VAR_DECL_RE = re.compile(r"\bvar\s+(\w+)\s+([\w.]+)")
_SHORT_DECL_RE = re.compile(r"\b(\w+)\s*:=\s*([\w.]+)\s*\{\s*\}")
# DTO 里只把「像资源标识的字段」当参数展开：结构体的 CreatedAt/PageSize 等字段
# 展开只会把整库 CRUD 变成噪声候选。
_ID_FIELD_RE = re.compile(
    r"(?:^|[a-z_])(?:id|ids|uid|uuid|code|key|no|num|name|title|username|email)$", re.I)
# 归一名落在这些集合里的字段不是「对象引用」（命名空间/检索/分页/代码生成输入），
# 与 rules/idor.py 的 _NON_RESOURCE_NAMES 保持同一口径。
_NON_RESOURCE_FIELDS = frozenset({
    "db", "dbname", "database", "databasename", "tablename", "table",
    "schema", "schemaname", "collection", "collectionname",
    "keyword", "keywords", "query", "search", "filter",
    "sort", "sortby", "order", "orderby", "page", "pageindex", "pageno",
    "pagenum", "pagesize", "limit", "offset", "cursor",
    "filename", "filepath", "structname", "templatename", "modelname",
    "packagename", "modulename",
})
_NON_RESOURCE_FIELD_SUFFIXES = (
    "dbname", "tablename", "schemaname", "databasename", "collectionname",
    "packagename", "structname", "templatename", "modelname", "modulename",
    "filename", "filepath",
)


def _is_non_resource_field(name: str) -> bool:
    n = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    return bool(n) and (n in _NON_RESOURCE_FIELDS
                        or any(n.endswith(s) for s in _NON_RESOURCE_FIELD_SUFFIXES))

_PROJECT: Optional["_ProjectIndex"] = None


def build_project(sources: Dict[str, bytes]) -> None:
    """为整个 Go 包建路由索引（cli.scan 在逐文件抽取前调用）。"""
    global _PROJECT
    _PROJECT = _ProjectIndex(sources)


def reset_project() -> None:
    global _PROJECT
    _PROJECT = None


def _norm_path(p: str) -> str:
    return os.path.normpath(str(p))


def _assigned_name(call) -> Optional[str]:
    """`x := recv.Group(...)` 里的左侧变量名。"""
    parent = getattr(call, "parent", None)
    if parent is not None and parent.type == "expression_list":
        parent = parent.parent
    if parent is not None and parent.type in ("short_var_declaration", "assignment_statement"):
        left = _one(parent.child_by_field_name("left"))
        if left is not None and left.type == "identifier":
            return text_of(left).strip()
    return None


class _Registrar:
    __slots__ = ("name", "file", "param", "body_calls")

    def __init__(self, name: str, file: str, param: str):
        self.name = name
        self.file = file
        self.param = param
        self.body_calls: List[Any] = []   # registrar 函数体内的 call_expression


class _ProjectIndex:
    """全局函数/结构体表 + 每文件路由模型 + registrar 展开。

    registrar = 形参含 `*gin.RouterGroup` / `*echo.Group` / `*gin.Engine` 的函数，
    大型 Gin 工程常把路由注册抽到 `InitXxxRouter(Router *gin.RouterGroup)` 这类辅助函数里，
    由 `initialize/router.go` 传入带中间件的组 → 只有跨文件展开才能拿到路径前缀与鉴权链。
    """

    def __init__(self, sources: Dict[str, bytes]):
        self.sources: Dict[str, bytes] = {_norm_path(k): v for k, v in sources.items()}
        self.lines: Dict[str, List[str]] = {}
        self.roots: Dict[str, Any] = {}
        self.funcs: Dict[str, Tuple[str, Any]] = {}     # name -> (file, node)（首个定义）
        self.structs: Dict[str, List[Tuple[str, str]]] = {}
        self.registrars: Dict[str, _Registrar] = {}
        self.models: Dict[str, _RouterModel] = {}
        self.func_nodes: Dict[str, Any] = {}
        self.routes: Dict[str, List[Dict[str, Any]]] = {}
        self.endpoints: Dict[str, List[Endpoint]] = {}
        self.handlers: Dict[str, Dict[str, Tuple[str, Any]]] = {}
        self.guards: Dict[str, List[Guard]] = {}
        self._build()

    # ---- 构建 ----
    def _build(self) -> None:
        files = sorted(self.sources)
        for file in files:
            src = self.sources[file]
            self.lines[file] = src.decode("utf-8", errors="replace").splitlines()
            self.roots[file] = Parser(_GO_LANGUAGE).parse(src).root_node
        for file in files:
            root = self.roots[file]
            for node in _walk_all(root):
                if node.type in ("function_declaration", "method_declaration"):
                    name = node.child_by_field_name("name")
                    if name is not None:
                        self.funcs.setdefault(text_of(name), (file, node))
                elif node.type == "type_declaration":
                    self._index_struct(node)
            self.models[file] = _build_model(root)
            for name, node in _func_index(root).items():
                param = _engine_param(node)
                if param and name not in self.registrars:
                    reg = _Registrar(name=name, file=file, param=param)
                    body = node.child_by_field_name("body")
                    if body is not None:
                        reg.body_calls = [c for c in _walk_all(body)
                                          if c.type == "call_expression"]
                    self.registrars[name] = reg
        self.func_nodes = {name: node for name, (_f, node) in self.funcs.items()}
        self._expand_embedded()
        self._resolve_all()

    def _index_struct(self, decl) -> None:
        for node in _walk_all(decl):
            if node.type != "type_spec":
                continue
            name = text_of(node.child_by_field_name("name") or "").strip()
            typ = node.child_by_field_name("type")
            if not name or typ is None or typ.type != "struct_type":
                continue
            fields: List[Tuple[str, str]] = []
            for body in typ.named_children:
                for field in body.named_children:
                    if field.type != "field_declaration":
                        continue
                    fname = field.child_by_field_name("name")
                    ftype = field.child_by_field_name("type")
                    if fname is not None:
                        fields.append((text_of(fname).strip(),
                                       text_of(ftype).strip() if ftype is not None else ""))
                    elif ftype is not None:
                        # 嵌入字段（`global.GVA_MODEL` 这类公共基类）：先记下来，_expand_embedded 里展开
                        fields.append(("", text_of(ftype).strip()))
            self.structs.setdefault(name, fields)

    def _expand_embedded(self, depth_max: int = 4) -> None:
        """把嵌入结构体（公共基类 / gorm.Model）的字段并入外层，供 DTO 参数展开。"""

        def expand(name: str, depth: int, seen: set) -> List[Tuple[str, str]]:
            if depth > depth_max or name in seen:
                return []
            seen = seen | {name}
            out: List[Tuple[str, str]] = []
            for fname, ftype in self.structs.get(name, []):
                if fname:
                    out.append((fname, ftype))
                    continue
                out.extend(expand((ftype or "").split(".")[-1], depth + 1, seen))
            return out

        for name in list(self.structs):
            self.structs[name] = expand(name, 0, set())

    def _collect_registrar_calls(self) -> None:
        names = set(self.registrars)
        for file in self.sources:
            root = self.roots[file]
            for node in _walk_all(root):
                if node.type != "call_expression":
                    continue
                fn = node.child_by_field_name("function")
                if fn is None or fn.type != "selector_expression":
                    continue
                field = text_of(fn.child_by_field_name("field") or "").strip()
                if field in names and field in self.registrars:
                    self.registrars[field].calls.append(node)

    def _group_args(self, call, model: _RouterModel) -> Optional[Tuple[str, List[str]]]:
        """解析 registrar 调用点传入的路由组（实参优先，其次接收者）。"""
        args = call.child_by_field_name("arguments")
        kids = [text_of(x).strip() for x in (args.named_children if args is not None else [])]
        for text in kids:
            if text in model.prefix:
                return model.prefix[text], list(model.root_mw.get(text, [])) + list(
                    model.chain.get(text, []))
        fn = call.child_by_field_name("function")
        recv = text_of(fn.child_by_field_name("operand") or "").strip()
        if recv in model.prefix:
            return model.prefix[recv], list(model.root_mw.get(recv, [])) + list(
                model.chain.get(recv, []))
        return None

    def _resolve_all(self) -> None:
        seen: Dict[str, set] = {}
        for file in self.sources:
            model = self.models[file]
            for node in _walk_all(self.roots[file]):
                if node.type != "call_expression":
                    continue
                fn = node.child_by_field_name("function")
                if fn is None or fn.type != "selector_expression":
                    continue
                name = text_of(fn.child_by_field_name("field") or "").strip()
                reg = self.registrars.get(name)
                if reg is None:
                    continue
                group = self._group_args(node, model)
                if group is None:
                    continue
                prefix, chain = group
                args = node.child_by_field_name("arguments")
                extra = [text_of(k) for k in
                         (args.named_children[1:] if args is not None else [])]
                for route in self._expand(reg.name, prefix, chain + extra, depth=0):
                    key = (route["verb"], route["path"], route["file"])
                    bucket = seen.setdefault(route["file"], set())
                    if key in bucket:
                        continue
                    bucket.add(key)
                    self.routes.setdefault(route["file"], []).append(route)
                    self.handlers.setdefault(route["file"], {})[
                        f"handler:{route['path']}"] = (route["handler_file"],
                                                       route["handler"])
        # 同一文件内直接注册的路由（fixture/小工程：`r := gin.Default(); r.GET(...)`）
        for file in self.sources:
            model = self.models[file]
            bucket = seen.setdefault(file, set())
            for verb, path, handler, call, recv, route_mw in _routes(model, self.roots[file]):
                # 只认本文件里真正由路由器变量注册的路由：registrar 形参（*gin.RouterGroup）
                # 注册的路由由 _expand 按调用方组展开，这里跳过，避免丢失路径前缀与中间件。
                if recv not in model.prefix:
                    continue
                key = (_VERBS[verb], path, file)
                if key in bucket:
                    continue
                bucket.add(key)
                mw = (list(model.root_mw.get(recv, [])) + list(model.chain.get(recv, []))
                      + list(route_mw))
                self.routes.setdefault(file, []).append({
                    "verb": _VERBS[verb], "path": path, "handler": handler,
                    "handler_file": file, "mw": mw, "call": call, "file": file,
                })
                self.handlers.setdefault(file, {})[f"handler:{path}"] = (file, handler)
        for file in self.sources:
            self.endpoints[file] = [self._endpoint(r) for r in self.routes.get(file, [])]
            self.guards[file] = self._guards_for(file)

    def _expand(self, name: str, prefix: str, mw: List[str], depth: int):
        reg = self.registrars.get(name)
        if reg is None or depth > 6:
            return []
        groups: Dict[str, Tuple[str, List[str]]] = {reg.param: (prefix, list(mw))}
        out: List[Dict[str, Any]] = []
        for call in sorted(reg.body_calls, key=lambda c: c.start_byte):
            layers = _call_layers(call)
            if not layers:
                continue
            cur = layers[0][1]
            for field, _recv, args in layers:
                kids = [text_of(k) for k in
                        (args.named_children if args is not None else [])]
                group = groups.get(cur)
                if field == "Group" and group is not None and kids:
                    var = _assigned_name(call)
                    if var:
                        rel = _first_string(kids[0]) or ""
                        groups[var] = (_join_path(group[0], rel), group[1] + kids[1:])
                        cur = var
                    continue
                if field.lower() == "use" and group is not None:
                    group[1].extend(kids)
                    continue
                if field.lower() in _VERBS and group is not None and len(kids) >= 2:
                    handler = args.named_children[-1]
                    handler_file, handler_node = self._resolve_global(handler, reg.file)
                    out.append({
                        "verb": _VERBS[field.lower()],
                        "path": _join_path(group[0], _first_string(kids[0]) or ""),
                        "handler": handler_node,
                        "handler_file": handler_file,
                        "mw": group[1] + kids[1:-1],
                        "call": call,
                        "file": reg.file,
                    })
                    continue
                sub = self.registrars.get(field)
                if sub is not None and group is not None:
                    out.extend(self._expand(field, group[0], group[1] + kids[1:], depth + 1))
        return out

    def _resolve_global(self, handler, default_file: str) -> Tuple[str, Any]:
        if handler is None:
            return default_file, handler
        if handler.type == "func_literal":
            return default_file, handler
        text = text_of(handler)
        name = text.split(".")[-1].strip()
        hit = self.funcs.get(name)
        if hit is None:
            return default_file, handler
        # `baseApi.Register` 这类接收者暗示 api 层：优先取 /api/ 目录下的同名函数
        if "api" in text.lower():
            for other_name, (file, node) in self.funcs.items():
                if other_name == name and "/api/" in file.replace("\\", "/"):
                    return file, node
        return hit

    def _endpoint(self, route: Dict[str, Any]) -> Endpoint:
        handler = route["handler"]
        file = route["file"]
        index = self.func_nodes
        path = route["path"]
        return Endpoint(
            id=f"{file}:handler:{route['verb']}:{path}",
            file=file, method=route["verb"], path=path,
            handler=f"handler:{path}",
            params=GoExtractor._params(handler, path, self.structs),
            auth=_auth_info(route["mw"], index, route["call"]),
            privilege_op=_is_privileged(route["verb"].lower(), handler),
            line_start=route["call"].start_point[0] + 1,
            line_end=route["call"].end_point[0] + 1,
            module=_dir_module(file),
        )

    def _guards_for(self, file: str) -> List[Guard]:
        model = self.models.get(file)
        index = self.func_nodes
        module = _dir_module(file)
        out: List[Guard] = []
        if model is not None:
            for recv, chain in model.chain.items():
                for text in chain:
                    out.append(_mk_guard(text, index, _scope_patterns(model.prefix.get(recv, "")),
                                         file, module))
            for recv, mws in model.root_mw.items():
                for text in mws:
                    out.append(_mk_guard(text, index, _scope_patterns(model.prefix.get(recv, "")),
                                         file, module))
        seen = set()
        for route in self.routes.get(file, []):
            for text in route["mw"]:
                if (text, route["path"]) in seen:
                    continue
                seen.add((text, route["path"]))
                out.append(_mk_guard(text, index, [route["path"]], file, module))
        return out


def _engine_param(node) -> Optional[str]:
    """registrar 形参名：类型是 *gin.RouterGroup / *echo.Group / *gin.Engine。"""
    params = node.child_by_field_name("parameters")
    if params is None:
        return None
    for decl in params.named_children:
        if decl.type != "parameter_declaration":
            continue
        typ = decl.child_by_field_name("type")
        name = decl.child_by_field_name("name")
        if typ is None or name is None:
            continue
        if _ENGINE_PARAM_RE.search(text_of(typ)):
            return text_of(name).strip()
    return None


# ---------- 路由模型（G1/G2/G3） ----------

class _RouterModel:
    """路由变量模型：前缀（Group 链）+ 组级中间件链 + 根级 .Use() 中间件。"""

    __slots__ = ("prefix", "chain", "root_mw")

    def __init__(self):
        self.prefix: Dict[str, str] = {}
        self.chain: Dict[str, List[str]] = {}
        self.root_mw: Dict[str, List[str]] = {}


def _one(node):
    """`a := b` 的左右两侧在 tree-sitter-go 里是 expression_list，取单个元素。"""
    if node is None:
        return None
    if node.type == "expression_list":
        kids = node.named_children
        return kids[0] if len(kids) == 1 else None
    return node


def _call_layers(node) -> List[Tuple[str, str, Any]]:
    """展开链式调用 `a.Use(m).Group("/x")` → [(field, receiver, arguments), ...]（源码顺序）。

    Go 把 `a.Use(x).Use(y)` 解析为 selector(operand=call_expression(...), field=Use)，
    接收者可能是另一个调用，需要下钻到最内层标识符。
    """
    chain: List[Tuple[str, Any]] = []
    cur = node
    recv = ""
    while cur is not None and cur.type == "call_expression":
        fn = cur.child_by_field_name("function")
        if fn is None or fn.type != "selector_expression":
            return []
        args = cur.child_by_field_name("arguments")
        field = text_of(fn.child_by_field_name("field") or "").strip()
        chain.append((field, args))
        operand = fn.child_by_field_name("operand")
        if operand is not None and operand.type == "call_expression":
            cur = operand
            continue
        recv = text_of(operand or "").strip()
        break
    return [(f, recv, a) for f, a in reversed(chain)]


def _build_model(root) -> _RouterModel:
    model = _RouterModel()
    groups: List[Tuple[str, str, Any]] = []
    uses: List[Tuple[str, Any]] = []
    seen_uses = set()
    for node in _walk_all(root):
        if node.type != "call_expression":
            continue
        layers = _call_layers(node)
        if not layers:
            continue
        field, recv, args = layers[-1]
        parent = getattr(node, "parent", None)
        if parent is not None and parent.type == "expression_list":
            parent = parent.parent
        if parent is not None and parent.type in ("short_var_declaration",
                                                  "assignment_statement"):
            left = _one(parent.child_by_field_name("left"))
            names = [text_of(x).strip() for x in
                     (left.named_children if left is not None and left.type == "expression_list"
                      else [left]) if x is not None and x.type == "identifier"]
            if names and field in _ROUTER_CTORS:
                for n in names:
                    model.prefix.setdefault(n, "")
                    model.chain.setdefault(n, [])
                    model.root_mw.setdefault(n, [])
            elif names and field == "Group":
                groups.append((names[0], recv, args))
        for f, r, a in layers:
            if f.lower() != "use":
                continue
            key = (r, text_of(a))
            if key in seen_uses:
                continue
            seen_uses.add(key)
            uses.append((r, a))
    # 多轮解析嵌套 Group（v2 := v1.Group("/v2") 依赖 v1 的前缀）
    for _ in range(8):
        changed = False
        for name, recv, args in groups:
            if name in model.prefix or recv not in model.prefix:
                continue
            kids = _arg_texts(args)
            model.prefix[name] = _join_path(model.prefix[recv],
                                            _first_string(kids[0]) if kids else "")
            model.chain[name] = list(model.chain.get(recv, [])) + kids[1:]
            changed = True
        if not changed:
            break
    for recv, args in uses:
        kids = _arg_texts(args)
        if recv in model.chain:
            model.chain[recv].extend(kids)
        elif recv in model.root_mw:
            model.root_mw[recv].extend(kids)
    return model


def _routes(model: _RouterModel, root):
    """产出 (verb, 完整路径, handler 节点, 调用节点, 路由变量, 路由级中间件)。"""
    for node in _walk_all(root):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "selector_expression":
            continue
        verb = text_of(fn.child_by_field_name("field") or "").lower()
        if verb not in _VERBS:
            continue
        recv = text_of(fn.child_by_field_name("operand") or "").strip()
        args = node.child_by_field_name("arguments")
        kids = args.named_children if args is not None else []
        if len(kids) < 2:
            continue
        rel = _first_string(text_of(kids[0]))
        if rel is None:
            continue
        # 惯例：路径在前、中间件居中、handler 在最后
        handler = kids[-1]
        if handler.type not in ("func_literal", "identifier", "selector_expression"):
            continue
        mw: List[str] = [text_of(k) for k in kids[1:-1]]
        yield verb, _join_path(model.prefix.get(recv, ""), rel), handler, node, recv, mw


def _func_index(root) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for node in _walk_all(root):
        if node.type in ("function_declaration", "method_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                out.setdefault(text_of(n), node)
    return out


def _resolve_handler(handler, index: Dict[str, Any]):
    if handler is None:
        return None
    if handler.type == "func_literal":
        return handler
    name = text_of(handler).split(".")[-1].strip()
    return index.get(name, handler)


def _bind_source(method: str) -> ParamSource:
    m = (method or "").lower()
    if "query" in m:
        return ParamSource.QUERY
    if "uri" in m or "param" in m:
        return ParamSource.PATH
    return ParamSource.BODY


def _dto_params(text: str, structs: Dict[str, List[Tuple[str, str]]],
                seen: set) -> List[Param]:
    """`c.ShouldBindJSON(&user)` + `var user system.SysUser` → 结构体字段作为请求参数。

    Gin 工程普遍用 DTO 接收请求体（例如 setUserInfo 只按 body 里的 id 更新），
    不展开结构体就看不到这类资源标识。绑定方法决定来源：*Query → QUERY，*Uri → PATH，
    JSON/Bind → BODY。
    """
    bound = _BIND_RE.findall(text or "")
    if not bound:
        return []
    types: Dict[str, str] = {}
    for m in _SHORT_DECL_RE.finditer(text or ""):
        types.setdefault(m.group(1), m.group(2).split(".")[-1])
    for m in _VAR_DECL_RE.finditer(text or ""):
        types[m.group(1)] = m.group(2).split(".")[-1]
    out: List[Param] = []
    for method, var in bound:
        source = _bind_source(method)
        for name, ftype in structs.get(types.get(var, ""), []):
            if name in seen:
                continue
            if not _ID_FIELD_RE.search(name):
                continue
            if _is_non_resource_field(name):
                continue  # 命名空间/检索/分页字段不是资源标识
            seen.add(name)
            out.append(Param(name=name, source=source, type=ftype or "string"))
    return out


def _classify_mw(text: str, index: Dict[str, Any]) -> Tuple[bool, str]:
    """中间件是否做鉴权 + 是否角色/权限级（供 A2 授权强度判定）。"""
    raw = (text or "").strip()
    base = raw.split("(")[0].strip().split(".")[-1]
    if _POLICY_MW_RE.search(base):
        # 策略引擎（Casbin/OPA）：鉴权规则在数据里，静态不可判定 → 视为授权决策点
        return True, "policy:" + base
    node = index.get(base)
    body = text_of(node) if node is not None else ""
    is_auth = bool(_AUTH_MW_RE.search(base) or (body and _MW_BODY_AUTH_RE.search(body)))
    role = raw if _ROLE_MW_RE.search(base) else ""
    return is_auth, role


def _auth_info(mw: List[str], index: Dict[str, Any], call) -> AuthInfo:
    has_auth = False
    role = ""
    for text in mw:
        ok, rol = _classify_mw(text, index)
        if ok:
            has_auth = True
        if rol and (not role or rol.startswith("policy:")):
            role = rol
    if has_auth:
        return AuthInfo(present=True, mechanism=AuthMechanism.MIDDLEWARE, role_or_perm=role,
                        scope="METHOD", line=call.start_point[0] + 1,
                        annotation=(mw[0] if mw else None))
    return AuthInfo(present=False, mechanism=AuthMechanism.NONE, role_or_perm=None,
                    scope="NONE", line=-1)


def _mk_guard(text: str, index: Dict[str, Any], patterns: List[str], file: str,
              module: str) -> Guard:
    ok, _role = _classify_mw(text, index)
    raw = (text or "").strip()
    base = raw.split("(")[0].strip().split(".")[-1]
    node = index.get(base)
    body = text_of(node) if node is not None else ""
    return Guard(
        kind="MIDDLEWARE", name=raw, patterns=list(patterns), has_auth_check=ok,
        depends_on_client_input=bool(_CLIENT_INPUT_RE.search(body or raw)),
        line=node.start_point[0] + 1 if node is not None else -1,
        file=file, module=module,
    )


def _is_privileged(verb: str, handler) -> bool:
    """G6：特权操作 = 方法名前缀 ∪ 原生 SQL 写语句 ∪ 路由写动词。"""
    if verb in _WRITE_VERBS:
        return True
    if handler is None:
        return False
    return has_write_op(handler, "go") or bool(_SQL_WRITE_RE.search(text_of(handler)))


def _scope_patterns(prefix: str) -> List[str]:
    """守卫作用域：组前缀 + /**（G9：不再用空 patterns 表示全局）。"""
    p = (prefix or "").rstrip("/")
    return [p + "/**"] if p else ["/**"]


def _dir_module(file: str) -> str:
    """G10：Go 无构建模块事实，用文件所在目录充当守卫作用域（同包共享、跨包隔离）。"""
    return os.path.dirname(str(file)).replace("\\", "/")


def _arg_texts(args) -> List[str]:
    if args is None:
        return []
    return [text_of(x) for x in args.named_children]


def _first_string(text: str) -> Optional[str]:
    m = re.search(r"[\"'`]([^\"'`]*)[\"'`]", text or "")
    return m.group(1) if m else None


def _join_path(prefix: str, rel: str) -> str:
    prefix = (prefix or "").rstrip("/")
    rel = (rel or "").strip()
    if not rel:
        return prefix
    if not prefix:
        return rel if rel.startswith("/") else "/" + rel
    return prefix + "/" + rel.lstrip("/")


def _walk_all(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.named_children)
