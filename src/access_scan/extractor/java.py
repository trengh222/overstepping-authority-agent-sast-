"""Java/Spring 前端（M1 实现，方案 §6.1）。

基于 tree-sitter-java AST 遍历，识别：
- 路由：@GetMapping/@PostMapping/@PutMapping/@DeleteMapping/@PatchMapping/@RequestMapping（含类级路径前缀合并）
- 参数：@PathVariable、@RequestParam、@RequestBody（Spring 6 隐式 PathVariable 按 PATH 兜底）
- 鉴权：@PreAuthorize / @Secured / @RolesAllowed（类级 + 方法级，方法级优先）
- 特权操作：方法体内含 save/delete/update/export 等写操作调用
- 资源实体：@Entity + @Table；归属字段匹配 user_id/owner_id/created_by/tenant_id/uid 等
"""
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import tree_sitter_java
from tree_sitter import Language, Parser

from ..config import load_ownership, lookup_ownership
from ..ir import (AuthInfo, AuthMechanism, Endpoint, FieldFact, Param, ParamSource,
                  Resource)
from .base import Extractor, Guard, register

_JAVA_LANGUAGE = Language(tree_sitter_java.language())

# 写操作调用前缀 → privilege_op 判定
_WRITE_OP_PREFIXES = (
    "save", "insert", "upsert", "update", "delete", "remove", "write", "export",
    "approve", "reject", "refund", "transfer", "reset", "grant", "upload", "publish",
    "add",
)

# 归属字段名（含 snake/camel）——命中即作为 Resource.owner_field
_OWNER_FIELD_NAMES = (
    "user_id", "userId", "owner_id", "ownerId", "created_by", "createdBy",
    "creator_id", "creatorId", "tenant_id", "tenantId", "uid", "uploader_id", "uploaderId",
)

# 资源标识字段
_IDENTIFIER_FIELD_NAMES = ("id", "uuid", "code", "no")

# DTO/实体字段名是否像「资源标识」（骆驼/下划线/复数，供 @RequestBody 拆包）
_ID_FIELD_CAMEL_RE = re.compile(r"[a-z](Id|Uid|Uuid|Code|Key|No|Num|Name|Title|Username|Email|Slug)$")
_ID_FIELD_SUFFIX_RE = re.compile(r"[_-](id|uuid|code|key|no|name|title|username|email|slug)$", re.I)
_ID_FIELD_PLURAL_RE = re.compile(r"(?:ids|uuids|codes|keys|nos)$", re.I)


def looks_like_resource_id(name: str, type_text: str = "") -> bool:
    """字段/参数名是否像资源标识（与规则 A 的命名阶梯保持一致）。"""
    n = (name or "").strip()
    if not n:
        return False
    if n.lower() in {"id", "uuid", "code", "key", "no", "username", "email", "slug"}:
        return True
    if _ID_FIELD_CAMEL_RE.search(n) or _ID_FIELD_SUFFIX_RE.search(n) \
            or _ID_FIELD_PLURAL_RE.search(n):
        return True
    return False

_HTTP_VERB_ANNOTATION = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}
_AUTH_ANNOTATIONS = ("PreAuthorize", "Secured", "RolesAllowed")
# 自定义 AOP 鉴权注解：不依赖具体注解名，靠「切面引用 + 注解参数语义」双通道识别
_CUSTOM_AUTH_ASPECT_RE = re.compile(
    r"@Before\s*\(\s*[\"']@annotation\s*\(\s*([\w.]+)\s*\)")
_CUSTOM_AUTH_LOGIC_RE = re.compile(
    r"(token|redis|session|login|permission|authority|role|auth)", re.I)
# 注解参数里的鉴权语义开关（checkLogin=true / login=true / requireAuth=true ...）
_AUTH_FLAG_ARG_RE = re.compile(
    r"\b(?:checkLogin|requireLogin|needLogin|loginRequired|requireAuth|needAuth|"
    r"authenticated|auth)\s*=\s*true", re.I)
# Spring 参数绑定：这些类型由框架按标量绑定，其余无注解类型视为对象（query/form）绑定
_SCALAR_PARAM_TYPES = {
    "string", "char", "character", "boolean", "bool", "byte", "short", "int",
    "integer", "long", "float", "double", "bigdecimal", "biginteger", "number",
    "date", "localdate", "localdatetime", "localtime", "instant", "timestamp",
    "uuid", "multipartfile", "httpservletrequest", "httpservletresponse",
    "principal", "model", "modelmap", "bindingresult", "locale", "sessionstatus",
}
# 框架注入的上下文参数（不是客户端可控业务参数，不能作为污点源）
_INJECTED_PARAM_TYPES = {
    "httpservletrequest", "httpservletresponse", "principal", "model", "modelmap",
    "bindingresult", "locale", "sessionstatus", "authentication", "session",
}


def is_injected_param_type(type_text: str) -> bool:
    """框架注入的上下文参数（request/response/principal 等），不作为客户端污点源。"""
    t = re.sub(r"<.*>", "", (type_text or "")).strip().rsplit(".", 1)[-1].lower()
    return t in _INJECTED_PARAM_TYPES


def is_scalar_param_type(type_text: str) -> bool:
    """参数类型是否为框架按标量绑定的简单类型（非对象型污点源）。"""
    t = re.sub(r"<.*>", "", (type_text or "")).strip()
    t = t.rsplit(".", 1)[-1].lower()
    if not t:
        return True  # 类型缺失时保守按标量处理，避免把普通参数当对象
    if t.endswith("[]"):
        return True
    return t in _SCALAR_PARAM_TYPES


def collect_custom_auth_annotations(texts) -> set:
    """从 @Aspect 的 @Before("@annotation(Xxx)") 切面中识别自定义鉴权注解。

    仅当切面方法体附近出现 token/redis/session/登录/权限等校验逻辑时才登记，
    避免把日志/审计切面误当鉴权。
    """
    out: set = set()
    for lang, text in texts:
        if lang != "java" or not text:
            continue
        for m in _CUSTOM_AUTH_ASPECT_RE.finditer(text):
            window = text[m.start():m.start() + 1500]
            if _CUSTOM_AUTH_LOGIC_RE.search(window):
                out.add(m.group(1).split(".")[-1])
    return out

# 服务/仓储后缀 → 实体名推断（OrderService → Order）
_ENTITY_SUFFIX_RE = re.compile(r"(ServiceImpl|serviceImpl|Service|Repository|Repo|Mapper|DAO|Dao|Gateway|Store)$")

# 规则 B 守卫（拦截器/过滤器）识别
_GUARD_CLASS_RE = re.compile(r"HandlerInterceptor|OncePerRequestFilter|javax\.servlet\.Filter")
_GUARD_AUTH_RE = re.compile(
    r"(hasRole|hasAnyRole|hasAuthority|isAuthenticated|getAuthentication|getContext\(\)"
    r"|checkPermission|authorize|authority|\brole\b|\badmin\b)", re.I,
)
_CLIENT_INPUT_RE = re.compile(r"\.(getParameter|getHeader|getCookies|getQueryString)\(")
_AUTH_METHOD_NAMES = ("preHandle", "doFilterInternal", "doFilter")


def _text(node: Any) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _has_session_login(method_node: Any) -> bool:
    """HttpSession 参数 + 方法体读取会话属性（getAttribute）→ 会话级认证。"""
    params_node = method_node.child_by_field_name("parameters")
    if params_node is None:
        return False
    if not any("HttpSession" in _text(p) for p in params_node.named_children):
        return False
    body = method_node.child_by_field_name("body")
    return body is not None and ".getAttribute(" in _text(body)


def _annotations(node: Any) -> List[Tuple[str, str]]:
    """返回 [(注解名, 原始参数文本)]，如 [("GetMapping", '("/{id}")')]。

    tree-sitter-java：注解位于 `modifiers` 分组节点内；
    带参数的注解节点类型为 annotation，无参数的为 marker_annotation
    （如 @Override / @RestController）。
    """
    out: List[Tuple[str, str]] = []
    for group in node.named_children:
        if group.type != "modifiers":
            continue
        for ch in group.named_children:
            if ch.type == "annotation":
                name_node = ch.child_by_field_name("name")
                name = _text(name_node) if name_node else _text(ch).lstrip("@").split("(")[0]
                args_node = ch.child_by_field_name("arguments")
                raw = _text(args_node).strip() if args_node else ""
                out.append((name, raw))
            elif ch.type == "marker_annotation":
                name_node = ch.child_by_field_name("name")
                name = _text(name_node) if name_node else _text(ch).lstrip("@")
                out.append((name, ""))
    return out


def _quoted_strings(text: str) -> List[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', text)


def _http_verb_from_args(args_raw: str) -> str:
    m = re.search(r"RequestMethod\.([A-Z]+)", args_raw, re.I)
    if m:
        return m.group(1).upper()
    for verb in ("POST", "PUT", "DELETE", "PATCH"):
        if re.search(rf"\b{verb}\b", args_raw, re.I):
            return verb
    return "GET"


def _join_path(prefix: str, sub: str) -> str:
    if not prefix:
        return sub or "/"
    if not sub:
        return prefix
    return prefix.rstrip("/") + "/" + sub.lstrip("/")


def _looks_like_identifier(name: str) -> bool:
    """Spring 6 隐式 @PathVariable 兜底：名字像资源 id 且无显式来源注解。"""
    n = name.lower()
    return n in ("id", "uuid", "code", "key", "no") or n.endswith("_id") or (len(n) > 2 and n.endswith("id"))


def _path_has_param(path: str, name: str) -> bool:
    """路径模板中是否真的有该占位符（{id} / {id:\\d+}）。"""
    return bool(re.search(r"\{" + re.escape(name) + r"(?:[:}])", path or ""))


@dataclass
class JavaEndpointCtx:
    """规则层所需的 handler 上下文：AST 节点 + 类字段表 + 源码行。"""
    class_node: Any
    method_node: Any
    fields: Dict[str, str]          # 字段名 -> 声明类型
    file: str
    lines: List[str]
    language: str = "java"
    body_aliases: Dict[str, str] = field(default_factory=dict)  # DTO 字段名 -> 形参名

    @property
    def node(self) -> Any:
        return self.method_node


JavaGuard = Guard  # 向后兼容别名（测试/旧引用使用）


def _iter_calls(node: Any):
    if node.type == "method_invocation":
        yield node
    for ch in node.named_children:
        yield from _iter_calls(ch)


# 继承链事实涉及的声明节点：class / interface / enum / record
_HIERARCHY_NODE_TYPES = ("class_declaration", "interface_declaration",
                         "enum_declaration", "record_declaration")


def _type_names(node: Any) -> List[str]:
    """从 superclass / super_interfaces / extends_interfaces 取出类型简单名（去泛型）。"""
    out: List[str] = []
    for ch in node.named_children:
        if ch.type == "type_list":
            out.extend(_type_names(ch))
        elif ch.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
            out.append(_text(ch).split("<")[0].strip().split(".")[-1])
    if not out and node.type in ("type_identifier", "scoped_type_identifier"):
        out.append(_text(node).split("<")[0].strip().split(".")[-1])
    return [n for n in out if n]


def _dedupe(items: List[str]) -> List[str]:
    out: List[str] = []
    for it in items:
        if it and it not in out:
            out.append(it)
    return out


def find_write_ops(method_node: Any) -> List[Tuple[str, int]]:
    """handler 内敏感写操作调用：[(方法名, 行号)]，供规则 B 判定与举证。

    集合 API（List.add/addAll …）不是业务写操作，需按接收者类型排除：
    领域对象的装配/聚合代码不应把只读接口误判成「特权写」。
    """
    body = method_node.child_by_field_name("body")
    if body is None:
        return []
    coll_vars = _collection_vars(body)
    ops: List[Tuple[str, int]] = []
    for call in _iter_calls(body):
        name_node = call.child_by_field_name("name")
        cname = _text(name_node) if name_node else ""
        if not cname.lower().startswith(_WRITE_OP_PREFIXES):
            continue
        if cname.lower() in _COLLECTION_MUTATORS and _is_collection_receiver(call, coll_vars):
            continue
        ops.append((cname, call.start_point[0] + 1))
    return ops


# 集合类型声明 → 变量名（判定 add/addAll/put/remove 是否为集合 API）
_COLLECTION_DECL_RE = re.compile(
    r"\b(?:List|Set|Map|Collection|Deque|Queue|Iterable|ArrayList|LinkedList|HashMap|"
    r"HashSet|TreeMap|TreeSet|LinkedHashMap|LinkedHashSet|Vector|Stack|"
    r"CopyOnWriteArrayList)\s*(?:<[^;=(){}]*>)?\s+(\w+)\s*[=;]", re.I)
# 集合工具类/流式 API 的接收者
_COLLECTION_UTILS = {"collections", "arrays", "objects", "stream", "streams", "stringutils"}
_COLLECTION_MUTATORS = {"add", "addall", "put", "putall", "remove", "removeall",
                        "removeif", "clear", "sort", "offer", "push", "pop"}


def _collection_vars(body: Any) -> set:
    return {m.group(1) for m in _COLLECTION_DECL_RE.finditer(_text(body))}


def _is_collection_receiver(call: Any, coll_vars: set) -> bool:
    obj = call.child_by_field_name("object")
    if obj is None:
        return False
    recv = _text(obj).strip().split(".")[-1]
    return recv in coll_vars or recv.lower() in _COLLECTION_UTILS


# 序列化/脱敏相关注解：命中即认为该字段不会原样返回（B6 排除）
_PROTECTED_FIELD_ANNOTATIONS = {
    "JsonIgnore", "JsonIgnoreProperties", "JsonBackReference", "Transient",
    "Sensitive", "Desensitize", "Desensitized", "Mask", "Encrypt",
}


def _field_annotations(member: Any) -> List[str]:
    """字段声明上的注解名（含 @JsonIgnore 等 marker_annotation）。

    注意：本项目的 tree-sitter-java 语法里注解包在 `modifiers` 节点内，且既不是
    field_declaration 的 `modifiers` 字段（child_by_field_name 取不到），注解节点
    也不一定是 named child —— 因此沿 children 递归两层 + 文本兜底。
    """
    mods = member.child_by_field_name("modifiers")
    start = mods if mods is not None else member
    out: List[str] = []

    def _walk(node: Any, depth: int) -> None:
        if node.type in ("annotation", "marker_annotation"):
            name_node = node.child_by_field_name("name")
            raw = _text(name_node if name_node is not None else node).strip().lstrip("@")
            name = re.split(r"[\s(]", raw)[0] if raw else ""
            if name:
                out.append(name)
            return
        if depth >= 2:
            return
        for ch in node.children:
            _walk(ch, depth + 1)

    for ch in start.children:
        _walk(ch, 0)
    if not out:
        # 文本兜底：modifiers 文本里 @Name 形式的注解（参数里的点号引用不误收）
        out = re.findall(r"@([A-Za-z_][\w.]*)", _text(start))
    return [a.split("(")[0] for a in out if a]


@register("java")
class JavaExtractor(Extractor):
    language = "java"

    # ---- 解析 ----
    def parse(self, src: bytes):
        if isinstance(src, str):
            src = src.encode("utf-8")
        parser = Parser(_JAVA_LANGUAGE)
        return parser.parse(src)

    # ---- L2 提取（基类抽象方法） ----
    def extract_endpoints(self, ast, file: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        pkg = self._package_name(ast)
        field_map = self.collect_class_fields(ast)   # DTO 字段事实（@RequestBody 拆包用）
        for cls in self._iter_classes(ast.root_node):
            cls_name = _text(cls.child_by_field_name("name"))
            cls_annots = _annotations(cls)
            prefix = ""
            for name, raw in cls_annots:
                if name == "RequestMapping":
                    segs = _quoted_strings(raw)
                    prefix = segs[0] if segs else ""
            body = cls.child_by_field_name("body")
            if body is None:
                continue
            for member in body.named_children:
                if member.type != "method_declaration":
                    continue
                ep = self._build_endpoint(file, cls_name, cls_annots, prefix, member)
                if ep is not None:
                    # 注册可达：Java 用全限定类名（包 + 类），供 Spring 扫描覆盖判定
                    ep.container = f"{pkg}.{cls_name}" if pkg else cls_name
                    self._expand_body_params(ep, member, field_map)
                    endpoints.append(ep)
        return endpoints

    @staticmethod
    def _expand_body_params(ep: Endpoint, method_node: Any,
                            field_map: Dict[str, List[FieldFact]]) -> None:
        """@RequestBody DTO 拆包：把 body 对象的标识字段补成 BODY 参数。

        `rename(@RequestBody RenameRequest request)` 中真正可控的是 `request.getDocId()`；
        不拆包时只看到 BODY 参数 `request`，命名不像标识 → 规则 A 直接跳过（漏报）。
        拆出的字段参数名与 DTO 字段同名，污点追踪阶段按 `<形参名>.<字段名>` 关联。
        """
        known = {(p.name, p.source) for p in ep.params}
        formals = method_node.child_by_field_name("parameters")
        if formals is None:
            return
        for fp in formals.named_children:
            if fp.type not in ("formal_parameter", "spread_parameter"):
                continue
            if not any(n == "RequestBody" for n, _ in _annotations(fp)):
                continue
            type_node = fp.child_by_field_name("type")
            tname = re.sub(r"<.*>", "", _text(type_node) if type_node else "").strip()
            tname = tname.rsplit(".", 1)[-1]
            for fact in field_map.get(tname, []):
                if not looks_like_resource_id(fact.name, fact.type):
                    continue
                if (fact.name, ParamSource.BODY) in known:
                    continue
                ep.params.append(Param(name=fact.name, source=ParamSource.BODY,
                                       type=fact.type))
                known.add((fact.name, ParamSource.BODY))

    @staticmethod
    def _package_name(ast) -> str:
        for ch in ast.root_node.named_children:
            if ch.type == "package_declaration":
                m = re.search(r"package\s+([\w.]+)", _text(ch))
                if m:
                    return m.group(1)
        return ""

    def extract_resources(self, ast, file: str) -> List[Resource]:
        model = load_ownership()
        resources: List[Resource] = []
        for cls in self._iter_classes(ast.root_node):
            cls_annots = _annotations(cls)
            is_entity = any(n == "Entity" for n, _ in cls_annots)
            cls_name = _text(cls.child_by_field_name("name"))
            # 所有权模型声明过的类（含不带 @Entity 的 PO/DTO）同样纳入隐私判定
            if not is_entity and lookup_ownership(cls_name, model) is None:
                continue
            entity = cls_name
            owner = identifier = None
            for name, raw in cls_annots:
                if name == "Table":
                    segs = _quoted_strings(raw)
                    if segs:
                        entity = segs[0]
            body = cls.child_by_field_name("body")
            if body is not None:
                for member in body.named_children:
                    if member.type != "field_declaration":
                        continue
                    decl = member.child_by_field_name("declarator")
                    fname = _text(decl.child_by_field_name("name")) if decl else ""
                    if not fname:
                        continue
                    if identifier is None and fname in _IDENTIFIER_FIELD_NAMES:
                        identifier = fname
                    if owner is None and fname in _OWNER_FIELD_NAMES:
                        owner = fname
            identifier = identifier or "id"
            # 所有权模型三层：声明式优先（按类名或表名匹配）
            declared = lookup_ownership(cls_name, model) or lookup_ownership(entity, model)
            if declared is not None:
                owner = declared.get("owner_field") or owner
                privacy, confidence = declared.get("privacy", "UNKNOWN"), 1.0
            else:
                privacy, confidence = "UNKNOWN", 0.5
            resources.append(Resource(
                entity=entity, identifier_field=identifier, owner_field=owner,
                privacy=privacy, confidence=confidence,
            ))
        return resources

    # ---- 规则层所需的 handler 上下文 ----
    def endpoint_contexts(self, ast, file: str, src: bytes) -> Dict[str, JavaEndpointCtx]:
        lines = src.decode("utf-8", errors="replace").splitlines()
        out: Dict[str, JavaEndpointCtx] = {}
        field_map = self.collect_class_fields(ast)   # DTO 拆包别名表（污点追踪用）
        for cls in self._iter_classes(ast.root_node):
            cls_name = _text(cls.child_by_field_name("name"))
            fields = self._collect_fields(cls)
            body = cls.child_by_field_name("body")
            if body is None:
                continue
            for member in body.named_children:
                if member.type != "method_declaration":
                    continue
                name_node = member.child_by_field_name("name")
                mname = _text(name_node) if name_node else ""
                if not mname:
                    continue
                aliases = self._body_aliases(member, field_map)
                out[f"{cls_name}.{mname}"] = JavaEndpointCtx(
                    cls, member, fields, file, lines, body_aliases=aliases)
        return out

    @staticmethod
    def _body_aliases(method_node: Any,
                      field_map: Dict[str, List[FieldFact]]) -> Dict[str, str]:
        """DTO 标识字段 -> 绑定该 DTO 的形参名（`docId -> request`）。

        污点分析以「变量名集合」为源；这里把 DTO 字段补成源的同时，
        也把承载它的形参名放进去，`request.getDocId()` 这类实参才会被判为污点。
        """
        out: Dict[str, str] = {}
        formals = method_node.child_by_field_name("parameters")
        if formals is None:
            return out
        for fp in formals.named_children:
            if fp.type not in ("formal_parameter", "spread_parameter"):
                continue
            if not any(n == "RequestBody" for n, _ in _annotations(fp)):
                continue
            name_node = fp.child_by_field_name("name")
            pname = _text(name_node) if name_node is not None else ""
            type_node = fp.child_by_field_name("type")
            tname = re.sub(r"<.*>", "", _text(type_node) if type_node else "").strip()
            tname = tname.rsplit(".", 1)[-1]
            if not pname or not tname:
                continue
            for fact in field_map.get(tname, []):
                if looks_like_resource_id(fact.name, fact.type):
                    out.setdefault(fact.name, pname)
        return out

    # ---- 内部工具 ----
    @staticmethod
    def _iter_classes(root: Any):
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "class_declaration" and node.child_by_field_name("name"):
                yield node
            stack.extend(node.named_children)

    @staticmethod
    def _collect_fields(cls: Any) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        body = cls.child_by_field_name("body")
        if body is None:
            return fields
        for member in body.named_children:
            if member.type != "field_declaration":
                continue
            type_node = member.child_by_field_name("type")
            ftype = re.sub(r"<.*>", "", _text(type_node) if type_node else "")
            decl = member.child_by_field_name("declarator")
            if decl is None:
                continue
            name_node = decl.child_by_field_name("name")
            fname = _text(name_node) if name_node else ""
            if fname and ftype:
                fields[fname] = ftype
        return fields

    # ---- 字段级事实（规则 B6：属性级越权/敏感字段暴露） ----
    def collect_class_fields(self, ast) -> Dict[str, List[FieldFact]]:
        """整文件所有类的字段事实：{类名: [FieldFact]}（含注解与脱敏标记）。

        与 endpoint_contexts 的 fields 表不同，这里保留注解与类型，供 B6 判定
        「返回对象是否暴露敏感字段」；类名重名时合并字段（保守，宁多不漏）。
        """
        out: Dict[str, List[FieldFact]] = {}
        for cls in self._iter_classes(ast.root_node):
            name_node = cls.child_by_field_name("name")
            cname = _text(name_node) if name_node is not None else ""
            if not cname:
                continue
            facts = self._class_field_facts(cls)
            if facts:
                out.setdefault(cname, []).extend(facts)
        return out

    @staticmethod
    def _class_field_facts(cls: Any) -> List[FieldFact]:
        body = cls.child_by_field_name("body")
        if body is None:
            return []
        out: List[FieldFact] = []
        for member in body.named_children:
            if member.type != "field_declaration":
                continue
            type_node = member.child_by_field_name("type")
            ftype = re.sub(r"<.*>", "", _text(type_node) if type_node else "").strip()
            decl = member.child_by_field_name("declarator")
            if decl is None:
                continue
            name_node = decl.child_by_field_name("name")
            fname = _text(name_node) if name_node is not None else ""
            if not fname:
                continue
            annots = _field_annotations(member)
            protected = (any(a.split(".")[-1] in _PROTECTED_FIELD_ANNOTATIONS for a in annots)
                         or "WRITE_ONLY" in " ".join(annots))  # @JsonProperty(access=WRITE_ONLY)
            out.append(FieldFact(name=fname, type=ftype, annotations=annots,
                                 protected=protected))
        return out

    def _build_endpoint(self, file: str, cls_name: str, cls_annots: List[Tuple[str, str]],
                        prefix: str, method_node: Any) -> Optional[Endpoint]:
        annots = _annotations(method_node)
        mapping = [(n, a) for n, a in annots if n in _HTTP_VERB_ANNOTATION or n == "RequestMapping"]
        if not mapping:
            return None

        name, raw = mapping[0]
        if name == "RequestMapping":
            http_method = _http_verb_from_args(raw)
        else:
            http_method = _HTTP_VERB_ANNOTATION[name]
        segs = _quoted_strings(raw)
        path = segs[0] if segs else ""
        full_path = _join_path(prefix, path)

        # 参数提取
        params: List[Param] = []
        formals = method_node.child_by_field_name("parameters")
        if formals is not None:
            for fp in formals.named_children:
                if fp.type not in ("formal_parameter", "spread_parameter"):
                    continue
                src: Optional[ParamSource] = None
                for n, _ in _annotations(fp):
                    if n == "PathVariable":
                        src = ParamSource.PATH
                        break
                    if n == "RequestParam":
                        src = ParamSource.QUERY
                        break
                    if n == "RequestBody":
                        src = ParamSource.BODY
                        break
                name_node = fp.child_by_field_name("name")
                pname = _text(name_node) if name_node else ""
                type_node = fp.child_by_field_name("type")
                ptype = _text(type_node) if type_node else ""
                if src is None and _looks_like_identifier(pname):
                    # D7：只有路径模板中真实存在的占位符才判 PATH；否则按 Spring 默认 query
                    src = (ParamSource.PATH if _path_has_param(full_path, pname)
                           else ParamSource.QUERY)
                if src is None and pname and not is_injected_param_type(ptype):
                    # Spring 通用绑定语义：无注解的业务参数由框架按 query/form 绑定
                    # （标量 = @RequestParam，对象 = 属性绑定），均由客户端可控。
                    src = ParamSource.QUERY
                if src is not None and pname:
                    params.append(Param(name=pname, source=src, type=ptype))

        # 鉴权：方法级优先，其次类级
        auth = AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                        role_or_perm=None, scope="NONE", line=-1)
        custom_auth = getattr(self, "custom_auth_annotations", ()) or ()
        for scope, ann_list in (("METHOD", annots), ("CLASS", cls_annots)):
            for n, raw in ann_list:
                if n in _AUTH_ANNOTATIONS or n in custom_auth:
                    segs = _quoted_strings(raw)
                    line = method_node.start_point[0] + 1 if scope == "METHOD" else -1
                    auth = AuthInfo(present=True, mechanism=AuthMechanism.ANNOTATION,
                                    role_or_perm=segs[0] if segs else raw,
                                    scope=scope, line=line, annotation=n)
                    break
                # 通用通道：注解带 checkLogin/login/requireAuth=true 等鉴权语义开关。
                # 不绑定具体注解名；false 或无开关的注解不会被当作鉴权。
                if _AUTH_FLAG_ARG_RE.search(raw or ""):
                    line = method_node.start_point[0] + 1 if scope == "METHOD" else -1
                    auth = AuthInfo(present=True, mechanism=AuthMechanism.ANNOTATION,
                                    role_or_perm=raw, scope=scope, line=line, annotation=n)
                    break
            if auth.present:
                break
        # 会话级认证：HttpSession 参数 + 读取会话属性（getAttribute）→ 已登录。
        # 与注解/拦截器同属「认证已存在」，A3（未授权）不应再报。
        if not auth.present and _has_session_login(method_node):
            auth = AuthInfo(present=True, mechanism=AuthMechanism.SESSION,
                            role_or_perm=None, scope="METHOD",
                            line=method_node.start_point[0] + 1,
                            annotation="HttpSession")

        method_name = _text(method_node.child_by_field_name("name"))
        handler = f"{cls_name}.{method_name}"
        return Endpoint(
            id=f"{file}:{handler}:{http_method}:{full_path}",
            file=file,
            method=http_method,
            path=full_path,
            handler=handler,
            params=params,
            auth=auth,
            privilege_op=self._has_write_op(method_node),
            line_start=method_node.start_point[0] + 1,
            line_end=method_node.end_point[0] + 1,
        )

    def _has_write_op(self, method_node: Any) -> bool:
        return bool(find_write_ops(method_node))

    # ---- L2 守卫提取（规则 B 用） ----
    def extract_guards(self, ast, file: str) -> Tuple[List[JavaGuard], List[Tuple[str, List[str]]]]:
        """提取文件内的垂直鉴权设备。

        返回 (guards, chains)：
        - guards：本文件内可分析逻辑的拦截器/过滤器（patterns 暂为空=全局，
          由跨文件的 link_guards 绑定）；
        - chains：WebMvcConfigurer 中 addInterceptor 引用与其路径模式
          (ref_text, patterns)，供跨文件绑定。
        """
        guards: List[JavaGuard] = []
        chains: List[Tuple[str, List[str]]] = []
        for cls in self._iter_classes(ast.root_node):
            cls_name = _text(cls.child_by_field_name("name"))
            ifaces, super_ = self._interfaces_text(cls)
            impl = ifaces + super_
            body = cls.child_by_field_name("body")
            if body is None:
                continue
            guards.extend(_security_chain_guards(cls_name, body, file))
            if _GUARD_CLASS_RE.search(impl):
                auth_method = self._find_method(body, _AUTH_METHOD_NAMES)
                logic = _text(auth_method) if auth_method is not None else _text(body)
                if not _GUARD_AUTH_RE.search(logic):
                    continue  # 无鉴权逻辑的拦截器不构成守卫
                line = auth_method.start_point[0] + 1 if auth_method is not None else cls.start_point[0] + 1
                kind = "FILTER" if re.search(r"Filter", impl) else "INTERCEPTOR"
                guards.append(JavaGuard(
                    kind=kind, name=cls_name, patterns=[],
                    has_auth_check=True,
                    depends_on_client_input=bool(_CLIENT_INPUT_RE.search(logic)),
                    line=line, file=file,
                ))
            elif re.search(r"WebMvcConfigurer", impl) and "addInterceptor" in _text(body):
                chains.extend(self._config_chains(body))
        return guards, chains

    def extract_hierarchy(self, ast, file: str) -> Dict[str, List[str]]:
        """类型继承链事实：`{类型名: [直接父类型名]}`（extends / implements / 接口 extends）。

        只记录「谁是谁的父类型」，不做全限定名解析（与 method_index 的简单类名对齐）；
        同名类型跨包重名时取并集，宁多勿缺——多出来的边只会多给一次跨过程机会。
        """
        out: Dict[str, List[str]] = {}
        stack = [ast.root_node]
        while stack:
            node = stack.pop()
            if node.type in _HIERARCHY_NODE_TYPES:
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    parents: List[str] = []
                    sup = node.child_by_field_name("superclass")
                    if sup is not None:                       # class X extends Y
                        parents.extend(_type_names(sup))
                    ifaces = node.child_by_field_name("interfaces")
                    if ifaces is not None:                    # class/enum/record ... implements A, B
                        parents.extend(_type_names(ifaces))
                    for ch in node.named_children:            # interface X extends A, B
                        if ch.type == "extends_interfaces":
                            parents.extend(_type_names(ch))
                    out[_text(name_node)] = _dedupe(parents)
            stack.extend(node.named_children)
        return out

    @staticmethod
    def _interfaces_text(cls: Any) -> Tuple[str, str]:
        iface_node = cls.child_by_field_name("interfaces")
        sup_node = cls.child_by_field_name("superclass")
        return (_text(iface_node) if iface_node else ""), (_text(sup_node) if sup_node else "")

    @staticmethod
    def _find_method(body: Any, names) -> Optional[Any]:
        for member in body.named_children:
            if member.type != "method_declaration":
                continue
            name_node = member.child_by_field_name("name")
            mname = _text(name_node) if name_node else ""
            if mname in names:
                return member
        return None

    @staticmethod
    def _config_chains(body: Any) -> List[Tuple[str, List[str]]]:
        """从 Configurer 方法体解析注册链路：[("new AuthInterceptor", ["/admin/safe/**"])]。"""
        def norm_ref(s: str) -> str:
            return re.sub(r"\(\s*\)?\s*$", "", s.strip())  # 去掉尾部括号，统一引用形式

        chains: List[Tuple[str, List[str]]] = []
        refs_seen: List[str] = []
        for call in _iter_calls(body):
            name_node = call.child_by_field_name("name")
            if not name_node:
                continue
            cname = _text(name_node)
            if cname == "addPathPatterns":
                pats = _quoted_strings(_text(call)) or ["/**"]
                for m in re.finditer(r"addInterceptor\(\s*([^)]*)", _text(call)):
                    ref = norm_ref(m.group(1))
                    refs_seen.append(ref)
                    chains.append((ref, list(pats)))
            elif cname == "addInterceptor":
                args_node = call.child_by_field_name("arguments")
                if args_node is not None and args_node.named_children:
                    ref = norm_ref(_text(args_node.named_children[0]))
                    if ref not in refs_seen:
                        chains.append((ref, ["/**"]))  # 未绑定路径 → 全局
        return chains


# ---- Spring Security 声明式鉴权（SecurityFilterChain：requestMatchers("/x/**").authenticated()）----
_SEC_MATCHER_RE = re.compile(
    r"\b(?:requestMatchers|antMatchers|mvcMatchers|regexMatchers)\s*\(")
_SEC_PROTECT_CALL_RE = re.compile(
    r"\.\s*(authenticated|fullyAuthenticated|hasRole|hasAnyRole|hasAuthority|"
    r"hasAnyAuthority|access|denyAll)\s*\(")


def _paren_text(text: str, open_pos: int) -> str:
    """取 text[open_pos] 处 '(' 的平衡括号内容（不含外层括号）。"""
    if open_pos < 0 or open_pos >= len(text) or text[open_pos] != "(":
        return ""
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i]
    return text[open_pos + 1:]


def _security_chain_guards(cls_name: str, body: Any, file: str) -> List[Guard]:
    """从 SecurityFilterChain 配置类提取「路径 → 保护」声明，合成 CONFIGURER 守卫。

    只认保护型链式调用（authenticated/hasRole/...）；permitAll/anonymous 不算守卫。
    与拦截器守卫一样，最终由 link_guards + 模块归属决定覆盖范围。
    """
    text = _text(body)
    if "SecurityFilterChain" not in text and not re.search(
            r"authorizeHttpRequests|authorizeRequests", text):
        return []
    out: List[Guard] = []
    seen: set = set()
    for m in _SEC_MATCHER_RE.finditer(text):
        pats = _quoted_strings(_paren_text(text, m.end() - 1))
        if not pats:
            continue
        tail = text[m.end():m.end() + 300]
        if _SEC_PROTECT_CALL_RE.search(tail) is None:
            continue
        key = tuple(pats)
        if key in seen:
            continue
        seen.add(key)
        out.append(Guard(
            kind="CONFIGURER", name=f"{cls_name}#securityChain", patterns=list(pats),
            has_auth_check=True, depends_on_client_input=False,
            line=body.start_point[0] + 1 + text[:m.start()].count("\n"),
            file=file, registered=True,
        ))
    return out


def guard_to_dict(g: Guard) -> dict:
    """守卫序列化（增量扫描基线用）。"""
    return asdict(g)


def guard_from_dict(d: dict) -> Guard:
    return Guard(**d)


# 注册链路解析后由 extractor/base.py 的 link_guards 做跨文件绑定（语言中立）