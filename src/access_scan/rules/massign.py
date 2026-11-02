"""规则 C：客户端可控权限字段提权（Mass Assignment，A4 子类）。

形态：请求体/参数里的权限敏感字段（admin/role/is_admin/permissions…）几乎直接
进入权限决策——模型构造 kw（User(admin=...)）、属性赋值（obj.admin = ...）——
普通客户端因此可以自封管理员。VAmPI 的 POST /users/v1/register 即此类
（request_data['admin'] → User(admin=admin) → db.session.add）。

Java：启发式——setXxx(权限词) setter 实参引用 BODY/QUERY 参数、或 handler 内
getParameter("admin") 等直接读取，且存在持久化调用（方向保守，交 L5 LLM 复核）。
其他语言暂未覆盖（M4 前端启发式层尚未实现 mass assignment 形态）。
"""
import re
from typing import Any, List, Optional, Set, Tuple

from ..dataflow import asts
from ..ir import Candidate, ParamSource, ResourceAccess

# 权限敏感字段名（构造 kw / 属性名 / 载荷字段共用）
_PRIV_FIELD_RE = re.compile(
    r"^(?:is[_\-]?|can[_\-]?|has[_\-]?)?"
    r"(?:admin|super[_\-]?user|staff|moderator|manager|role[s]?|"
    r"permission[s]?|privilege[s]?|user[_\-]?type)$", re.I)

# 客户端 body 容器来源
_BODY_SRC_RE = re.compile(r"^request\.(?:get_json\(\)|json|form|data|get_data\(\))$")
_BODY_PARAM_NAMES = {"request_data", "req_data", "form_data", "payload", "body",
                     "req_body", "json_data", "post_data"}

_GETTER_NAME_RE = re.compile(r"^(?:get|getlist)$")
_STR_LIT_RE = re.compile(r"""['"]{1,3}([^'"]+)['"]{1,3}""")

# 持久化收尾调用（属性赋值 sink 要求存在其一）
_PERSIST_CALLS = {"add", "commit", "save", "saveall", "insert", "update", "merge",
                  "persist", "put", "create"}

_LITERAL_TYPES = {"true", "false", "integer", "float", "string", "none",
                  "list", "dictionary", "tuple", "set", "concatenated_string"}

# Java：setXxx 权限 setter / getParameter("admin") 直接读取
_PRIV_SETTER_RE = re.compile(
    r"^set(?:is|can|has)?(?:admin|superuser|staff|moderator|manager|role[s]?|"
    r"permission[s]?|privilege[s]?|usertype)$", re.I)
_DIRECT_REQ_RE = re.compile(
    r"getParameter\s*\(\s*[\"']\s*(?:is[_\-]?)?(?:admin|super[_\-]?user|staff|"
    r"moderator|role[s]?|permission[s]?|privilege[s]?|user[_\-]?type)\s*[\"']\s*\)", re.I)


def _txt(node: Any) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _walk(node: Any):
    if node is None:
        return
    yield node
    for ch in node.named_children:
        yield from _walk(ch)


# ---------- Java：setter/请求参数启发式 ----------

def _word_in(name: str, text: str) -> bool:
    return bool(re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text))


def _recall_java(endpoint, ctx) -> List[Candidate]:
    src = _txt(ctx.node)
    param_names = {p.name for p in endpoint.params
                   if p.source in (ParamSource.BODY, ParamSource.QUERY)}
    setter_lines: List[int] = []
    for call in asts.iter_calls(ctx.node, "java"):
        name = (asts.call_name(call) or "")
        if not _PRIV_SETTER_RE.match(name):
            continue
        if any(_word_in(p, asts.call_arg_texts(call)) for p in param_names):
            setter_lines.append(call.start_point[0] + 1)
    direct = _DIRECT_REQ_RE.search(src)
    if not setter_lines and not direct:
        return []
    persisting = any((asts.call_name(c) or "").lower() in _PERSIST_CALLS
                     for c in asts.iter_calls(ctx.node, "java"))
    if not persisting:
        return []
    if setter_lines:
        line = setter_lines[0]
    else:
        line = src[:direct.start()].count("\n") + 1 if direct else -1
    src_lines = src.splitlines()
    text = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
    access = ResourceAccess(
        entity="", identifier_param="privilege_field",
        flow=["客户端可控字段直接写入权限属性 setter/请求参数",
              "随后进入持久化调用（save/insert/update）"],
        ownership_predicate=False,
        sink_snippet=f"{ctx.file}:{line}: {text}", sink_line=line,
    )
    return [Candidate(endpoint=endpoint, access=access, subtype="A4", rule_id="C-mass")]


# ---------- JavaScript/TypeScript：权限字段写入启发式 ----------
_JS_BODY_RE = re.compile(
    r"req\.(?:body|query|params|data)\b|request\.(?:body|query|params|data)\b", re.I)


def _js_from_body(node: Any) -> bool:
    """node 的值是否来自客户端 body/query/params（含 spread ...req.body）。"""
    if node is None:
        return False
    if _JS_BODY_RE.search(_txt(node)):
        return True
    if node.type == "spread_element":
        return _js_from_body(node.child_by_field_name("argument"))
    return False


def _recall_js(endpoint, ctx) -> List[Candidate]:
    """JS/TS：权限字段由客户端 body/query/params 写入模型（构造/赋值 + 持久化）。"""
    node = ctx.node
    writes: List[Tuple[str, int]] = []
    # 1. 对象构造：Model.create({ role: req.body.role }) / { ...req.body }
    for call in asts.iter_calls(node, "javascript"):
        args = call.child_by_field_name("arguments")
        if args is None:
            continue
        for arg in args.named_children:
            if arg.type != "object":
                continue
            for pair in arg.named_children:
                if pair.type == "pair":
                    key = _txt(pair.child_by_field_name("key") or "").strip()
                    if _PRIV_FIELD_RE.match(key) and _js_from_body(pair.child_by_field_name("value")):
                        writes.append((key, pair.start_point[0] + 1))
                elif pair.type == "spread_element" and _js_from_body(pair):
                    writes.append(("*", pair.start_point[0] + 1))
    # 2. 属性赋值：obj.role = req.body.role
    for n in _walk(node):
        if n.type != "assignment_expression":
            continue
        left = n.child_by_field_name("left")
        right = n.child_by_field_name("right")
        if left is None or left.type != "member_expression" or right is None:
            continue
        field = _txt(left.child_by_field_name("property") or "").strip()
        if _PRIV_FIELD_RE.match(field) and _js_from_body(right):
            writes.append((field, n.start_point[0] + 1))
    if not writes:
        return []
    persisting = any((asts.call_name(c) or "").lower() in _PERSIST_CALLS
                     for c in asts.iter_calls(node, "javascript"))
    if not persisting:
        return []
    field, line = writes[0]
    text = ctx.lines[line - 1].strip() if 0 < line <= len(ctx.lines) else ""
    access = ResourceAccess(
        entity="", identifier_param=field,
        flow=[f"权限字段 '{field}' 由客户端 body/query/params 写入模型",
              "随后进入持久化调用（create/save/update）"],
        ownership_predicate=False,
        sink_snippet=f"{ctx.file}:{line}: {text}", sink_line=line,
    )
    return [Candidate(endpoint=endpoint, access=access, subtype="A4", rule_id="C-mass")]


def recall_massign(endpoint, ctx) -> List[Candidate]:
    """规则 C：客户端可控权限字段提权。按语言分派；未覆盖语言暂不召回。"""
    lang = getattr(ctx, "language", "java")
    if lang == "java":
        return _recall_java(endpoint, ctx)
    if lang == "javascript":
        return _recall_js(endpoint, ctx)
    return []