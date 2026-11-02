"""规则 B6：属性级越权 / 敏感字段暴露（BOPLA，属性级授权缺失）。

形态：handler 返回的对象（VO/实体/DTO）含敏感字段（config/ownership.yaml 的
`sensitive_fields` 声明），源码里没有任何脱敏证据（@JsonIgnore / 显式 mask），
客户端即可从响应里拿到他人敏感字段。

判定链路（纯静态、确定性字段事实）：
1. 收集 handler 的 return 表达式，剥掉统一响应包装（getSuccessResponseVO /
   ResponseEntity.ok / success 等）；
2. 解析返回值的声明类型：局部变量声明 → 类字段 → `new T()` 构造；
3. 用类字段索引（extractor.collect_class_fields 一次扫描建立）取该类型的字段事实；
4. 字段名命中敏感名单且未标注脱敏 → emit Candidate(subtype="B6")，证据带字段名。

不做的事：不区分「返回本人数据」还是「他人数据」（这需要归属分析，交给 A1/A3 +
LLM 复核）；因此 B6 只到 LIKELY，不升级 CONFIRMED。
"""
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..ir import Candidate, FieldFact, ResourceAccess

# 统一响应包装的调用名（取实参后再判类型）
_WRAPPER_CALLS = {
    "getsuccessresponsevo", "success", "ok", "of", "build", "wrap", "result",
    "data", "toresponse", "responseentity", "render", "rendersuccess",
}

# 公开认证流程：登录/注册/找回密码等本来就返回用户自身信息，不报 B6
_PUBLIC_AUTH_RE = re.compile(
    r"/(?:login|logoff|logout|signin|signup|register|regist|captcha|refresh|"
    r"reset|forget|password|token)\b", re.I)


def _txt(node: Any) -> str:
    t = node.text if node is not None else b""
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


@lru_cache(maxsize=16)
def _sensitive_re(patterns: Tuple[str, ...]) -> Optional["re.Pattern"]:
    """敏感字段名正则：名单片段去掉下划线后对「归一化字段名」做 search。"""
    parts: List[str] = []
    for p in patterns:
        p = (p or "").strip()
        if not p:
            continue
        p = p.replace("_?", "").replace("_", "")
        parts.append(f"(?:{p})")
    if not parts:
        return None
    return re.compile("|".join(parts), re.I)


def _is_sensitive(fact: FieldFact, rx, patterns: Sequence[str]) -> bool:
    if fact.protected:
        return False
    name = _norm(fact.name)
    if rx is not None and rx.search(name):
        return True
    # 兜底：名单片段以明文包含在字段名里（如 userIdCardNo 命中 idcard）
    return any(_norm(p) and _norm(p) in name for p in patterns)


def _arguments(call: Any) -> List[Any]:
    args = call.child_by_field_name("arguments")
    return list(args.named_children) if args is not None else []


def _callee_name(call: Any) -> str:
    name = call.child_by_field_name("name")
    return _norm(_txt(name))


def _unwrap(expr: Any) -> Any:
    """剥掉统一响应包装：getSuccessResponseVO(x) → x；非包装调用 → 原样返回 None 类型。"""
    seen = 0
    while expr is not None and expr.type == "method_invocation" and seen < 4:
        name = _callee_name(expr)
        if name not in _WRAPPER_CALLS:
            return expr
        args = _arguments(expr)
        if not args:
            return expr
        expr = args[0] if name != "of" else args[-1]
        seen += 1
    return expr


def _strip_generics(type_text: str) -> str:
    return re.sub(r"<.*>", "", type_text or "").strip().split(".")[-1]


def _local_types(method_node: Any) -> Dict[str, str]:
    """handler 内局部变量声明：{变量名: 简单类型名}。"""
    out: Dict[str, str] = {}
    stack = [method_node]
    while stack:
        node = stack.pop()
        if node.type == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            tname = _strip_generics(_txt(type_node))
            for decl in node.named_children:
                if decl.type != "variable_declarator":
                    continue
                name_node = decl.child_by_field_name("name")
                if name_node is not None and tname:
                    out[_txt(name_node).strip()] = tname
        stack.extend(node.named_children)
    return out


def _type_of(expr: Any, local_types: Dict[str, str], ctx: Any) -> Optional[str]:
    """返回表达式的声明类型（简单名）；无法确定返回 None。"""
    if expr is None:
        return None
    t = expr.type
    if t == "identifier":
        name = _txt(expr).strip()
        return local_types.get(name) or (getattr(ctx, "fields", {}) or {}).get(name)
    if t == "object_creation_expression":
        type_node = expr.child_by_field_name("type")
        return _strip_generics(_txt(type_node)) or None
    if t == "cast_expression":
        return _strip_generics(_txt(expr.child_by_field_name("type"))) or None
    if t == "field_access":
        name = _txt(expr).strip().split(".")[-1]
        return (getattr(ctx, "fields", {}) or {}).get(name)
    return None


def _return_values(method_node: Any) -> List[Tuple[Any, int]]:
    out: List[Tuple[Any, int]] = []
    stack = [method_node]
    while stack:
        node = stack.pop()
        if node.type == "return_statement" and node.named_children:
            out.append((node.named_children[0], node.start_point[0] + 1))
        stack.extend(node.named_children)
    return out


def recall_exposure(endpoint, ctx, class_index: Dict[str, List[FieldFact]],
                    patterns: Sequence[str]) -> List[Candidate]:
    """规则 B6：返回对象暴露敏感字段（属性级越权）。无命中返回 []。"""
    if not class_index or not patterns:
        return []
    if _PUBLIC_AUTH_RE.search(endpoint.path or "") or _PUBLIC_AUTH_RE.search(endpoint.handler or ""):
        return []
    rx = _sensitive_re(tuple(patterns))
    local_types = _local_types(ctx.node)
    hits: Dict[str, List[str]] = {}       # 类型 -> 敏感字段名（去重保序）
    lines: Dict[str, int] = {}            # 类型 -> 首次出现行号
    for expr, line in _return_values(ctx.node):
        value = _unwrap(expr)
        tname = _type_of(value, local_types, ctx)
        if not tname:
            continue
        facts = class_index.get(tname) or []
        if not facts:
            continue
        names = [f.name for f in facts if _is_sensitive(f, rx, patterns)]
        if not names:
            continue
        bucket = hits.setdefault(tname, [])
        for n in names:
            if n not in bucket:
                bucket.append(n)
        lines.setdefault(tname, line)
    if not hits:
        return []

    types = sorted(hits)
    names: List[str] = []
    for t in types:
        for n in hits[t]:
            if n not in names:
                names.append(n)
    line = min(lines.values())
    text = ""
    if getattr(ctx, "lines", None) and 0 < line <= len(ctx.lines):
        text = ctx.lines[line - 1].strip()
    entity = "/".join(types)
    access = ResourceAccess(
        entity=entity,
        identifier_param="",
        flow=[f"return {entity} 含敏感字段 {', '.join(names)}（未脱敏，字段级授权缺失）"],
        ownership_predicate=False,
        sink_snippet=f"{ctx.file}:{line}: {text}",
        sink_line=line,
    )
    access.sensitive_fields = list(names)
    return [Candidate(endpoint=endpoint, access=access, subtype="B6",
                      rule_id="B6-field-exposure")]
