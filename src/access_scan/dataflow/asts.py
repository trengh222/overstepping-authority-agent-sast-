"""跨语言 AST 小工具：调用节点遍历、调用名/参数提取、写操作前缀。

设计约定：
- 调用节点的字段名逐语言不同（见 `_CALL_SPEC`），集中声明，不再用 `or` 串联兜底；
- 必需字段缺失时抛 `AstShapeError`（grammar 升级/换版本 → 显式失败，不静默返回 ""）；
- 未知语言不静默退化为全语言集合：先做别名归一，仍未知则告警一次。
"""
import re
import warnings
from typing import Any, Dict, Iterator, List, Optional

# 各语言「调用」节点类型（Java/JS 把对象构造也算作调用：new FileInputStream(path)）
_CALL_TYPES = {
    "java": ("method_invocation", "object_creation_expression"),
    "javascript": ("call_expression", "new_expression"),
    "typescript": ("call_expression", "new_expression"),
    "go": ("call_expression",),
}
_ALL_CALL_TYPES = tuple(sorted({t for ts in _CALL_TYPES.values() for t in ts}))

# 调用节点 → 字段声明。callee=被调者字段；args=实参字段；receiver=接收者字段
# （method_invocation 的 object 是独立子节点，node.text 不含它）。
_CALL_SPEC: Dict[str, Dict[str, str]] = {
    "method_invocation": {"callee": "name", "args": "arguments", "receiver": "object", "sep": "."},
    "object_creation_expression": {"callee": "type", "args": "arguments"},
    "call_expression": {"callee": "function", "args": "arguments"},
    "new_expression": {"callee": "constructor", "args": "arguments"},
}

# 语言别名：js/ts 等简写与大小写/点号写法先归一，避免落进「未知语言」分支
_LANG_ALIASES = {
    "js": "javascript", "jsx": "javascript", "mjs": "javascript",
    "ts": "typescript", "tsx": "typescript",
    "golang": "go",
}
_WARNED_LANGS: set = set()

# 字符串字面量节点类型（SQL 文本/字段名提取用）；JS 模板串曾漏采
_LITERAL_TYPES = (
    "string_literal", "string", "raw_string_literal", "interpreted_string_literal",
    "template_string",
)

# 动态被调者节点（obj[key](x) / foo[bar](x)）：名字运行期才确定，静态阶段返回 None
_DYNAMIC_CALLEE_TYPES = (
    "subscript_expression", "element", "subscript", "dynamic_member_expression",
)

# 递归深度上限：AST 异常深（超长 JS 链/生成代码）时避免 RecursionError 打崩扫描
_MAX_DEPTH = 500

# Unicode 友好的标识符末段：getUserInfo / 查询用户 → 查询用户
_IDENT_RE = re.compile(r"([^\W\d]\w*)$", re.UNICODE)


class AstShapeError(RuntimeError):
    """AST 形状与预期 grammar 不符（通常是 tree-sitter grammar 升级/换版本）。"""


def _text(node: Any) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _root(node: Any) -> Any:
    """允许直接传 tree_sitter.Tree（ext.parse 的返回值），统一取 root_node。"""
    if node is None or hasattr(node, "type"):
        return node
    return getattr(node, "root_node", None)


def _normalize_language(language: Optional[str]) -> Optional[str]:
    if not language:
        return None
    lang = str(language).strip().lower().lstrip(".")
    return _LANG_ALIASES.get(lang, lang)


def _ident(text: str) -> str:
    """文本最后一个标识符：orderService.findById → findById；ArrayList<String> → ArrayList。"""
    m = _IDENT_RE.search(re.sub(r"<[^<>]*>", "", text.strip()))
    return m.group(1) if m else ""


def _callee(node: Any) -> Any:
    """被调者节点。字段名由 _CALL_SPEC 声明；缺失即抛错（grammar 漂移不再静默）。"""
    spec = _CALL_SPEC.get(node.type)
    if spec is not None:
        ch = node.child_by_field_name(spec["callee"])
        if ch is None:
            raise AstShapeError(
                f"{node.type} 缺少必需字段 {spec['callee']!r}"
                f"（tree-sitter grammar 可能已升级）；源码片段：{_text(node)[:120]!r}"
            )
        return ch
    # 未登记的节点类型：按常见字段名探测，探测不到返回 None（不抛错，避免误伤新语法）
    for f in ("function", "name", "constructor", "type"):
        ch = node.child_by_field_name(f)
        if ch is not None:
            return ch
    return None


def iter_calls(node: Any, language: Optional[str] = None, _depth: int = 0):
    if _depth > _MAX_DEPTH:
        return
    node = _root(node)
    if node is None:
        return
    lang = _normalize_language(language)
    kinds = _CALL_TYPES.get(lang) if lang else _ALL_CALL_TYPES
    if kinds is None:
        if lang not in _WARNED_LANGS:
            _WARNED_LANGS.add(lang)
            warnings.warn(
                f"asts.iter_calls: 未知语言 {lang!r}，退化为全语言调用类型集合"
                f"（结果可能偏离预期，请检查语言名/注册表）",
                RuntimeWarning, stacklevel=2,
            )
        kinds = _ALL_CALL_TYPES
    if node.type in kinds:
        yield node
    for ch in node.named_children:
        yield from iter_calls(ch, language, _depth + 1)


def call_name(node: Any) -> Optional[str]:
    """调用目标的最后一段名：User.query.filter_by → filter_by；Order::find → find。"""
    callee = _callee(node)
    if callee is None:
        return None
    if callee.type in _DYNAMIC_CALLEE_TYPES:
        return None  # obj[key](x) / foo[bar](x)：动态调用，静态阶段无名字
    if callee.type == "parenthesized_expression":
        inner = callee.named_children[0] if callee.named_children else None
        if inner is None or inner.type in _DYNAMIC_CALLEE_TYPES:
            return None
        if inner.type in _ALL_CALL_TYPES:
            return None  # (getFn())(x)：被调者是表达式结果，不是具名函数
        callee = inner
    return _ident(_text(callee)) or None


def call_full_text(node: Any) -> str:
    """调用目标全链文本（orderService.findById / prisma.order.findUnique）。"""
    spec = _CALL_SPEC.get(node.type)
    if spec is None:
        callee = _callee(node)
        return _text(callee).strip() if callee is not None else ""
    callee_text = _text(_callee(node)).strip()
    receiver = node.child_by_field_name(spec["receiver"]) if "receiver" in spec else None
    if receiver is not None:
        return f"{_text(receiver).strip()}{spec['sep']}{callee_text}"
    return callee_text


def call_arg_texts(node: Any) -> str:
    spec = _CALL_SPEC.get(node.type) or {}
    args = node.child_by_field_name(spec.get("args", "arguments"))
    if args is None:
        return ""
    return " ".join(_text(a) for a in args.named_children)


def walk_literals(node: Any, _depth: int = 0) -> Iterator[Any]:
    if _depth > _MAX_DEPTH:
        return
    node = _root(node)
    if node is None:
        return
    if node.type in _LITERAL_TYPES:
        yield node
    for ch in node.named_children:
        yield from walk_literals(ch, _depth + 1)


# 写操作调用前缀（各语言共用，特权操作判定）
WRITE_OP_PREFIXES = (
    "save", "insert", "upsert", "update", "delete", "remove", "write", "export",
    "approve", "reject", "refund", "transfer", "reset", "grant", "upload", "publish",
)
