"""构建可达（流水线①确定性层）：构建排除 + 死代码。

判定候选的 sink 是否「根本不在编译/运行产物里」，是五类可达性中最强的一档
（确定性、可自动关闭）：

- **文件级构建排除**：Go 的 `//go:build ignore` / `// +build ignore` 使整个文件
  不参与编译 → 该文件内全部端点不可达；
- **死代码**：sink 语句位于同一代码块内「无条件终止符」（return/throw/raise/
  panic/exit）之后 → 该语句不可达。

局限（诚实声明）：本层只覆盖源码内可确定性判定的构建排除；语言层面无构建标记的
工程（Java/JS）不做文件级判定。数据流层已基于 CFG 剪枝，本层主要覆盖
「CFG 之外的构建排除」，并在 CFG 未剪枝时兜底。
"""
import re
from typing import Any, Optional

_TERMINATORS = {
    "java": ("return_statement", "throw_statement"),
    "javascript": ("return_statement", "throw_statement"),
    "go": ("return_statement",),
}
_BLOCKS = {
    "java": ("block",),
    "javascript": ("statement_block",),
    "go": ("block", "statement_list"),
}
# 无条件终止调用（panic/os.Exit/exit）；仅当语句本身即该调用时才算终止
_EXIT_CALL_RE = re.compile(r"^\s*(?:panic|os\.Exit|exit|abort)\s*\(")
# Go 构建排除标记（//go:build ignore 或旧式 // +build ignore）
_BUILD_IGNORE_RE = re.compile(r"^\s*//\s*(?:go:build|\+build)\b[^\n]*\bignore\b", re.M)


def _txt(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def file_build_excluded(src_text: str, language: str) -> bool:
    """整个文件是否被构建标记排除（当前仅 Go 的 //go:build ignore）。"""
    if language != "go" or not src_text:
        return False
    return bool(_BUILD_IGNORE_RE.search(src_text))


def _walk(node: Any):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.named_children)


def _innermost_block(handler_node: Any, sink_line: int, language: str):
    """包含 sink 行的最小代码块节点（块节点行区间为闭区间）。"""
    types = _BLOCKS.get(language, ())
    best = None
    for n in _walk(handler_node):
        if n.type not in types:
            continue
        lo, hi = n.start_point[0] + 1, n.end_point[0] + 1
        if lo <= sink_line <= hi and (
                best is None or (hi - lo) < (best.end_point[0] - best.start_point[0])):
            best = n
    return best


def dead_sink_reason(handler_node: Any, sink_line: int, language: str) -> Optional[str]:
    """sink 是否位于无条件终止符之后的死代码区；是 → 返回原因文本，否则 None。"""
    if handler_node is None or sink_line <= 0:
        return None
    block = _innermost_block(handler_node, sink_line, language)
    if block is None:
        return None
    terms = _TERMINATORS.get(language, ())
    for stmt in block.named_children:
        sline = stmt.start_point[0] + 1
        if sline >= sink_line:
            break
        if stmt.type in terms:
            return f"死代码：sink 前第 {sline} 行存在无条件 {stmt.type}，sink 不可达"
        if stmt.type == "expression_statement" and _EXIT_CALL_RE.match(_txt(stmt)):
            return f"死代码：sink 前第 {sline} 行存在无条件终止调用，sink 不可达"
    return None
