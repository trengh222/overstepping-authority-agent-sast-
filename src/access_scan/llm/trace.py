"""LLM 引用锚点的机器回验（可追溯性闸门）。

LLM 的 evidence_lines / reasoning 里给出「文件:行」引用，本模块把这些引用
**落回真实源码**核验：

- 文件能在项目内解析（精确路径 → 相对 root → 按文件名索引）；
- 行号在文件范围内；
- 被引用的行（含上下文 ±2 行）命中声明的 token（handler 名 / sink 调用 / 实体名）；
- 是否有引用覆盖 sink 行（`sink_snippet` 的「文件:行」前缀）。

回验结果写进 `Finding.evidence["citation_check"]`，`verdict.py` 据此：
- 引用全部核验失败 → 置信度封顶 + 标注待人工确认（不据"文本声称"给结论）；
- 升级 CONFIRMED 要求「至少一条引用通过 + sink 行被覆盖」。

只做静态文本/行号核对，不执行任何代码；找不到文件时记为 broken 而不是崩溃。
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_CITATION_RE = re.compile(r"([A-Za-z0-9_./\\-]+\.java):(\d+)(?:\s*[-~]\s*(\d+))?")
_SINK_RE = re.compile(r"^(.+?\.java):(\d+):")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
_MAX_INDEX_FILES = 40000

_GENERIC = {
    "return", "public", "private", "static", "void", "string", "boolean", "object",
    "class", "import", "package", "this", "true", "false", "null", "none", "self",
    "select", "insert", "update", "delete", "where", "values", "from", "join",
    "order", "group", "limit", "offset", "into", "set", "table", "service",
    "controller", "repository", "mapper", "handler", "request", "response",
}

_INDEX: Dict[str, Dict[str, Path]] = {}


@dataclass
class Citation:
    path: str
    line_start: int
    line_end: int

    def __str__(self) -> str:
        if self.line_end != self.line_start:
            return f"{self.path}:{self.line_start}-{self.line_end}"
        return f"{self.path}:{self.line_start}"


def _norm(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def _base(name: str) -> str:
    return _norm(name).split("/")[-1]


def parse_citations(texts: Iterable[str]) -> List[Citation]:
    """从若干文本里抽取「文件:行[-行]」引用（去重、保持出现顺序）。"""
    out: List[Citation] = []
    seen = set()
    for text in texts or []:
        for m in _CITATION_RE.finditer(text or ""):
            lo = int(m.group(2))
            hi = int(m.group(3) or lo)
            if lo <= 0 or hi < lo:
                continue
            key = (_norm(m.group(1)), lo, hi)
            if key in seen:
                continue
            seen.add(key)
            out.append(Citation(m.group(1), lo, hi))
    return out


def sink_location(candidate: Any) -> Optional[Tuple[str, int]]:
    """sink 的（文件, 行号）：优先取 sink_snippet 前缀「文件:行: 代码」。"""
    acc = getattr(candidate, "access", None)
    if acc is None:
        return None
    m = _SINK_RE.search((getattr(acc, "sink_snippet", "") or "").replace("\\", "/"))
    if m:
        return m.group(1), int(m.group(2))
    line = int(getattr(acc, "sink_line", 0) or 0)
    if line:
        ep = getattr(candidate, "endpoint", None)
        return (getattr(ep, "file", "") or ""), line
    return None


def _file_index(root: Path) -> Dict[str, Path]:
    key = str(root.resolve())
    idx = _INDEX.get(key)
    if idx is None:
        idx = {}
        try:
            for p in root.rglob("*.java"):
                idx.setdefault(p.name, p)
                if len(idx) >= _MAX_INDEX_FILES:
                    break
        except OSError:
            pass
        _INDEX[key] = idx
    return idx


def resolve_path(citation: Citation, root: Optional[Path]) -> Optional[Path]:
    """把引用路径解析成真实文件：绝对路径 → root 相对 → 文件名索引。"""
    raw = Path(citation.path)
    if raw.is_absolute() and raw.exists():
        return raw
    if root is not None:
        direct = root / _norm(citation.path)
        if direct.exists():
            return direct
        idx = _file_index(root)
        return idx.get(_base(citation.path))
    return None


def _tokens(candidate: Any) -> set:
    """核验用 token：handler 名 / sink 代码标识符 / 实体名（小写）。"""
    out = set()
    ep = getattr(candidate, "endpoint", None)
    handler = getattr(ep, "handler", "") or ""
    tail = handler.split(".")[-1].split("(")[0]
    if len(tail) >= 4:
        out.add(tail.lower())
    acc = getattr(candidate, "access", None)
    snippet = getattr(acc, "sink_snippet", "") or ""
    code = snippet.split(": ", 1)[1] if ": " in snippet else snippet
    for t in _WORD_RE.findall(code):
        low = t.lower()
        if low not in _GENERIC:
            out.add(low)
    entity = (getattr(acc, "entity", "") or "").lower()
    if len(entity) >= 3:
        out.add(entity)
    return out


def verify_citations(candidate: Any, texts: Sequence[str],
                     root: Optional[Path] = None) -> Dict[str, Any]:
    """回验 LLM 引用；返回 {total, verified, broken[], sink, sink_covered, ok}。

    broken 每条给出原因（file_not_found / line_out_of_range / line_mismatch），
    报告层可直接渲染「模型引用了什么、为什么对不上」。
    """
    cits = parse_citations(texts)
    sink = sink_location(candidate)
    tokens = _tokens(candidate)
    res: Dict[str, Any] = {
        "total": len(cits),
        "verified": 0,
        "broken": [],
        "sink": {"file": sink[0], "line": sink[1]} if sink else None,
        "sink_covered": False,
        "ok": False,
    }
    if not cits:
        return res
    sink_base = _base(sink[0]) if sink else ""
    for c in cits:
        p = resolve_path(c, root)
        if p is None:
            res["broken"].append({"citation": str(c), "reason": "file_not_found"})
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            res["broken"].append({"citation": str(c), "reason": "unreadable"})
            continue
        if not lines or c.line_start > len(lines) or c.line_end > len(lines):
            res["broken"].append({"citation": str(c), "reason": "line_out_of_range",
                                  "file_lines": len(lines)})
            continue
        seg = "\n".join(lines[max(0, c.line_start - 3):c.line_end + 2]).lower()
        if tokens and not any(t in seg for t in tokens):
            res["broken"].append({"citation": str(c), "reason": "line_mismatch",
                                  "hint": lines[c.line_start - 1].strip()[:120]})
            continue
        res["verified"] += 1
        if sink and _base(p.name) == sink_base and c.line_start <= sink[1] <= c.line_end:
            res["sink_covered"] = True
    res["ok"] = res["verified"] > 0
    return res
