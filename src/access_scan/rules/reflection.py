"""反射 / 动态分派点识别（M7）。

静态分析对反射不可见：`Class.forName` + `getDeclaredMethod().invoke(...)`、
`BeanUtils.copyProperties`、`JSON.parseObject`、`getBean` 会切断调用图与字段级
数据流。方案风险表口径是「动态分派/反射 → 降级，不为此判无校验」：
识别到这些点时不把它当成"缺少鉴权"的证据，只降置信度并转人工。

识别粒度：handler 方法体内的调用点（Java 用 `call_full_text` 的 `接收者.方法`，
其他语言用调用原文做宽松匹配）；每处记 {kind, name, line, snippet}。
"""
import re
from typing import Any, Dict, List, Optional

from ..dataflow import asts

# Java：call_full_text 形如 "BeanUtils.copyProperties" / "method.invoke" / "JSONObject.parseObject"
_SITE_SPECS = [
    ("classloader", re.compile(r"(?:^|\.)Class\.forName$|\.loadClass$|^ClassLoader\b", re.I)),
    ("reflective-field", re.compile(r"\.get(?:Declared)?Fields?$", re.I)),
    ("reflective-method", re.compile(
        r"\.get(?:Declared)?Methods?$|\.get(?:Declared)?Constructor$|\.getParameterTypes$", re.I)),
    ("method-invoke", re.compile(r"\.invoke$|\.newInstance$", re.I)),
    ("accessible-bypass", re.compile(r"\.setAccessible$", re.I)),
    ("dynamic-proxy", re.compile(
        r"^Proxy\.newProxyInstance$|^MethodHandles?\b|^MethodHandle\b", re.I)),
    ("bean-copy", re.compile(
        r"^(?:BeanUtils|CopyTools|PropertyUtils|BeanCopier)\.copyProperties$", re.I)),
    ("deserialize", re.compile(
        r"\.(?:parseObject|parseArray|readValue|readTree|fromJson|unmarshal|deserialize)$", re.I)),
    ("container-lookup", re.compile(r"\.getBean$", re.I)),
]

# 非 Java：对调用原文做宽松匹配（call_full_text 在 Go 等语言里含实参）
_LOOSE_SPECS = [
    ("dynamic-access", re.compile(
        r"getattr\s*\(|globals\s*\(\s*\)\s*\[|importlib\.import_module|__import__\s*\(", re.I)),
    ("dynamic-access", re.compile(
        r"Reflect\.\w+|\[['\"](?:admin|role)['\"]\]|\bapply\s*\(", re.I)),
    ("bean-copy", re.compile(r"copyProperties|StructScan|mapstructure\.Decode", re.I)),
    ("deserialize", re.compile(
        r"parseObject|parseArray|readValue|json_decode|json\.Unmarshal|Unmarshal\(", re.I)),
]


def _txt(node: Any) -> str:
    t = node.text if node is not None else b""
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _match(kind_text: str, loose_text: str, lang: str) -> Optional[str]:
    if lang == "java":
        for kind, rx in _SITE_SPECS:
            if rx.search(kind_text or ""):
                return kind
        return None
    for kind, rx in _LOOSE_SPECS:
        if rx.search(loose_text or ""):
            return kind
    return None


def reflection_sites(node: Any, lang: str = "java", limit: int = 20) -> List[Dict[str, Any]]:
    """handler 方法体内的反射/动态分派点清单（按行号去重，最多 limit 条）。"""
    out: List[Dict[str, Any]] = []
    seen = set()
    try:
        calls = list(asts.iter_calls(node, lang))
    except asts.AstShapeError:
        return []
    for call in calls:
        try:
            full = asts.call_full_text(call)
        except asts.AstShapeError:
            full = ""
        raw = _txt(call)
        kind = _match(full, raw, lang)
        if not kind:
            continue
        line = call.start_point[0] + 1
        key = (kind, line)
        if key in seen:
            continue
        seen.add(key)
        snippet = (raw.strip().splitlines() or [""])[0][:160]
        out.append({"kind": kind, "name": full or snippet[:60], "line": line,
                    "snippet": snippet})
        if len(out) >= limit:
            break
    return out


def reflection_hint(sites: List[Dict[str, Any]]) -> str:
    """把识别结果压成一句可达性提示（写进 reachability_hints / 报告）。"""
    if not sites:
        return ""
    desc = "、".join(f"{s['kind']}@{s['line']}" for s in sites[:6])
    return (f"调用链存在反射/动态分派点 {len(sites)} 处（{desc}）：静态不可判定，"
            f"不得据此判定「无校验」，降级转人工复核")


def has_reflection_text(text: str, lang: str = "java") -> bool:
    """源码片段里是否出现反射/动态分派调用（taint 链路标 dynamic 用）。"""
    if not text:
        return False
    if lang == "java":
        return any(rx.search(text) for _, rx in _SITE_SPECS if not rx.pattern.endswith("$")) \
            or bool(re.search(
                r"Class\.forName|\.getDeclared(?:Field|Method|Constructor)s?\b|"
                r"\.setAccessible\s*\(|\.invoke\s*\(|BeanUtils\.copyProperties|"
                r"parseObject\s*\(", text))
    return any(rx.search(text) for _, rx in _LOOSE_SPECS)
