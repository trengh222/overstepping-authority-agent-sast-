"""仓库配置键解析（Spring application.* / .env）：为配置可达提供静态声明证据。

只解析仓库内常见的声明式配置（application.yml/yaml、application-*.yml、
application.properties、.env/.env.*），把嵌套键展平为点号键并归一化（小写、
`_`/`-` 转 `.`）。值只接受可静态确定的布尔写法（true/false/1/0）。

安全语义：
- 键在仓库中缺失 → 不产出声明（declared=None，交 LLM 判定 needs_config，只降级）；
- 键存在但值动态（`${...}` / `@...@`）或多 profile 冲突 → declared=None（同样只降级）；
- 只有明确声明的 false 才允许走「配置关闭」降级分支。
"""
import re
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore
except ImportError:  # 无 PyYAML → 只解析 properties/.env
    yaml = None

_CONFIG_NAMES = re.compile(
    r"^(?:application(?:-[^.]+)?\.(?:ya?ml|properties)|\.env(?:\.[^.]+)?|"
    r"[^.]+\.env)$", re.I)
_DYNAMIC_VALUE_RE = re.compile(r"\$\{.*\}|@[^@]+@")
_PROP_RE = re.compile(r"^\s*([\w.\-]+)\s*[:=]\s*(.*?)\s*$")
_BOOL_TEXT = {
    "true": True, "false": False, "1": True, "0": False,
    "yes": True, "no": False, "on": True, "off": False,
}


def _norm_key(key: str) -> str:
    return str(key).strip().lower().replace("-", ".").replace("_", ".")


def _bool_value(raw: Any) -> Optional[bool]:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)) and raw in (0, 1):
        return bool(raw)
    if isinstance(raw, str):
        text = raw.strip().strip("'\"")
        if _DYNAMIC_VALUE_RE.search(text):
            return None
        return _BOOL_TEXT.get(text.lower())
    return None


def _flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(_flatten(v, key))
            else:
                out[_norm_key(key)] = v
    return out


def _parse_yaml(text: str) -> Dict[str, Any]:
    if yaml is None:
        return {}
    try:
        data = yaml.safe_load(text)
    except Exception:
        return {}
    return _flatten(data)


def _parse_properties(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        m = _PROP_RE.match(line)
        if m:
            out[_norm_key(m.group(1))] = m.group(2)
    return out


def collect_repo_flags(root: Path) -> Dict[str, Optional[bool]]:
    """扫描仓库配置键 → {归一化键: True/False/None}；冲突或动态值记 None。"""
    if not root.is_dir():
        return {}
    seen: Dict[str, Optional[bool]] = {}
    for p in root.rglob("*"):
        if not p.is_file() or not _CONFIG_NAMES.match(p.name):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        raw = _parse_yaml(text) if p.suffix.lower() in (".yml", ".yaml") else _parse_properties(text)
        for key, value in raw.items():
            if key in seen:
                if seen[key] != _bool_value(value):
                    seen[key] = None  # 多文件/多 profile 冲突 → 不确定
            else:
                seen[key] = _bool_value(value)
    return seen
