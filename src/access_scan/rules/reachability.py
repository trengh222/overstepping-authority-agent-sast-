"""可达性剪枝（方向三，配置开关范围）。

识别 handler 方法体内的配置/feature/env 开关读取，输出三态：
- reachable：无配置开关依赖，或声明为 enabled；
- unreachable：配置开关声明为 disabled（降级不删除）；
- needs_config：依赖配置开关但未声明值（提示补充 feature_flags.yaml）。

局限（诚实声明）：本层只识别「handler 读取了配置开关」，不判定该开关是否
真的关闭了路由注册（后者需要路由包裹的 CFG 分析，属独立二期）。
"""
import re
from typing import Any, Dict, List

# 配置/feature/env 开关读取表达式（多语言）
_CONFIG_READ_RE = re.compile(
    r"(?:config|settings|feature|flag|process\.env|os\.environ|os\.getenv|"
    r"getProperty|getenv|ConditionalOnProperty|@Value|env\s*\()",
    re.I)
# 开关名字面量：'export.enabled' / "debug.enabled"
_FLAG_LITERAL_RE = re.compile(r"['\"`]([\w.\-]+)['\"`]")
# 占位符：${export.enabled}
_FLAG_PLACEHOLDER_RE = re.compile(r"\$\{([\w.\-]+)\}")
# 属性访问：config.exportEnabled / settings.EXPORT_ENABLED / process.env.EXPORT_ENABLED
_FLAG_ATTR_RE = re.compile(
    r"(?:config|settings|cfg|feature|flag|process\.env)\s*[.\[]\s*([A-Za-z_][\w]*)",
    re.I)


def _node_text(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def extract_flag_names(handler_src: str) -> List[str]:
    """从 handler 源码提取配置开关名（尽力而为，含去重）。"""
    names: List[str] = []
    for line in handler_src.splitlines():
        if not _CONFIG_READ_RE.search(line):
            continue
        names.extend(_FLAG_LITERAL_RE.findall(line))
        names.extend(_FLAG_PLACEHOLDER_RE.findall(line))
        names.extend(m.group(1) for m in _FLAG_ATTR_RE.finditer(line))
    return list(dict.fromkeys(names))


def _norm(s: str) -> str:
    return s.lower().replace("_", ".").replace("-", ".")


def collect_flag_refs(handler_node: Any, flags: Dict[str, bool] = None,
                      repo_flags: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """收集 handler 内配置开关引用及声明值（不判定，交 LLM 判定可达性）。

    声明值来源优先级：config/feature_flags.yaml（人工声明）> 仓库配置键
    （application.* / .env）> 缺失。仓库键存在但值动态/冲突时为 None（只降级）。

    返回 [{name, declared}]：declared 为 True/False/None。
    """
    flags = flags or {}
    names = extract_flag_names(_node_text(handler_node))
    norm_flags = {_norm(k): v for k, v in flags.items()}
    norm_repo = {_norm(k): v for k, v in (repo_flags or {}).items()}
    refs: List[Dict[str, Any]] = []
    seen = set()
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        key = _norm(n)
        if key in norm_flags:
            declared: Any = bool(norm_flags[key])
        elif key in norm_repo:
            declared = norm_repo[key]  # True / False / None（动态或冲突）
        else:
            declared = None
        refs.append({"name": n, "declared": declared})
    return refs
