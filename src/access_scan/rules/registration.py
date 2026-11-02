"""注册可达（确定性 + LLM）：路由未挂载检测。

路由定义存在、但承载它的容器从未被挂载 → 应用根本不服务该路由，属确定性误报
（可自动关闭）；LLM 若坚持漏洞则不关闭（保留人工复核）。

覆盖：
- JavaScript：Express `Router`，需 `app.use('/x', router)` 才挂载。

局限（诚实声明）：根容器（app/application/server/main）视为已挂载；仅当扫描范围为
整个目录时判定（单文件扫描无法确认别处是否挂载，避免误关）；仅覆盖 javascript。
"""
import re
from typing import Iterable, Optional, Set, Tuple

_ROOT_CONTAINERS = {"app", "application", "server", "main"}
_MOUNT_RE = {
    "javascript": re.compile(r"\.use\s*\(\s*(?:['\"][^'\"]*['\"]\s*,\s*)?([\w$]+)"),
}
# 注释剥离：注释里提到挂载调用（如「// 未 app.use(router)」）不应算作真实挂载
_COMMENT_RE = {
    "javascript": re.compile(r"//[^\n]*|/\*.*?\*/", re.S),
}


def collect_mounts(texts: Iterable[Tuple[str, str]]) -> Set[str]:
    """全工程收集「挂载调用」引用的容器名（app.use）。

    先剥离注释，避免注释里提到挂载调用（如「// 未 app.use(router)」）被误判为真实挂载。
    """
    mounted: Set[str] = set()
    for lang, text in texts:
        rx = _MOUNT_RE.get(lang)
        if rx is None or not text:
            continue
        cref = _COMMENT_RE.get(lang)
        code = cref.sub(" ", text) if cref is not None else text
        for m in rx.finditer(code):
            mounted.add(m.group(1).split(".")[-1])
    return mounted


def unmounted_reason(language: str, container: Optional[str], mounted: Set[str],
                     whole_project: bool) -> Optional[str]:
    """容器未见挂载 → 返回原因文本；无法判定情形（非全量扫描 / 根容器 / 已挂载 / 语言不覆盖）→ None。"""
    if not whole_project or not container or language not in _MOUNT_RE:
        return None
    if container in _ROOT_CONTAINERS or container in mounted:
        return None
    return f"路由容器 '{container}' 未见挂载调用（app.use）"
