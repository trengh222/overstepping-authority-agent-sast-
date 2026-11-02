"""Java 类型继承链事实：双向邻接表（父类型 / 子类型）。

`extends` / `implements` / 接口 `extends` 都记为父边（跨过程解析只关心「是不是一家人」，
不区分继承与实现）。类名用源码简单名，与 method_index 的 key（`ClassName.method`）保持一致。

用途（见 taint._resolve_java_target）：
- 子类实现：调用点接收者是接口/抽象父类型时，向下找到真正实现该方法的子类；
- 继承方法体：子类没覆写时，向上找到父类里的方法体。

children 反向表按需构建一次并缓存，避免每次调用点重复扫描全表。
"""
from typing import Dict, Iterable, List, Optional

_MAX_NODES = 64  # 单次遍历上限，防深继承/环导致爆炸


class Hierarchy:
    """`{类型名: [直接父类型名]}` + 惰性构建的反向表。"""

    __slots__ = ("parents", "_children")

    def __init__(self, parents: Optional[Dict[str, Iterable[str]]] = None):
        self.parents: Dict[str, List[str]] = {}
        self._children: Optional[Dict[str, List[str]]] = None
        if parents:
            self.merge(parents)

    # ---- 构建 ----
    def merge(self, facts: Dict[str, Iterable[str]]) -> "Hierarchy":
        """并入单个文件的继承关系（同名类型取并集，保持确定顺序）。"""
        for name, parents in facts.items():
            bucket = self.parents.setdefault(name, [])
            for p in parents:
                if p and p not in bucket:
                    bucket.append(p)
        self._children = None
        return self

    def children_map(self) -> Dict[str, List[str]]:
        if self._children is None:
            ch: Dict[str, List[str]] = {}
            for child, parents in self.parents.items():
                for p in parents:
                    ch.setdefault(p, []).append(child)
            self._children = ch
        return self._children

    def __bool__(self) -> bool:
        return bool(self.parents)

    def __contains__(self, name: str) -> bool:
        return name in self.parents

    # ---- 查询 ----
    def ancestors_of(self, name: str) -> List[str]:
        """传递闭包：父类/接口链（不含自身，环安全）。"""
        return _walk(self.parents, name)

    def descendants_of(self, name: str) -> List[str]:
        """反向传递闭包：所有直接/间接收敛到 name 的子类型（不含自身，环安全）。"""
        return _walk(self.children_map(), name)

    def related_types(self, name: str) -> List[str]:
        return self.ancestors_of(name) + self.descendants_of(name)


def merge_into(hierarchy: Hierarchy, facts: Dict[str, Iterable[str]]) -> Hierarchy:
    """把单个文件的继承关系并入全局表（同 Hierarchy.merge，供 cli 调用）。"""
    return hierarchy.merge(facts)


def _walk(edges: Dict[str, List[str]], name: str) -> List[str]:
    out: List[str] = []
    seen = {name}
    queue = list(edges.get(name, []))
    while queue and len(out) < _MAX_NODES:
        cur = queue.pop(0)
        if not cur or cur in seen:
            continue
        seen.add(cur)
        out.append(cur)
        queue.extend(edges.get(cur, []))
    return out
