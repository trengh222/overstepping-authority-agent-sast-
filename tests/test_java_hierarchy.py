"""Java 继承链事实与跨过程解析测试。

运行：python -m pytest tests/test_java_hierarchy.py -q

覆盖：
- 继承事实提取：class extends / implements、interface extends、enum/record implements；
- 接口 → 实现类（跨两级继承）：字段类型是顶层接口时仍能进入实现类方法体；
- 子类未覆写 → 父类方法体；
- 无继承事实时全部退回原行为（失败方向安全）。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.hierarchy import Hierarchy
from access_scan.dataflow.taint import _resolve_java_target
from access_scan.extractor.java import JavaExtractor

_FIX = _REPO / "tests" / "fixtures_hierarchy"


# ---------------- 继承事实提取 ----------------

_HIER_SRC = b"""
package x;
interface Base {}
interface Mid extends Base, Other {}
class Impl extends Abs implements Mid {}
enum E implements Mid {}
record R(String s) implements Mid {}
class Plain {}
"""


def _hierarchy_of(src: bytes) -> Hierarchy:
    ext = JavaExtractor()
    return Hierarchy(ext.extract_hierarchy(ext.parse(src), "x/T.java"))


def test_extract_extends_and_implements():
    h = _hierarchy_of(_HIER_SRC)
    assert h.parents["Mid"] == ["Base", "Other"], "interface extends 多父类型"
    assert h.parents["Impl"] == ["Abs", "Mid"], "class extends + implements"
    assert h.parents["E"] == ["Mid"] and h.parents["R"] == ["Mid"], "enum/record implements 同样计入"
    assert h.parents["Plain"] == []


def test_ancestors_and_descendants_are_transitive():
    h = _hierarchy_of(_HIER_SRC)
    assert h.ancestors_of("Impl") == ["Abs", "Mid", "Base", "Other"]
    assert set(h.descendants_of("Mid")) == {"Impl", "E", "R"}
    assert set(h.related_types("Mid")) == {"Base", "Other", "Impl", "E", "R"}


def test_hierarchy_walk_is_cycle_safe():
    h = Hierarchy({"A": ["B"], "B": ["A"]})
    assert h.ancestors_of("A") == ["B"]
    assert h.descendants_of("A") == ["B"]


# ---------------- 跨过程解析 ----------------

def test_resolve_without_hierarchy_keeps_old_behaviour():
    index = {"AssetStoreImpl.getById": "<ctx>"}
    assert _resolve_java_target(index, "BaseStore", "getById") == (None, None)
    assert _resolve_java_target(index, "BaseStore", "getById", None) == (None, None)


def test_resolve_with_hierarchy_finds_impl():
    index = {"AssetStoreImpl.getById": "<ctx>"}
    h = Hierarchy({"AssetStore": ["BaseStore"], "AssetStoreImpl": ["AssetStore"]})
    assert _resolve_java_target(index, "BaseStore", "getById", h)[0] == "AssetStoreImpl.getById"
    assert _resolve_java_target(index, "AssetStoreImpl", "getById", h)[0] == "AssetStoreImpl.getById"


def test_resolve_ancestor_method_body():
    index = {"BaseAssetHandler.load": "<ctx>"}
    h = Hierarchy({"ChildAssetHandler": ["BaseAssetHandler"]})
    assert _resolve_java_target(index, "ChildAssetHandler", "load", h)[0] == "BaseAssetHandler.load"


# ---------------- 端到端 ----------------

def _cands():
    kept, gw = cli.scan(_FIX)
    return kept + gw


def _by_path(path):
    return [c for c in _cands() if c.endpoint.path == path]


def _slice_labels(c):
    return [s.get("call") for s in (c.access.chain_slices or [])]


def test_interface_call_reaches_impl_body():
    cands = _by_path("/api/assets/{assetId}")
    assert cands, "字段类型是顶层接口时，应沿继承链进入实现类"
    labels = _slice_labels(cands[0])
    assert "AssetStoreImpl.getById" in labels, f"实际切片: {labels}"
    assert cands[0].access.entity == "Asset", cands[0].access.entity


def test_inherited_method_body():
    cands = _by_path("/api/legacy/{assetId}")
    assert cands, "子类未覆写时，应进入父类方法体"
    labels = _slice_labels(cands[0])
    assert "BaseAssetHandler.load" in labels, f"实际切片: {labels}"
