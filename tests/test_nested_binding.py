"""父子绑定（嵌套资源）判定：显式字段绑定与联合条件仓储方法。"""
from pathlib import Path

from access_scan.cli import scan

FIXTURES = Path(__file__).parent / "fixtures" / "java" / "nested_bind"


def _candidates(case: str):
    kept, gateway = scan(FIXTURES / case)
    return list(kept) + list(gateway)


def _a1_params(case: str):
    return {(c.access.identifier_param or "").lower()
            for c in _candidates(case) if c.subtype == "A1"}


def test_safe_field_binding_suppresses_child_param():
    """`c.getVideoId().equals(id)` 且 id 已归属校验 → cid 不再报 A1。"""
    assert _a1_params("safe_field") == set()


def test_safe_repo_conjunction_suppresses_child_param():
    """`deleteByIdAndVideoId(cid, id)` 且 id 已归属校验 → cid 不再报 A1。"""
    assert _a1_params("safe_repo") == set()


def test_unsafe_child_param_still_reported():
    """只校验视频归属、评论未绑定 → cid 仍应报 A1。"""
    assert "cid" in _a1_params("unsafe")


def test_unsafe_repo_without_owner_still_reported():
    """父子 id 都由客户端控制、无归属校验 → 仍应报 A1。"""
    assert _a1_params("unsafe_repo")
