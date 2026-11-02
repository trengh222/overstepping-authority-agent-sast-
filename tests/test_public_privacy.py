"""公开资源隐私模型（所有权模型）验证。

运行：python -m pytest tests/test_public_privacy.py -q

覆盖：
- 未声明的 POJO → 隐私 UNKNOWN → A1 一律保留（失败方向安全：证据不全不关闭）；
- 声明 PUBLIC → 只豁免「读」访问，写/删仍报 A1；
- 声明 PRIVATE → 全部保留；
- 不带 @Entity 的 POJO，只要所有权模型显式声明即可纳入隐私判定。
"""
import shutil
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.extractor.java import JavaExtractor
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint,
                            ParamSource, Resource, ResourceAccess)
from access_scan.rules.filter import apply_filters

_FIX = _REPO / "tests" / "fixtures_privacy"

_READ_PATH = "/api/articles/{articleId}"
_WRITE_PATH = "/api/articles/remove/{articleId}"


def _config_dir(tmp_path: Path, privacy: str) -> Path:
    d = tmp_path / "cfg"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ownership.yaml").write_text(
        "version: 1\n"
        "resources:\n"
        "  - entity: Article\n"
        "    identifier_field: articleId\n"
        "    owner_field: authorId\n"
        f"    privacy: {privacy}\n"
        "default_privacy: UNKNOWN\n",
        encoding="utf-8",
    )
    return d


def _scan(monkeypatch, config_dir: Path):
    monkeypatch.setenv("ACCESS_SCAN_CONFIG_DIR", str(config_dir))
    kept, gw = cli.scan(_FIX)
    return kept + gw


def _paths(cands):
    return {c.endpoint.path for c in cands if c.subtype in ("A1", "A3")}


def test_undeclared_pojo_kept(monkeypatch, tmp_path):
    """无声明 → UNKNOWN → 读写都保留（不因信息不全而关闭）。"""
    cfg = tmp_path / "empty"
    cfg.mkdir()
    paths = _paths(_scan(monkeypatch, cfg))
    assert _READ_PATH in paths and _WRITE_PATH in paths


def test_declared_public_drops_read_keeps_write(monkeypatch, tmp_path):
    """PUBLIC 只豁免读；按 id 删除仍是越权写。"""
    paths = _paths(_scan(monkeypatch, _config_dir(tmp_path, "PUBLIC")))
    assert _READ_PATH not in paths, "公开资源的读访问不应报 A1"
    assert _WRITE_PATH in paths, "公开资源不豁免写/删"


def test_declared_private_keeps_both(monkeypatch, tmp_path):
    paths = _paths(_scan(monkeypatch, _config_dir(tmp_path, "PRIVATE")))
    assert {_READ_PATH, _WRITE_PATH} <= paths


def test_declared_pojo_without_entity_annotation(monkeypatch, tmp_path):
    """所有权模型显式声明的类，即使没有 @Entity 也纳入隐私判定。"""
    monkeypatch.setenv("ACCESS_SCAN_CONFIG_DIR", str(_config_dir(tmp_path, "PUBLIC")))
    ext = JavaExtractor()
    src = (_FIX / "Article.java").read_bytes()
    resources = ext.extract_resources(ext.parse(src), str(_FIX / "Article.java"))
    got = {r.entity: r.privacy for r in resources}
    assert got.get("Article") == "PUBLIC"


def _cand(path: str, flow_last: str) -> Candidate:
    ep = Endpoint(id=f"x:{path}", file="x.java", method="GET", path=path, handler="X.f",
                  params=[], auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                                           role_or_perm=None, scope="NONE"),
                  privilege_op=False, line_start=1, line_end=2)
    acc = ResourceAccess(entity="Article", identifier_param="articleId",
                         flow=["articleId", flow_last], ownership_predicate=False,
                         sink_snippet="x.java:1")
    return Candidate(endpoint=ep, access=acc, subtype="A1", rule_id="A1-idor")


def test_filter_unit_public_read_vs_write():
    resources = [Resource(entity="Article", identifier_field="articleId",
                          owner_field="authorId", privacy="PUBLIC", confidence=1.0)]
    kept, _ = apply_filters(
        [_cand("/r", "this.articleMapper.selectById"), _cand("/w", "this.articleMapper.deleteById")],
        {}, resources)
    assert [c.endpoint.path for c in kept] == ["/w"]
