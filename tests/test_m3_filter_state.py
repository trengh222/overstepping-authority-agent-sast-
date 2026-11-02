"""M3 验证：L4 过滤、候选/守卫序列化、增量扫描基线、SARIF、所有权反馈闭环。

运行：python tests/test_m3_filter_state.py
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.cache import ScanState
from access_scan.config import load_ownership, lookup_ownership, record_ownership_feedback
from access_scan.extractor.java import JavaExtractor, JavaGuard, guard_from_dict, guard_to_dict
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint, Resource,
                            ResourceAccess, candidate_from_dict, candidate_to_dict)
from access_scan.llm.verdict import VerdictPipeline
from access_scan.report.sarif import render as render_sarif
from access_scan.rules.filter import apply_filters, gateway_finding

_FIXTURES = _REPO / "tests" / "fixtures" / "java"


def _mk_candidate(path: str, subtype: str = "A1", entity: str = "Order") -> Candidate:
    ep = Endpoint(id=f"t:{subtype}:{path}", file="t.java", method="GET", path=path,
                  handler="T.h", params=[],
                  auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                                role_or_perm=None, scope="NONE"),
                  privilege_op=(subtype != "A1"), line_start=1, line_end=2)
    acc = ResourceAccess(entity=entity, identifier_param="id", flow=["id->x"],
                         ownership_predicate=False, sink_snippet="t.java:1: x")
    return Candidate(endpoint=ep, access=acc, subtype=subtype, rule_id="r")


def test_candidate_serde_roundtrip():
    kept, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    cand = kept[0]
    c2 = candidate_from_dict(candidate_to_dict(cand))
    assert c2.subtype == cand.subtype == "A3"
    assert c2.endpoint.path == cand.endpoint.path
    assert c2.access.flow == cand.access.flow
    assert c2.endpoint.auth.mechanism == cand.endpoint.auth.mechanism


def test_guard_serde_roundtrip():
    g = JavaGuard("INTERCEPTOR", "AuthInt", ["/a/**"], True, False, 7, "f.java")
    assert guard_from_dict(guard_to_dict(g)) == g


def test_scanstate_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        s = ScanState(str(Path(d) / "s.db"))
        s.put("f.java", "h1", {"candidates": [1]})
        assert s.get("f.java")["hash"] == "h1"
        s.close()


def test_incremental_reuses_unchanged():
    with tempfile.TemporaryDirectory() as d:
        s = ScanState(str(Path(d) / "s.db"))
        orig = JavaExtractor.parse
        n = {"c": 0}

        def counted(self, src):
            n["c"] += 1
            return orig(self, src)

        JavaExtractor.parse = counted
        try:
            kept1, gw1 = cli.scan(_FIXTURES, state=s)
            n1 = n["c"]
            kept2, gw2 = cli.scan(_FIXTURES, state=s)
            assert n["c"] == n1, "未变更文件不得重新解析（增量复用基线）"
            assert [c.endpoint.id for c in kept1] == [c.endpoint.id for c in kept2]
            assert [c.endpoint.id for c in gw1] == [c.endpoint.id for c in gw2]
        finally:
            JavaExtractor.parse = orig
            s.close()


def test_filters_exclude_public_gateway():
    cands = [
        _mk_candidate("/public/static/logo", "A1"),
        _mk_candidate("/api/order/{id}", "A1"),
        _mk_candidate("/api/product/{id}", "A1", entity="Product"),
        _mk_candidate("/admin/user", "A3"),
        _mk_candidate("/internal/job/run", "A3"),
    ]
    rules = {"exclude_prefixes": ["/public/"],
             "gateway_protected_prefixes": ["/admin/", "/internal/"]}
    resources = [Resource(entity="Product", identifier_field="id",
                          owner_field=None, privacy="PUBLIC", confidence=1.0)]
    kept, gw = apply_filters(cands, rules, resources)
    assert [c.endpoint.path for c in kept] == ["/api/order/{id}"]
    assert {c.endpoint.path for c in gw} == {"/admin/user", "/internal/job/run"}
    f = gateway_finding(gw[0])
    assert f.verdict == "LIKELY" and "网关" in f.llm_reasoning
    assert f.confidence == 0.3 and f.evidence["gateway_protected"] is True


def test_sarif_render():
    kept, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    fs = VerdictPipeline(judge=None).run(kept)
    doc = render_sarif(fs)
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "A3" and r["level"] == "warning"
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert r["partialFingerprints"]["accessScanCodeHash"]


def test_ownership_feedback_wins():
    with tempfile.TemporaryDirectory() as d:
        cfgdir = Path(d)
        record_ownership_feedback("Product", "PRIVATE", "人工确认", config_dir=cfgdir)
        record_ownership_feedback("Order", "PUBLIC", "订单接口本就公开", config_dir=cfgdir)
        m = load_ownership(config_dir=cfgdir)
        assert lookup_ownership("Product", m)["privacy"] == "PRIVATE"
        assert lookup_ownership("Order", m)["privacy"] == "PUBLIC"
        assert lookup_ownership("Missing", m) is None


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()