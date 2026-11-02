"""引用锚点回验（trace.py）与 verdict 接线测试（可追溯性闸门）。

运行：python -m pytest tests/test_m8_trace.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint,  # noqa: E402
                            Param, ParamSource, ResourceAccess)
from access_scan.llm.trace import parse_citations, verify_citations  # noqa: E402
from access_scan.llm.verdict import (decide, promote_with_counterexample,  # noqa: E402
                                     _evidence_sufficient)

_CTL = """package com.app;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private final OrderService orderService;

    @GetMapping("/{id}")
    public Order detail(@PathVariable Long id) {
        return orderService.load(id);
    }
}
"""

_SVC = """package com.app;

@Repository
public class OrderService {
    private final JdbcTemplate jdbcTemplate;

    public Order load(Long id) {
        String sql = "select * from t_order where id = ?";
        return jdbcTemplate.queryForObject(sql, Order.class, id);
    }
}
"""


def _mk(tmp_path) -> Path:
    (tmp_path / "OrderController.java").write_text(_CTL, encoding="utf-8")
    (tmp_path / "OrderService.java").write_text(_SVC, encoding="utf-8")
    return tmp_path


def _cand(root: Path, sink_line: int = 11) -> Candidate:
    ep = Endpoint(
        id="x", file="OrderController.java", method="GET", path="/api/orders/{id}",
        handler="OrderController.detail",
        params=[Param("id", ParamSource.PATH, "Long")],
        auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                      role_or_perm=None, scope="NONE"),
        privilege_op=False, line_start=7, line_end=10,
    )
    acc = ResourceAccess(
        entity="Order", identifier_param="id",
        flow=["id -> orderService.load -> t_order WHERE id"],
        ownership_predicate=False,
        sink_snippet="OrderService.java:%d: jdbcTemplate.queryForObject(sql, Order.class, id)" % sink_line,
        sink_line=sink_line,
    )
    return Candidate(endpoint=ep, access=acc, subtype="A1", rule_id="A1-idor")


def test_parse_citations_dedup():
    cs = parse_citations([
        "OrderService.java:11: jdbcTemplate.queryForObject 无归属过滤",
        "OrderService.java:11: 重复引用应去重",
        "OrderController.java:8-9: handler 无鉴权",
        "不是引用的一行",
    ])
    assert [str(c) for c in cs] == ["OrderService.java:11", "OrderController.java:8-9"]


def test_verify_ok_and_sink_covered(tmp_path):
    root = _mk(tmp_path)
    cand = _cand(root)
    chk = verify_citations(cand, [
        "OrderService.java:11: jdbcTemplate.queryForObject 仅按 id 查询，无 owner 过滤",
        "OrderController.java:8-9: detail 未做鉴权",
    ], root)
    assert chk["total"] == 2 and chk["verified"] == 2
    assert chk["ok"] is True and chk["sink_covered"] is True
    assert chk["broken"] == []


def test_verify_broken_file_and_range(tmp_path):
    root = _mk(tmp_path)
    cand = _cand(root)
    chk = verify_citations(cand, ["Nope.java:3: 不存在", "OrderService.java:999: 越界"], root)
    reasons = {b["reason"] for b in chk["broken"]}
    assert reasons == {"file_not_found", "line_out_of_range"}
    assert chk["verified"] == 0 and chk["ok"] is False


def test_verify_line_mismatch(tmp_path):
    root = _mk(tmp_path)
    cand = _cand(root)
    (root / "OrderService.java").write_text(_SVC + "\n// unrelated\n", encoding="utf-8")
    n = len((root / "OrderService.java").read_text(encoding="utf-8").splitlines())
    chk = verify_citations(cand, ["OrderService.java:%d: 完全无关的注释行" % n], root)
    assert chk["verified"] == 0
    assert chk["broken"][0]["reason"] == "line_mismatch"


def test_decide_downgrades_when_citations_unverifiable(tmp_path):
    root = _mk(tmp_path)
    cand = _cand(root)
    llm = {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
           "reasoning": "仅按 id 查询", "resource_privacy": "PRIVATE",
           "evidence_lines": ["Ghost.java:12: 编造的证据"]}
    f = decide(cand, llm, root=root)
    chk = f.evidence["citation_check"]
    assert chk["verified"] == 0
    assert f.verdict == "LIKELY" and f.disposition == "downgrade_annotate"
    assert f.confidence <= 0.3
    assert "不可追溯" in f.evidence["citation_review"]
    assert _evidence_sufficient(f) is False


def test_decide_annotates_when_sink_not_covered(tmp_path):
    root = _mk(tmp_path)
    cand = _cand(root)
    llm = {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
           "reasoning": "无归属过滤", "resource_privacy": "PRIVATE",
           "evidence_lines": ["OrderController.java:8-9: detail 未做鉴权"]}
    f = decide(cand, llm, root=root)
    assert f.verdict == "LIKELY" and f.disposition == "downgrade_annotate"
    assert f.evidence["citation_check"]["sink_covered"] is False
    assert "未覆盖 sink 行" in f.evidence["citation_review"]


def test_promote_requires_sink_coverage(tmp_path):
    root = _mk(tmp_path)
    cand = _cand(root)
    ok = decide(cand, {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
                       "reasoning": "sink 直接按 id 查询",
                       "evidence_lines": ["OrderService.java:11: queryForObject 无 owner 过滤"]},
                root=root)
    ce = {"counterexample": 7, "poc": "GET /api/orders/7"}
    promoted = promote_with_counterexample(ok, ce)
    assert promoted.verdict == "CONFIRMED" and promoted.disposition == "promote"

    weak = decide(cand, {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
                         "reasoning": "handler 无鉴权",
                         "evidence_lines": ["OrderController.java:8-9: detail 未做鉴权"]},
                  root=root)
    blocked = promote_with_counterexample(weak, ce)
    assert blocked.verdict == "LIKELY"
    assert "引用未通过回验" in blocked.evidence["citation_block"]
    assert blocked.evidence["evidence_verification"] == "failed"
