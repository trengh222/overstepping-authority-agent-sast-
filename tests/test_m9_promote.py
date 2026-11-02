"""M9：符号反例升级 CONFIRMED 的反证闸门与说法改写。

覆盖两条实测暴露的边界：
- 回验器已确认「拦截门真实存在」时，符号执行 sat（数据可达）不得把 LIKELY 升为 CONFIRMED；
- 模型原先判定「非漏洞」但静态污点流 + 符号反例成立时，升级必须改写模型结论，避免报告自相矛盾。
"""
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint,
                            ResourceAccess)
from access_scan.llm.verdict import (decide, promote_with_counterexample,
                                     static_only_finding)

CE = {"counterexample": 1001, "poc": "GET http://<host>/api/order/1001"}
SINK = "OrderController.java:7: return orderService.findById(id);"
EVIDENCE = "findById(id) 未做归属过滤，客户端可控 id 直接查询"


def _cand(auth_present: bool = True) -> Candidate:
    auth = (AuthInfo(present=True, mechanism=AuthMechanism.ANNOTATION,
                     role_or_perm="hasRole('ADMIN')", scope="METHOD",
                     line=3, annotation="PreAuthorize")
            if auth_present else AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                                          role_or_perm=None, scope="NONE"))
    return Candidate(
        endpoint=Endpoint(id="x", file="OrderController.java", method="GET",
                          path="/api/order/{id}", handler="get", params=[],
                          auth=auth, privilege_op=False, line_start=1, line_end=9,
                          container=None),
        access=ResourceAccess(
            entity="Order", identifier_param="id",
            flow=["id -> orderService.findById -> Order"], ownership_predicate=False,
            sink_snippet=SINK, sink_line=7),
        subtype="A1", rule_id="A1-idor")


GATE = {"is_vulnerable": False, "confidence": 0.9, "reasoning": "PreAuthorize 限制管理员",
        "blocking_gate": {"type": "annotation", "name": "PreAuthorize"},
        "evidence_lines": [EVIDENCE]}
NEG = {"is_vulnerable": False, "confidence": 0.9, "reasoning": "看起来是公开接口",
       "evidence_lines": [EVIDENCE]}


def test_promote_blocks_on_verified_gate():
    f = decide(_cand(auth_present=True), GATE)
    assert f.verdict == "LIKELY" and f.evidence["gate_verification"] == "passed"
    p = promote_with_counterexample(f, CE)
    assert p.verdict == "LIKELY", "门已回验通过时不得升级 CONFIRMED"
    assert p.disposition == "downgrade_annotate"
    assert p.evidence["promotion_block"] == "gate_verified"
    assert p.evidence["evidence_verification"] == "failed"
    assert p.evidence["symbolic_reachability"] == "sat"   # 反例本身仍然记录
    assert p.poc == CE["poc"]


def test_promote_after_failed_gate():
    # 模型声称有门，但源码里找不到（auth.present=False）→ 回验 failed → 可升级
    f = decide(_cand(auth_present=False), GATE)
    assert f.evidence["gate_verification"] == "failed"
    p = promote_with_counterexample(f, CE)
    assert p.verdict == "CONFIRMED" and p.disposition == "promote"
    assert p.evidence.get("model_verdict_overridden") is True
    assert "推翻模型否定" in (p.llm_reasoning or "")


def test_promote_rewrites_negative_reasoning():
    f = decide(_cand(auth_present=False), NEG)
    assert f.verdict == "LIKELY" and "公开" in (f.llm_reasoning or "")
    p = promote_with_counterexample(f, CE)
    assert p.verdict == "CONFIRMED"
    assert p.evidence["model_verdict_overridden"] is True
    assert "推翻模型否定" in (p.llm_reasoning or "")
    assert "id=1001" in (p.llm_reasoning or "")
    assert p.confidence >= f.confidence


def test_promote_requires_llm_and_evidence():
    s = static_only_finding(_cand())
    p = promote_with_counterexample(s, CE)
    assert p.verdict == "LIKELY"
    assert p.evidence["evidence_verification"] == "failed"
    assert p.evidence["symbolic_reachability"] == "sat"


def test_dedupe_keeps_evidence_consistent_with_verdict():
    """合并同端点时，判定与证据必须来自同一候选（不得出现 passed + keep 的混搭）。"""
    from access_scan.cli import dedupe_findings
    passed = decide(_cand(auth_present=True), GATE)    # gate passed → downgrade_annotate 0.32
    failed = decide(_cand(auth_present=False), GATE)   # gate failed → keep 0.55
    merged = dedupe_findings([passed, failed])
    assert len(merged) == 1
    m = merged[0]
    assert m.confidence == 0.55 and m.disposition == "keep"
    assert m.evidence["gate_verification"] == "failed"
    assert len(m.evidence["merged_sinks"]) == 1
