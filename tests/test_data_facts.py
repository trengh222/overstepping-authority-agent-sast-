"""数据事实模块测试：归属约束可关闭、类型收窄只降级、符号三态不重复实现。

运行：python -m pytest tests/test_data_facts.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint, Param,
                            ParamSource, ResourceAccess)
from access_scan.llm.verdict import VerdictPipeline, decide
from access_scan.rules.data_facts import data_fact_hints, is_type_narrowed

_FIX = _REPO / "tests" / "fixtures"

_LLM = {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
        "resource_privacy": "PRIVATE", "reasoning": "仅按 id 查询",
        "evidence_lines": ["第 20 行：orderService.findById(id) 无归属过滤"]}


def _cand(param_type="Long", ownership=False, flow=None, sink=True):
    return Candidate(
        endpoint=Endpoint(
            id="x", file="x.java", method="GET", path="/api/order/{id}", handler="h",
            params=[Param(name="id", source=ParamSource.PATH, type=param_type)],
            auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                          role_or_perm=None, scope="NONE", line=-1),
            privilege_op=False, line_start=10, line_end=20,
        ),
        access=ResourceAccess(
            entity="Order", identifier_param="id",
            flow=["id -> orderService.findById -> Order"] if flow is None else flow,
            ownership_predicate=ownership,
            sink_snippet="x.java:15: return orderService.findById(id);" if sink else "",
            sink_line=15,
        ),
        subtype="A1", rule_id="A1-idor",
    )


# ---------------- 静态事实 ----------------

def test_type_narrowed_matching():
    assert is_type_narrowed("UUID")
    assert is_type_narrowed("java.util.UUID")
    assert is_type_narrowed("uuid.UUID")
    assert is_type_narrowed("ObjectId")
    assert not is_type_narrowed("Long")
    assert not is_type_narrowed("String")


def test_normal_flow_has_no_data_hint():
    assert data_fact_hints(_cand()) == {}


def test_type_narrowed_only_downgrades():
    hints = data_fact_hints(_cand(param_type="UUID"))
    assert "data_downgrade" in hints and "data" not in hints
    assert "仅降级" in hints["data_downgrade"]


def test_ownership_constrained_is_data_fact():
    hints = data_fact_hints(_cand(ownership=True))
    assert hints.get("data"), "归属约束应产出可关闭的数据事实"


def test_empty_flow_no_fact():
    assert data_fact_hints(_cand(flow=[])) == {}
    assert data_fact_hints(_cand(sink=False)) == {}


# ---------------- 端到端 ----------------

def _candidate(fixture: str):
    cands, _ = cli.scan(_FIX / fixture)
    return [c for c in cands if c.subtype == "A1"][0]


def test_uuid_fixture_hint():
    c = _candidate("data/uuid_idor")
    assert c.endpoint.params[0].type == "UUID"
    assert "data_downgrade" in c.reachability_hints


def test_uuid_decide_downgrades_not_closes():
    """策略矩阵 行3/行7：类型收窄属运行时假设 → 只降级（LIKELY），不关闭。"""
    c = _candidate("data/uuid_idor")
    f = decide(c, dict(_LLM))
    assert f.verdict == "LIKELY", "类型收窄只降级、不关闭"
    assert f.reachability_class == "data" and f.disposition == "downgrade_annotate"
    assert f.evidence.get("data_downgrade")
    assert f.evidence.get("close_authority") == "downgrade_only"
    assert f.confidence <= 0.3


def test_non_uuid_fixture_no_downgrade():
    c = _candidate("java")
    assert "data_downgrade" not in c.reachability_hints


def test_ownership_data_fact_closes_without_llm():
    class Boom:
        available = True

        def judge(self, pkg):
            raise AssertionError("归属性数据事实不应调用 LLM")

        def adversarial(self, pkg, verdict):
            raise AssertionError("不应调用对抗复核")

    c = _cand(ownership=True)
    c.reachability_hints = {"data": "sink 查询已含归属约束（ownership_predicate=true）"}
    f = VerdictPipeline(judge=Boom()).run([c])[0]
    assert f.verdict == "UNCERTAIN" and f.reachability_class == "data"
    assert f.disposition == "auto_close" and "数据流事实" in f.llm_reasoning
