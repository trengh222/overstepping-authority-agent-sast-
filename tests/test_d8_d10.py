"""D8 报告去重 + D10 LLM 限流/快速失败测试。

运行：python -m pytest tests/test_d8_d10.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.ir import Finding
from access_scan.llm.verdict import VerdictPipeline

_FIX = _REPO / "tests" / "fixtures"


def _cand():
    cands, _ = cli.scan(_FIX / "java" / "idor_branch")
    return cands[0]


def _f(verdict, conf, sink):
    return Finding(candidate=_cand(), verdict=verdict, subtype="A1", confidence=conf,
                   llm_reasoning="x", evidence={"sink_snippet": sink})


# ---------------- D8 ----------------

def test_dedupe_same_endpoint():
    out = cli.dedupe_findings([
        _f("LIKELY", 0.8, "svc.findA"),
        _f("CONFIRMED", 0.9, "svc.findB"),
        _f("LIKELY", 0.7, "svc.findA"),
    ])
    assert len(out) == 1, "同 method+path+handler 应合并为一条"
    f = out[0]
    assert f.verdict == "CONFIRMED", "保留最高 severity"
    assert f.evidence["merged_count"] == 2
    assert set(f.evidence["merged_sinks"]) == {"svc.findA", "svc.findB"}


def test_dedupe_keeps_distinct_endpoints():
    a = _f("LIKELY", 0.8, "s1")
    b = _f("LIKELY", 0.8, "s2")
    b.candidate.endpoint.path = "/api/other/{id}"
    assert len(cli.dedupe_findings([a, b])) == 2


# ---------------- D10 ----------------

class BoomJudge:
    available = True
    calls = 0

    def judge(self, pkg):
        type(self).calls += 1
        raise AssertionError("超预算后不应再调用 LLM")

    def adversarial(self, pkg, verdict):
        raise AssertionError("超预算后不应调用对抗复核")


def test_budget_exhausted_falls_back_static():
    cands, _ = cli.scan(_FIX / "java" / "idor_branch")
    p = VerdictPipeline(judge=BoomJudge(), samples=1, max_seconds=1e-9)
    fs = p.run(cands)
    assert p.budget_exhausted
    assert BoomJudge.calls == 0
    assert all(f.verdict == "LIKELY" and f.llm_reasoning is None for f in fs)


def test_limit_truncates_candidates():
    findings, _ = cli.run(_FIX / "java", judge=None, limit=1, symbolic=False)
    assert len(findings) == 1


def test_parallel_samples_majority():
    class J:
        available = True
        calls = 0

        def judge(self, pkg):
            type(self).calls += 1
            return {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
                    "resource_privacy": "PRIVATE", "reasoning": "仅按 id 查询",
                    "evidence_lines": ["第 22 行：findById 无归属过滤"]}

        def adversarial(self, pkg, verdict):
            return {"refuted": False, "reasoning": "维持"}

    cands, _ = cli.scan(_FIX / "java" / "idor_branch")
    p = VerdictPipeline(judge=J(), samples=3, parallel_samples=True)
    fs = p.run(cands)
    assert J.calls == 3, "3 次采样应全部执行"
    assert fs[0].verdict == "LIKELY" and "3/3" in fs[0].llm_reasoning
