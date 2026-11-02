"""M2 判定层 + 缓存 离线验证（无需真实 LLM / API Key）。

运行：python tests/test_m2_verdict.py
覆盖：evidence_key 确定性、缓存读写、schema 校验降级、
§7.4 verdict 判定（LIKELY/UNCERTAIN、公开资源、对抗否定）、
离线静态兜底、二次扫描缓存命中（零新增 LLM 调用）。
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.cache import VerdictCache, evidence_key
from access_scan.llm.verdict import VerdictPipeline, decide, validate

_FIXTURES = _REPO / "tests" / "fixtures" / "java"

_VULN = {
    "is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
    "resource_privacy": "PRIVATE", "reasoning": "证据包 line 25：仅按 id 查询，无归属校验。",
    "evidence_lines": [], "uncertain_reason": "",
}


class FakeJudge:
    """结构性 Fake：available=True 参与判定；refuted 控制对抗复核结果。"""

    def __init__(self, verdict=None, refuted: bool = False):
        self.verdict = verdict or dict(_VULN)
        self.refuted = refuted
        self.calls = 0
        self.available = True

    def judge(self, pkg):
        self.calls += 1
        return dict(self.verdict)

    def adversarial(self, pkg, verdict):
        return {"refuted": self.refuted, "reasoning": "网关已有全局校验" if self.refuted else "维持漏洞成立"}


def _candidate():
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    assert cands, "fixture 应产生候选"
    return cands[0]


def test_evidence_key():
    a = {"x": 1, "y": "中"}
    b = {"y": "中", "x": 1}
    assert evidence_key(a) == evidence_key(b)
    assert evidence_key({**a, "x": 2}) != evidence_key(a)


def test_cache_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        c = VerdictCache(str(Path(d) / "c.db"))
        assert c.get("k1") is None
        c.put("k1", {"v": 1})
        assert c.get("k1") == {"v": 1}
        c.close()


def test_validate_fallback_and_clamp():
    assert validate("垃圾输出")["subtype"] == "NONE"
    bad = dict(_VULN)
    bad["confidence"] = 9.9
    assert validate(bad)["confidence"] == 1.0
    broken = dict(_VULN, subtype="A7", is_vulnerable="yes")
    n = validate(broken)
    assert n["is_vulnerable"] is False and n["subtype"] == "NONE"


def test_decide():
    cand = _candidate()
    f = decide(cand, validate(dict(_VULN)), upheld=True)
    assert f.verdict == "LIKELY" and f.fix_suggestion and f.evidence["sink_snippet"]
    # 自信负结论 / 对抗否定 / PUBLIC 都是模型推断（策略矩阵 行6）→ 不改判定
    f2 = decide(cand, validate(dict(_VULN, is_vulnerable=False, subtype="NONE", reasoning="公开文章")))
    assert f2.verdict == "LIKELY" and f2.evidence.get("model_inference")
    f3 = decide(cand, validate(dict(_VULN)), upheld=False, adv_reason="网关已有校验")
    assert f3.verdict == "LIKELY" and "网关" in f3.llm_reasoning
    f4 = decide(cand, validate(dict(_VULN, resource_privacy="PUBLIC")))
    assert f4.verdict == "LIKELY" and "公开资源" in f4.llm_reasoning
    assert f4.evidence.get("close_authority") == "annotate_only"


def test_pipeline_offline_static_fallback():
    cands, _ = cli.scan(_FIXTURES)
    fs = VerdictPipeline(judge=None).run(cands)
    assert len(fs) == len(cands) >= 4
    assert all(f.verdict == "LIKELY" and f.llm_reasoning is None for f in fs)


def test_pipeline_cache_second_scan():
    cands, _ = cli.scan(_FIXTURES)
    fake = FakeJudge()
    with tempfile.TemporaryDirectory() as d:
        cache = VerdictCache(str(Path(d) / "c.db"))
        fs1 = VerdictPipeline(judge=fake, cache=cache).run(cands)
        calls_after_first = fake.calls
        assert len(fs1) == len(cands)
        p2 = VerdictPipeline(judge=fake, cache=cache)
        fs2 = p2.run(cands)
        assert fake.calls == calls_after_first, "二次扫描不得新增 LLM 调用"
        assert p2.cache_hits == len(cands), "二次扫描应全部命中缓存"
        assert [f.verdict for f in fs2] == [f.verdict for f in fs1]
        cache.close()


def test_pipeline_adversarial_veto():
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    fs = VerdictPipeline(judge=FakeJudge(refuted=True)).run(cands)
    # 对抗否定是模型推断（行6）：不自动关闭，保留 LIKELY 并标注待人工复核
    assert fs and all(f.verdict == "LIKELY" for f in fs)
    assert all(f.evidence.get("model_inference") for f in fs)


class FluctuatingJudge:
    """模拟 reasoning 模型非确定性：每次 judge 按序列返回不同判定。"""

    def __init__(self, votes):
        self.votes = votes
        self.idx = 0
        self.available = True
        self.calls = 0

    def judge(self, pkg):
        v = dict(self.votes[self.idx % len(self.votes)])
        self.idx += 1
        self.calls += 1
        return v

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": ""}


def test_vote_majority_and_discount():
    vuln = dict(_VULN, confidence=0.9)
    notvuln = dict(_VULN, is_vulnerable=False, subtype="NONE", confidence=0.2)
    judge = FluctuatingJudge([vuln, notvuln, vuln])  # 2:1 → 多数 vuln，分歧打折
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    fs = VerdictPipeline(judge=judge, samples=3).run(cands)
    assert fs[0].verdict == "LIKELY", "多数投票应判定为 LIKELY"
    assert "2/3" in fs[0].llm_reasoning, "分歧应标注采样一致性"
    # 平均 confidence=(0.9+0.2+0.9)/3≈0.667，分歧打折 0.7 → ≈0.467
    assert 0.4 <= fs[0].confidence <= 0.5


def test_vote_unanimous_no_discount():
    judge = FluctuatingJudge([dict(_VULN)] * 3)  # 3:0 全票一致
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    fs = VerdictPipeline(judge=judge, samples=3).run(cands)
    assert fs[0].verdict == "LIKELY"
    assert "3/3" in fs[0].llm_reasoning
    assert fs[0].confidence == 0.9, "全票一致不打折"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()