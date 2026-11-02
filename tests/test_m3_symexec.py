"""M3.3 符号执行反例/PoC 验证。运行：python tests/test_m3_symexec.py

覆盖：带路径约束的反例求解（branched）、不可达 sink 不产出反例、
未解释条件 unsound 降级、§7.4 升级（LLM 通过 → CONFIRMED；离线 → LIKELY + PoC）。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.symexec import build_poc, symbolic_counterexample
from access_scan.extractor.java import JavaExtractor
from access_scan.llm.verdict import VerdictPipeline, promote_with_counterexample

_FIXTURES = _REPO / "tests" / "fixtures" / "java"

_VULN_LLM = {
    "is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
    "resource_privacy": "PRIVATE", "reasoning": "仅按 id 查询，无归属校验。",
    "evidence_lines": ["第 4 行：orderService.findById(id) 仅按 id 查询，无 user_id 归属过滤"],
    "uncertain_reason": "",
}


class FakeJudge:
    available = True

    def judge(self, pkg):
        return dict(_VULN_LLM)

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": "维持漏洞成立"}


def _sym_result(fixture_dir: str):
    """直接调符号执行核心，返回 (counterexample or None)。"""
    ext = JavaExtractor()
    f = list((_FIXTURES / fixture_dir).glob("*.java"))[0]
    src = f.read_bytes()
    ast = ext.parse(src)
    eps = ext.extract_endpoints(ast, str(f))
    ctxs = ext.endpoint_contexts(ast, str(f), src)
    ep = eps[0]
    ctx = ctxs[ep.handler]
    # 复用规则 A 拿到 sink_line
    from access_scan.rules.idor import recall_idor
    cands = recall_idor(ep, ctx)
    assert cands, f"{fixture_dir} 应先产出 A1 候选"
    acc = cands[0].access
    return symbolic_counterexample(ctx.method_node, acc.identifier_param, acc.sink_line, ep)


def test_counterexample_with_branch_constraint():
    ce = _sym_result("idor_branch")
    assert ce is not None
    assert ce["counterexample"] > 1000, "反例应满足 id>1000 路径约束"
    assert f"/api/order/{ce['counterexample']}" in ce["poc"]
    assert "curl" in ce["poc"]


def test_unreachable_sink_no_counterexample():
    assert _sym_result("idor_unsat") is None


def test_unsound_condition_degrades():
    assert _sym_result("idor_unsound") is None


def test_promote_confirmed_with_llm_review():
    cands, _ = cli.scan(_FIXTURES / "idor_branch")
    fs = VerdictPipeline(judge=FakeJudge()).run(cands)
    out = cli.attach_counterexamples(fs)
    assert len(out) == 1
    f = out[0]
    assert f.verdict == "CONFIRMED"
    assert f.poc and "curl" in f.poc
    assert f.evidence["counterexample"] > 1000
    assert f.confidence > 0.9


def test_offline_keeps_likely_with_poc():
    cands, _ = cli.scan(_FIXTURES / "idor_branch")
    fs = VerdictPipeline(judge=None).run(cands)
    out = cli.attach_counterexamples(fs)
    f = out[0]
    assert f.verdict == "LIKELY", "离线无 LLM 复核不得升级 CONFIRMED（§7.4）"
    assert f.poc and f.evidence["counterexample"] > 1000


class NoEvidenceJudge:
    available = True

    def judge(self, pkg):
        return dict(_VULN_LLM, evidence_lines=[])  # 复核通过但未给出证据条目

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": "维持漏洞成立"}


def test_no_evidence_no_confirm():
    cands, _ = cli.scan(_FIXTURES / "idor_branch")
    fs = VerdictPipeline(judge=NoEvidenceJudge()).run(cands)
    out = cli.attach_counterexamples(fs)
    f = out[0]
    assert f.verdict == "LIKELY", "LLM 未给出证据条目（evidence_lines 空）不得升级 CONFIRMED"
    assert f.poc and f.evidence["counterexample"] > 1000


def test_unary_condition_no_crash():
    """回归：一元条件（!flags.isEnabled(...)）不得让符号执行崩溃（_text 收到空串）。"""
    cands, _ = cli.scan(_FIXTURES.parent / "reachability" / "java_export")
    fs = VerdictPipeline(judge=None).run(cands)
    out = cli.attach_counterexamples(fs)
    assert len(out) == 1 and out[0].verdict == "LIKELY", "未解释的一元条件按 unsound 保持 LIKELY"


def test_vertical_not_promoted():
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    fs = VerdictPipeline(judge=None).run(cands)
    out = cli.attach_counterexamples(fs)
    assert out[0].verdict == "LIKELY" and out[0].poc is None


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()