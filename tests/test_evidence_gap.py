"""evidence_lines 缺失率离线统计测试。

运行：python -m pytest tests/test_evidence_gap.py -q

目的：量化 LLM 判定层「判为漏洞但未给出可核验证据（evidence_lines 空）」的缺失率，
及其对 CONFIRMED 升级的抑制。接入真实 LLM 后，compute_evidence_gap 可直接复用，
把 FakeJudge 换成真实 judge 即可统计真实缺失率。

关键事实（见 verdict.py）：
- decide() 对「经 LLM 判定」的候选都会写 ev["llm_evidence_lines"]；
- static_only_finding（离线兜底）不写该键 → 可用「键是否存在」区分是否经 LLM 判定；
- promote_with_counterexample 只在 reasoning 非空 + evidence_lines 非空时升级 CONFIRMED，
  否则保留 LIKELY（不缺召回，只降 CONFIRMED 率）。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.llm.verdict import VerdictPipeline

_FIXTURES = _REPO / "tests" / "fixtures" / "java"

_VULN = {
    "is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
    "resource_privacy": "PRIVATE", "reasoning": "仅按 id 查询，无归属校验。",
    "evidence_lines": ["第 22 行：仅按 id 查询，无 user_id 归属过滤"],
    "uncertain_reason": "",
}


class EvidenceGapJudge:
    """模拟 LLM 判漏洞但按比例缺失 evidence_lines（确定性伪随机，按候选序号）。"""

    available = True

    def __init__(self, gap_ratio: float = 0.0):
        self.gap_ratio = gap_ratio
        self.idx = 0

    def judge(self, pkg):
        i = self.idx
        self.idx += 1
        missing = (i * 7) % 10 < self.gap_ratio * 10  # 确定性伪随机缺失
        v = dict(_VULN)
        v["evidence_lines"] = [] if missing else list(_VULN["evidence_lines"])
        return v

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": "维持漏洞成立"}


def compute_evidence_gap(findings):
    """统计 LLM 判定层的 evidence_lines 缺失率。

    仅统计「经 LLM 判定且判为漏洞（LIKELY/CONFIRMED）」的候选；
    离线兜底（无 llm_evidence_lines 键）不计入，避免把离线 LIKELY 误当缺失。
    """
    judged = [f for f in findings if "llm_evidence_lines" in f.evidence]
    vuln = [f for f in judged if f.verdict in ("LIKELY", "CONFIRMED")]
    missing = [f for f in vuln if not f.evidence["llm_evidence_lines"]]
    total = len(vuln)
    return {
        "judged": len(judged),
        "total_vuln": total,
        "evidence_missing": len(missing),
        "missing_rate": len(missing) / total if total else 0.0,
        "confirmed": sum(1 for f in findings if f.verdict == "CONFIRMED"),
        "likely": sum(1 for f in findings if f.verdict == "LIKELY"),
        "uncertain": sum(1 for f in findings if f.verdict == "UNCERTAIN"),
    }


def _run(gap_ratio):
    cands, _ = cli.scan(_FIXTURES)
    fs = VerdictPipeline(judge=EvidenceGapJudge(gap_ratio)).run(cands)
    return fs, compute_evidence_gap(fs)


def test_evidence_gap_zero():
    fs, g = _run(0.0)
    assert g["total_vuln"] > 0, "应有经 LLM 判为漏洞的候选"
    assert g["evidence_missing"] == 0
    assert g["missing_rate"] == 0.0


def test_evidence_gap_full():
    fs, g = _run(1.0)
    assert g["total_vuln"] > 0
    assert g["evidence_missing"] == g["total_vuln"], "gap_ratio=1 应全部缺失"
    assert g["missing_rate"] == 1.0


def test_evidence_gap_partial():
    fs, g = _run(0.5)
    assert g["total_vuln"] > 0
    assert 0 < g["missing_rate"] < 1, "gap_ratio=0.5 应测出部分缺失（中间态）"
    assert g["missing_rate"] == g["evidence_missing"] / g["total_vuln"]


def test_missing_evidence_blocks_confirm():
    """单个可 sat 的 A1 候选：有证据升级 CONFIRMED、缺证据卡 LIKELY（召回不丢）。"""
    cands, _ = cli.scan(_FIXTURES / "idor_branch")

    fs = VerdictPipeline(judge=EvidenceGapJudge(0.0)).run(cands)
    out = cli.attach_counterexamples(fs)
    assert out[0].verdict == "CONFIRMED"

    fs2 = VerdictPipeline(judge=EvidenceGapJudge(1.0)).run(cands)
    out2 = cli.attach_counterexamples(fs2)
    g = compute_evidence_gap(out2)
    assert out2[0].verdict == "LIKELY", "缺证据不得升级 CONFIRMED，但应保留 LIKELY（召回不丢）"
    assert g["missing_rate"] == 1.0 and g["confirmed"] == 0
    assert g["likely"] == 1, "缺证据的漏洞候选仍应为 LIKELY 告警"


def test_static_fallback_excluded_from_gap():
    """离线兜底（无 LLM）不应计入缺失率。"""
    cands, _ = cli.scan(_FIXTURES)
    fs = VerdictPipeline(judge=None).run(cands)
    g = compute_evidence_gap(fs)
    assert g["judged"] == 0, "离线兜底无 llm_evidence_lines 键，不应计为经 LLM 判定"
    assert g["total_vuln"] == 0 and g["missing_rate"] == 0.0


class _LinesJudge:
    """固定返回指定 evidence_lines 的 judge（用于证据内容核验测试）。"""

    available = True

    def __init__(self, lines):
        self.lines = list(lines)

    def judge(self, pkg):
        return dict(_VULN, evidence_lines=list(self.lines))

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": "维持漏洞成立"}


def _promote_with(lines):
    cands, _ = cli.scan(_FIXTURES / "idor_branch")
    fs = VerdictPipeline(judge=_LinesJudge(lines)).run(cands)
    assert len(fs) == 1
    return cli.attach_counterexamples(fs)[0]


def test_hallucinated_evidence_blocks_confirm():
    """编造行号且不含真实代码 → 证据核验失败，不得升级 CONFIRMED。"""
    f = _promote_with(["第 999 行：这里显然存在越权"])
    assert f.verdict == "LIKELY"
    assert f.evidence["evidence_verification"] == "failed"


def test_line_evidence_within_handler_range_passes():
    """行号落在 handler 范围内 → 证据核验通过。"""
    f = _promote_with(["第 22 行：仅按 id 查询，无 user_id 归属过滤"])
    assert f.verdict == "CONFIRMED"
    assert f.evidence["evidence_verification"] == "passed"


def test_code_evidence_matching_sink_passes():
    """证据条目包含 sink 中的真实调用 → 证据核验通过。"""
    f = _promote_with(["orderService.findById(id) 未做归属过滤"])
    assert f.verdict == "CONFIRMED"
    assert f.evidence["evidence_verification"] == "passed"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
