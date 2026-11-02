"""方向一：LLM 判定框架鉴权上下文（RAG）注入 单元测试。

运行：python -m pytest tests/test_llm_rag.py -q
覆盖：_guards_summary 过滤（未注册/无鉴权守卫被剔除，客户端输入守卫保留）、
build_evidence_pkg 注入/不注入 framework_guards（向后兼容）、
cli.scan 的 guards_out 回填、VerdictPipeline 把 guards 透传给判定器。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.extractor.base import Guard
from access_scan.llm.prompts import build_evidence_pkg, _guards_summary
from access_scan.llm.verdict import VerdictPipeline

_FIXTURES = _REPO / "tests" / "fixtures" / "java"


def _candidate():
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    assert cands, "a3 fixture 应产生候选"
    return cands[0]


def _guard(name="AuthInterceptor", **kw):
    base = dict(kind="INTERCEPTOR", name=name, patterns=["/api/**"],
                has_auth_check=True, depends_on_client_input=False,
                line=1, registered=True)
    base.update(kw)
    return Guard(**base)


def test_guards_summary_filters_inactive_and_noauth():
    gs = [
        _guard("AuthInterceptor"),                                     # 保留
        _guard("DeadInterceptor", registered=False),                   # 未注册 → 剔除
        _guard("bodyParser", has_auth_check=False),                    # 无鉴权 → 剔除
        _guard("HeaderAuth", depends_on_client_input=True),            # 客户端输入 → 保留（A4 相关）
    ]
    names = [g["name"] for g in _guards_summary(gs)]
    assert names == ["AuthInterceptor", "HeaderAuth"]


def test_guards_summary_empty_patterns_default_global():
    gs = [_guard(patterns=[])]
    s = _guards_summary(gs)
    assert s[0]["patterns"] == ["**"], "空 patterns 视为全局覆盖"


def test_evidence_pkg_injects_guards():
    cand = _candidate()
    pkg = build_evidence_pkg(cand, [_guard("AuthInterceptor")])
    assert "framework_guards" in pkg
    assert pkg["framework_guards"][0]["name"] == "AuthInterceptor"
    assert pkg["framework_guards"][0]["patterns"] == ["/api/**"]
    assert pkg["framework_guards"][0]["has_auth_check"] is True


def test_evidence_pkg_no_guards_no_injection():
    cand = _candidate()
    pkg = build_evidence_pkg(cand, None)
    assert "framework_guards" not in pkg, "guards 为空时不注入（保持缓存 key 向后兼容）"


def test_scan_guards_out_populated():
    out = []
    cli.scan(_FIXTURES / "vertical" / "safe", guards_out=out)
    assert out, "vertical/safe（含已注册 AuthInterceptor）应回填守卫清单"
    assert any("Auth" in g.name for g in out)


class CapturingJudge:
    available = True

    def __init__(self):
        self.pkgs = []

    def judge(self, pkg):
        self.pkgs.append(pkg)
        return {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
                "resource_privacy": "PRIVATE", "reasoning": "t", "evidence_lines": [],
                "uncertain_reason": ""}

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": ""}


def test_pipeline_passes_guards_to_judge():
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    gs = [_guard("AuthInterceptor")]
    judge = CapturingJudge()
    VerdictPipeline(judge=judge, guards=gs, samples=1).run(cands)
    assert judge.pkgs, "判定器应收到证据包"
    assert all("framework_guards" in p for p in judge.pkgs)
    assert judge.pkgs[0]["framework_guards"][0]["name"] == "AuthInterceptor"


def test_pipeline_no_guards_no_injection():
    cands, _ = cli.scan(_FIXTURES / "vertical" / "a3")
    judge = CapturingJudge()
    VerdictPipeline(judge=judge, samples=1).run(cands)
    assert judge.pkgs and all("framework_guards" not in p for p in judge.pkgs)


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()