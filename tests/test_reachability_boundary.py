"""五类可达性 → 处置边界 测试（构建/注册/配置/权限/数据）。

运行：python -m pytest tests/test_reachability_boundary.py -q
覆盖：
- 构建可达：构建排除（//go:build ignore）+ 死代码（终止符之后）→ 自动关闭；
- 注册可达：容器未见挂载（Express Router）→ 自动关闭；已挂载不提示；
- 数据可达：符号执行三态 sat/unsat/unsound → 升级 / 自动关闭 / 不动；
- decide 与 reachability_finding / unreachable_finding 的 class→disposition 映射。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.symexec import symbolic_reachability
from access_scan.extractor.base import Guard
from access_scan.extractor.go import GoExtractor
from access_scan.extractor.java import JavaExtractor
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint, ResourceAccess)
from access_scan.llm.verdict import (VerdictPipeline, data_fact_finding, decide,
                                     reachability_finding, unreachable_finding)
from access_scan.rules.build_reachability import dead_sink_reason, file_build_excluded
from access_scan.rules.registration import collect_mounts, unmounted_reason

_FIX = _REPO / "tests" / "fixtures"


def _cand(path="/api/order/{id}", container=None, hints=None, subtype="A1", flags=None,
          flow=None):
    return Candidate(
        endpoint=Endpoint(
            id="x", file="x", method="GET", path=path, handler="h", params=[],
            auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                          role_or_perm=None, scope="NONE", line=-1),
            privilege_op=False, line_start=1, line_end=1, container=container,
        ),
        access=ResourceAccess(entity="Order", identifier_param="id",
                              flow=["id -> orderService.findById -> Order"] if flow is None else flow,
                              ownership_predicate=False, sink_snippet="", sink_line=1),
        subtype=subtype, rule_id="A1-idor",
        reachability_hints=hints or {},
        flag_refs=flags or [],
    )


_VULN = {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9, "reasoning": "仅按 id 查询",
         "resource_privacy": "PRIVATE", "evidence_lines": ["第 4 行：findById 无归属过滤"]}


class _FakeJudge:
    available = True

    def judge(self, pkg):
        return dict(_VULN)

    def adversarial(self, pkg, verdict):
        return {"refuted": False, "reasoning": "维持漏洞成立"}


# ---------------- 构建可达 ----------------
def test_file_build_excluded_go_only():
    assert file_build_excluded("//go:build ignore\n\npackage main\n", "go")
    assert not file_build_excluded("//go:build linux\npackage main\n", "go")
    assert not file_build_excluded("//go:build ignore\n", "java")


def test_dead_sink_reason_go():
    src = b'package main\nfunc main() {\n\tid := "1"\n\treturn\n\t_ = id\n}\n'
    ast = GoExtractor().parse(src)
    reason = dead_sink_reason(ast.root_node, 5, "go")
    assert reason and "无条件" in reason, "终止符之后的 sink 应识别为死代码"
    assert dead_sink_reason(ast.root_node, 3, "go") is None, "终止符之前的 sink 不应判死代码"


def test_scan_build_excluded_go():
    cands, _ = cli.scan(_FIX / "build" / "go_ignore")
    assert cands, "构建排除文件内仍应召回候选（可达性判定在 L5）"
    assert all(c.reachability_hints.get("build") for c in cands), "应给出构建不可达提示"


# ---------------- 注册可达 ----------------
def test_collect_mounts():
    texts = [("javascript", "app.use('/api', router)")]
    assert collect_mounts(texts) == {"router"}


def test_collect_mounts_ignores_comments():
    # 注释里提到挂载调用不算真实挂载（否则会把已挂载容器误判为未挂载→漏报）
    assert collect_mounts([("javascript", "// app.use(router)\nconst x = 1;")]) == set()


def test_unmounted_reason():
    assert unmounted_reason("javascript", "router", set(), True)
    assert unmounted_reason("javascript", "router", {"router"}, True) is None  # 已挂载
    assert unmounted_reason("javascript", "app", set(), True) is None          # 根容器
    assert unmounted_reason("javascript", "router", set(), False) is None      # 非全量扫描不判定
    assert unmounted_reason("go", "router", set(), True) is None               # 语言不覆盖


def test_scan_js_registration_unmounted():
    cands, _ = cli.scan(_FIX / "registration" / "js_unmounted")
    assert cands, "未挂载 Express Router 内仍应召回候选"
    assert cands[0].reachability_hints.get("registration")


def test_scan_js_registration_mounted():
    cands, _ = cli.scan(_FIX / "registration" / "js_mounted")
    assert cands
    assert not cands[0].reachability_hints.get("registration")


# ---------------- 数据可达（符号执行三态） ----------------
def _sym(fixture_dir: str):
    ext = JavaExtractor()
    f = list((_FIX / "java" / fixture_dir).glob("*.java"))[0]
    src = f.read_bytes()
    ast = ext.parse(src)
    eps = ext.extract_endpoints(ast, str(f))
    ctxs = ext.endpoint_contexts(ast, str(f), src)
    ep = eps[0]
    ctx = ctxs[ep.handler]
    from access_scan.rules.idor import recall_idor
    acc = recall_idor(ep, ctx)[0].access
    return symbolic_reachability(ctx.method_node, acc.identifier_param, acc.sink_line, ep)


def test_symbolic_tri_state():
    assert _sym("idor_branch")["status"] == "sat"
    assert _sym("idor_unsat")["status"] == "unsat"
    assert _sym("idor_unsound")["status"] == "unsound"


def test_attach_unsat_auto_close():
    cands, _ = cli.scan(_FIX / "java" / "idor_unsat")
    fs = VerdictPipeline(judge=_FakeJudge()).run(cands)
    out = cli.attach_counterexamples(fs)
    assert out[0].verdict == "UNCERTAIN", "数据可达 unsat 应自动关闭"
    assert out[0].disposition == "auto_close"
    assert out[0].evidence.get("symbolic_reachability") == "unsat"


def test_promote_sets_promote_disposition():
    cands, _ = cli.scan(_FIX / "java" / "idor_branch")
    fs = VerdictPipeline(judge=_FakeJudge()).run(cands)
    out = cli.attach_counterexamples(fs)
    assert out[0].verdict == "CONFIRMED"
    assert out[0].disposition == "promote" and out[0].reachability_class == "data"
    assert out[0].evidence.get("symbolic_reachability") == "sat"


def test_attach_unsound_keeps_likely():
    cands, _ = cli.scan(_FIX / "java" / "idor_unsound")
    fs = VerdictPipeline(judge=_FakeJudge()).run(cands)
    out = cli.attach_counterexamples(fs)
    assert out[0].verdict == "LIKELY", "unsound（跑不动）不得降级，保持疑似"


# ---------------- class → disposition 映射 ----------------
def test_build_hint_auto_close_and_skips_llm():
    class _Boom:
        available = True

        def judge(self, pkg):
            raise AssertionError("构建不可达候选不应调用 LLM")

        def adversarial(self, pkg, verdict):
            raise AssertionError("不应调用对抗复核")

    fs = VerdictPipeline(judge=_Boom()).run([_cand(hints={"build": "文件被构建标记排除"})])
    assert len(fs) == 1
    assert fs[0].verdict == "UNCERTAIN"
    assert fs[0].reachability_class == "build" and fs[0].disposition == "auto_close"


def test_decide_registration_auto_close():
    c = _cand(container="bp", hints={"registration": "容器 'bp' 未见挂载调用"})
    f = decide(c, {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.7,
                   "reasoning": "路径存疑"})
    assert f.reachability_class == "registration" and f.disposition == "auto_close"
    assert f.verdict == "UNCERTAIN"


def test_decide_registration_llm_insists_keeps():
    c = _cand(container="bp", hints={"registration": "容器 'bp' 未见挂载调用"})
    f = decide(c, dict(_VULN))
    assert f.disposition == "keep" and f.reachability_class == "data", "LLM 坚持漏洞则不自动关闭"


def test_decide_config_downgrade_ticket():
    """LLM 不可达/需确认配置的声明必须有静态开关证据支撑。"""
    f = decide(_cand(flags=[{"name": "export.enabled", "declared": False}]),
               dict(_VULN, reachability="unreachable"))
    assert f.reachability_class == "config" and f.disposition == "downgrade_ticket"
    assert f.verdict == "UNCERTAIN", "declared=false 证据齐全才允许关闭"
    f2 = decide(_cand(flags=[{"name": "export.enabled", "declared": None}]),
                dict(_VULN, reachability="needs_config"))
    assert f2.reachability_class == "config" and f2.disposition == "downgrade_ticket"
    assert f2.verdict == "LIKELY"


def test_decide_unreachable_requires_disabled_flag():
    """LLM 声称不可达但无 declared=false → 不关闭，保留告警并转配置工单。"""
    f = decide(_cand(), dict(_VULN, reachability="unreachable"))
    assert f.verdict == "LIKELY", "无配置关闭证据不得自动关闭"
    assert f.reachability_class == "config" and f.disposition == "downgrade_ticket"
    assert f.evidence.get("reachability_verification") == "no_disabled_flag"


def test_decide_needs_config_requires_flag_refs():
    """证据包无 feature_flags 时，LLM 自述 needs_config 应被忽略（视为可达）。"""
    f = decide(_cand(), dict(_VULN, reachability="needs_config"))
    assert f.reachability_class == "data" and f.disposition == "keep"
    assert f.verdict == "LIKELY"


def test_decide_a4_negative_without_gate_keeps_likely():
    """A4 高危信号的负结论若无门可回验，不得直接关闭（基线实测漏报场景）。"""
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8,
           "reasoning": "字段白名单已过滤敏感字段"}
    f = decide(_cand(subtype="A4"), llm)
    assert f.verdict == "LIKELY" and f.disposition == "keep"
    assert f.evidence.get("negative_verification") == "unverified"


def test_decide_low_conf_negative_keeps_likely():
    """非 A4 但负结论置信度低于 0.6 → 同样不直接关闭。"""
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.4,
           "reasoning": "无法确定"}
    f = decide(_cand(subtype="A1"), llm)
    assert f.verdict == "LIKELY" and f.disposition == "keep"


def test_decide_confident_negative_keeps_likely():
    """策略矩阵 行6：自信负结论仍是模型推断 → 不改判定，只标注。"""
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8,
           "reasoning": "共享资源"}
    f = decide(_cand(subtype="A1"), llm)
    assert f.verdict == "LIKELY" and f.disposition == "keep"
    assert f.evidence.get("model_inference")


def test_decide_positive_requires_static_flow():
    """正向告警必须有静态污点链，空 flow 不直接告警。"""
    f = decide(_cand(subtype="A3", flow=[]), dict(_VULN))
    assert f.verdict == "UNCERTAIN" and f.disposition == "downgrade_annotate"
    assert f.evidence.get("positive_verification") == "failed"


def test_decide_a4_positive_requires_client_controlled_evidence():
    """A4 正向结论必须有「客户端可控鉴权」的真实静态证据。"""
    f = decide(_cand(subtype="A4", flow=["req -> admin"]), dict(_VULN))
    assert f.verdict == "UNCERTAIN" and f.evidence.get("positive_verification") == "failed"
    f2 = decide(_cand(subtype="A4",
                      flow=["鉴权守卫 authMw (MIDDLEWARE) 依赖客户端可控输入"]),
                dict(_VULN))
    assert f2.verdict == "LIKELY" and f2.reachability_class == "data"


def test_decide_permission_downgrade_annotate():
    """策略矩阵 行5：回验通过只降级，不关闭。"""
    guards = [Guard(kind="MIDDLEWARE", name="authMw", patterns=[], has_auth_check=True,
                    depends_on_client_input=False, line=1)]
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8, "reasoning": "有全局守卫",
           "blocking_gate": {"type": "guard", "name": "authMw"}}
    f = decide(_cand(), llm, guards=guards)
    assert f.verdict == "LIKELY"
    assert f.reachability_class == "permission" and f.disposition == "downgrade_annotate"
    assert f.evidence.get("gate_verification") == "passed"
    assert f.evidence.get("close_authority") == "downgrade_only"


def test_decide_data_keep():
    f = decide(_cand(), dict(_VULN))
    assert f.reachability_class == "data" and f.disposition == "keep"


def test_unreachable_finding_auto_close():
    g = unreachable_finding(decide(_cand(), dict(_VULN)), {"status": "unsat"})
    assert g.verdict == "UNCERTAIN" and g.reachability_class == "data"
    assert g.disposition == "auto_close" and g.evidence["symbolic_reachability"] == "unsat"


def test_reachability_finding_auto_close():
    f = reachability_finding(_cand(), "死代码", "build")
    assert f.verdict == "UNCERTAIN" and f.confidence == 0.0
    assert f.reachability_class == "build" and f.disposition == "auto_close"
    assert f.evidence.get("reachability_reason") == "死代码"


# ---------------- 策略矩阵：事实 / 推断 / 猜测 的处置边界 ----------------

def test_policy_matrix_facts_can_close():
    """行1/2/3：构建、注册、数据(unsat) 是确定性事实 → 允许自动关闭。"""
    cases = (("build", lambda: reachability_finding(_cand(), "模块未构建", "build")),
             ("registration", lambda: reachability_finding(_cand(), "包不在扫描根", "registration")),
             ("data", lambda: data_fact_finding(_cand(), "sink 已含归属约束")))
    for cls, maker in cases:
        f = maker()
        assert f.verdict == "UNCERTAIN" and f.disposition == "auto_close", cls
        assert f.evidence["fact_class"] == "fact", cls
        assert f.evidence["close_authority"] == "close_allowed", cls
    g = unreachable_finding(decide(_cand(), dict(_VULN)), {"status": "unsat"})
    assert g.disposition == "auto_close"
    assert g.evidence["close_authority"] == "close_allowed"


def test_policy_matrix_inference_only_downgrades():
    """行4/5：配置推断、权限推断 → 只降级，绝不自动关闭。"""
    # 配置推断：LLM 自述不可达且无 declared=false 证据 → LIKELY + 工单
    f = decide(_cand(), dict(_VULN, reachability="unreachable"))
    assert f.verdict == "LIKELY" and f.disposition == "downgrade_ticket"
    assert f.evidence["fact_class"] == "inference"
    assert f.evidence["close_authority"] == "downgrade_only"
    # 配置事实：声明中明确 declared=false → 允许关闭
    f2 = decide(_cand(flags=[{"name": "FEATURE_X", "declared": False}]),
                dict(_VULN, reachability="unreachable"))
    assert f2.verdict == "UNCERTAIN" and f2.evidence["close_authority"] == "close_allowed"
    # 权限推断：回验通过仍不得关闭
    guards = [Guard(kind="MIDDLEWARE", name="authMw", patterns=[], has_auth_check=True,
                    depends_on_client_input=False, line=1)]
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8,
           "reasoning": "有全局守卫", "blocking_gate": {"type": "guard", "name": "authMw"}}
    f3 = decide(_cand(), llm, guards=guards)
    assert f3.verdict == "LIKELY" and f3.disposition == "downgrade_annotate"
    assert f3.evidence["fact_class"] == "inference"
    assert f3.evidence["close_authority"] == "downgrade_only"


def test_policy_matrix_guesses_never_change_verdict():
    """行6：公开资源 / 自信负结论 / 对抗否定 → LIKELY + keep，仅标注。"""
    assert decide(_cand(), dict(_VULN)).verdict == "LIKELY"
    for kw in (dict(resource_privacy="PUBLIC"),
               dict(is_vulnerable=False, subtype="NONE", confidence=0.95, reasoning="内部接口")):
        f = decide(_cand(), dict(_VULN, **kw))
        assert f.verdict == "LIKELY" and f.disposition == "keep", kw
        assert f.evidence["close_authority"] == "annotate_only", kw
    f = decide(_cand(), dict(_VULN), upheld=False, adv_reason="网关已有校验")
    assert f.verdict == "LIKELY" and f.disposition == "keep"
    assert f.evidence["close_authority"] == "annotate_only"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
