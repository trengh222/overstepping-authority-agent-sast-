"""回验器（流水线④）单元测试：程序校验 LLM 声称的 blocking_gate 是否真实存在。

运行：python -m pytest tests/test_gate_verify.py -q
覆盖：guard/annotation/ownership 三种门的 verify_gate 校验（含名称/注册/鉴权能力核验），
以及 decide 里门确认存在 → 自动关(UNCERTAIN)、门不存在(幻觉) → 翻转保留(LIKELY)。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.extractor.base import Guard
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint,
                            ResourceAccess)
from access_scan.llm.verdict import decide, verify_gate

_SINK_WITH_OWNER = "tests/x.java:4: SELECT * FROM t_order WHERE id = :id AND user_id = :uid"
_SINK_NO_OWNER = "tests/x.java:4: return orderRepository.findById(id)"


def _cand(ownership=False, auth_present=False, auth_mech=AuthMechanism.NONE,
          annotation=None, role_or_perm=None, path="/api/order/{id}",
          subtype="A1"):
    return Candidate(
        endpoint=Endpoint(
            id="x", file="x.java", method="GET", path=path, handler="h",
            params=[], auth=AuthInfo(present=auth_present, mechanism=auth_mech,
                                     role_or_perm=role_or_perm, scope="NONE",
                                     line=-1, annotation=annotation),
            privilege_op=False, line_start=1, line_end=1,
        ),
        access=ResourceAccess(entity="Order", identifier_param="id", flow=[],
                              ownership_predicate=ownership,
                              sink_snippet=_SINK_WITH_OWNER if ownership else _SINK_NO_OWNER,
                              sink_line=1),
        subtype=subtype, rule_id="A1-idor",
    )


# ---------------- ownership ----------------

def test_verify_gate_ownership():
    gate = {"type": "ownership", "name": "user_id"}
    assert verify_gate(_cand(ownership=True), gate), "sink 文本真实含 user_id → 通过"
    assert not verify_gate(_cand(ownership=False), gate)
    # 归属约束存在，但 LLM 命名的字段不在 sink 里 → 不采信
    assert not verify_gate(_cand(ownership=True), {"type": "ownership", "name": "tenant_id"})
    assert not verify_gate(_cand(ownership=True), {"type": "ownership", "name": ""})


# ---------------- annotation ----------------

def test_verify_gate_annotation():
    c = _cand(auth_present=True, auth_mech=AuthMechanism.ANNOTATION,
              annotation="PreAuthorize", role_or_perm="hasRole('ADMIN')")
    assert verify_gate(c, {"type": "annotation", "name": "@PreAuthorize"})
    assert verify_gate(c, {"type": "annotation", "name": "hasRole('ADMIN')"})
    assert not verify_gate(c, {"type": "annotation", "name": "@Secured"}), "注解名不符应拒绝"
    assert not verify_gate(_cand(auth_present=False),
                           {"type": "annotation", "name": "@PreAuthorize"})


def test_verify_gate_annotation_requires_annotation_mechanism():
    """中间件鉴权不能被当作注解门采信。"""
    c = _cand(auth_present=True, auth_mech=AuthMechanism.MIDDLEWARE,
              role_or_perm="authenticate")
    assert not verify_gate(c, {"type": "annotation", "name": "authenticate"})


def test_verify_gate_permissive_annotation_rejected():
    """放行类注解（@PreAuthorize("isAnonymous()")）不是拦截门。"""
    c = _cand(auth_present=True, auth_mech=AuthMechanism.ANNOTATION,
              annotation="PreAuthorize", role_or_perm="isAnonymous()")
    assert not verify_gate(c, {"type": "annotation", "name": "PreAuthorize"})
    assert not verify_gate(c, {"type": "annotation", "name": "isAnonymous()"})


# ---------------- guard ----------------

def test_verify_gate_guard():
    guards = [Guard(kind="MIDDLEWARE", name="authMw", patterns=[],
                    has_auth_check=True, depends_on_client_input=False, line=1)]
    assert verify_gate(_cand(), {"type": "guard", "name": "AuthMw"}, guards), "名称大小写不敏感"
    assert not verify_gate(_cand(), {"type": "guard", "name": "otherMw"}, guards)
    assert not verify_gate(_cand(), {"type": "guard", "name": "auth"}, guards), "子串不算命中"


def test_verify_gate_guard_must_be_registered_and_auth():
    """未注册的拦截器 / 无鉴权逻辑或依赖客户端输入的守卫都不构成拦截门。"""
    unregistered = [Guard(kind="INTERCEPTOR", name="authMw", patterns=[],
                          has_auth_check=True, depends_on_client_input=False,
                          line=1, registered=False)]
    assert not verify_gate(_cand(), {"type": "guard", "name": "authMw"}, unregistered)
    no_auth = [Guard(kind="MIDDLEWARE", name="authMw", patterns=[],
                     has_auth_check=False, depends_on_client_input=True, line=1)]
    assert not verify_gate(_cand(), {"type": "guard", "name": "authMw"}, no_auth)
    client_dep = [Guard(kind="MIDDLEWARE", name="authMw", patterns=[],
                        has_auth_check=True, depends_on_client_input=True, line=1)]
    assert not verify_gate(_cand(), {"type": "guard", "name": "authMw"}, client_dep), \
        "鉴权依赖客户端可控输入（A4 信号）不得当作有效门"


def test_verify_gate_guard_path_coverage():
    guards = [Guard(kind="MIDDLEWARE", name="authMw", patterns=["/api/order/**"],
                    has_auth_check=True, depends_on_client_input=False, line=1)]
    assert verify_gate(_cand(path="/api/order/{id}"), {"type": "guard", "name": "authMw"}, guards)
    assert not verify_gate(_cand(path="/api/user/{id}"), {"type": "guard", "name": "authMw"}, guards)


# ---------------- decide 集成 ----------------

def test_decide_gate_passed_downgrades():
    """策略矩阵 行5：回验通过=权限推断 → 只降级，不自动关闭。"""
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8,
           "reasoning": "有归属校验", "blocking_gate": {"type": "ownership", "name": "user_id"}}
    f = decide(_cand(ownership=True), llm)
    assert f.verdict == "LIKELY", "权限推断不得作为关闭依据"
    assert f.disposition == "downgrade_annotate" and f.reachability_class == "permission"
    assert "回验确认" in f.llm_reasoning
    assert f.evidence.get("gate_verification") == "passed"
    assert f.evidence.get("close_authority") == "downgrade_only"


def test_decide_gate_failed_flip_to_likely():
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8,
           "reasoning": "有归属校验", "blocking_gate": {"type": "ownership", "name": "user_id"}}
    f = decide(_cand(ownership=False), llm)
    assert f.verdict == "LIKELY", "门不存在(幻觉)应翻转保留为疑似漏洞"
    assert f.evidence.get("gate_verification") == "failed"


def test_decide_gate_passed_confidence_below_failed():
    """回验通过（门真实存在）必须严格低于回验失败（模型编的门）的嫌疑度。"""
    gate = {"type": "ownership", "name": "user_id"}
    passed = decide(_cand(ownership=True),
                    {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.9,
                     "reasoning": "有归属校验", "blocking_gate": gate})
    failed = decide(_cand(ownership=False),
                    {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.9,
                     "reasoning": "有归属校验", "blocking_gate": gate})
    assert passed.confidence < failed.confidence == 0.55


def test_decide_gate_passed_confidence_inverts_safety_confidence():
    """方向取反：模型越确信「无漏洞」，嫌疑度越低（而不是越高）。"""
    gate = {"type": "ownership", "name": "user_id"}
    confs = []
    for safety in (0.2, 0.6, 0.95):
        f = decide(_cand(ownership=True),
                   {"is_vulnerable": False, "subtype": "NONE", "confidence": safety,
                    "reasoning": "有归属校验", "blocking_gate": gate})
        assert f.evidence["gate_verified_confidence"]["model_safety_confidence"] == safety
        confs.append(f.confidence)
    assert confs[0] > confs[1] > confs[2], f"嫌疑度应随安全置信度单调下降，实际 {confs}"
    assert all(0.3 <= c < 0.5 for c in confs)


def test_decide_no_gate_no_flip():
    # 无 blocking_gate、非 A4：自信负结论仍是模型推断（行6）→ 不改判定
    llm = {"is_vulnerable": False, "subtype": "NONE", "confidence": 0.8,
           "reasoning": "共享资源", "blocking_gate": None}
    f = decide(_cand(subtype="A1"), llm)
    assert f.verdict == "LIKELY" and f.disposition == "keep"
    assert "gate_verification" not in f.evidence
    assert f.evidence.get("model_inference")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")
