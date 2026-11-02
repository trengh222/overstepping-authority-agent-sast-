"""D1 守卫隔离测试：守卫只在所属构建模块内生效，跨模块不共享覆盖。

运行：python -m pytest tests/test_guard_scope.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.extractor.base import Guard, link_guards
from access_scan.ir import (AuthInfo, AuthMechanism, Candidate, Endpoint, ParamSource,
                            ResourceAccess)
from access_scan.llm.prompts import build_evidence_pkg
from access_scan.llm.verdict import verify_gate

_SCOPE = _REPO / "tests" / "fixtures_guard_scope"


def _cand(module: str):
    return Candidate(
        endpoint=Endpoint(
            id="x", file="x.java", method="DELETE", path="/manage/user/{id}", handler="h",
            params=[], auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                                     role_or_perm=None, scope="NONE", line=-1),
            privilege_op=True, line_start=1, line_end=2, module=module,
        ),
        access=ResourceAccess(entity="", identifier_param="", flow=["特权操作"],
                              ownership_predicate=False, sink_snippet="deleteUser"),
        subtype="A3", rule_id="B-a3",
    )


def _admin_guard():
    return [Guard(kind="INTERCEPTOR", name="AdminGuard", patterns=["/**"],
                  has_auth_check=True, depends_on_client_input=False, line=1,
                  file=str(_SCOPE / "admin" / "AdminGuard.java"), module="admin")]


def _a3(cands, module):
    return [c for c in cands if c.subtype == "A3" and (c.endpoint.module or "") == module]


# ---------------- 召回层（规则 B） ----------------

def test_guard_only_covers_own_module():
    guards = []
    cands, _ = cli.scan(_SCOPE, guards_out=guards)
    admin_guards = [g for g in guards if g.name == "AdminGuard"]
    assert admin_guards and admin_guards[0].module == "admin", "守卫应绑定到 admin 模块"
    assert _a3(cands, "web"), "web 模块无守卫，不应被 admin 守卫短路"
    assert not _a3(cands, "admin"), "admin 模块自身被 AdminGuard 覆盖"


def test_single_module_guard_still_global():
    """非多模块工程（无构建清单）保持原有全局语义。"""
    guards = [Guard(kind="MIDDLEWARE", name="authMw", patterns=["/**"],
                    has_auth_check=True, depends_on_client_input=False, line=1, module="")]
    assert verify_gate(_cand(""), {"type": "guard", "name": "authMw"}, guards)


def test_synthesized_guard_inherits_chain_module():
    guards = link_guards([], [("legacyAuth", ["/**"], "admin")])
    assert guards[0].kind == "CONFIGURER" and guards[0].module == "admin"


# ---------------- LLM 证据包（D9） ----------------

def test_evidence_pkg_only_injects_same_module_guards():
    guards = _admin_guard()
    web_pkg = build_evidence_pkg(_cand("web"), guards)
    admin_pkg = build_evidence_pkg(_cand("admin"), guards)
    assert "framework_guards" not in web_pkg, "web 候选不得看到 admin 守卫"
    assert admin_pkg["framework_guards"][0]["name"] == "AdminGuard"


def test_verify_gate_rejects_cross_module_guard():
    gates = {"type": "guard", "name": "AdminGuard"}
    assert not verify_gate(_cand("web"), gates, _admin_guard())
    assert verify_gate(_cand("admin"), gates, _admin_guard())
