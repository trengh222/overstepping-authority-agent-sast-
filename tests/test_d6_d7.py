"""D6 跨过程（接口→Impl→Mapper）+ D7 参数来源/公开认证白名单测试。

运行：python -m pytest tests/test_d6_d7.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.symexec import build_poc
from access_scan.ir import (AuthInfo, AuthMechanism, Endpoint, ParamSource)
from access_scan.rules.vertical import is_public_auth_endpoint

_FIX = _REPO / "tests" / "fixtures"


# ---------------- D6 ----------------

def test_interface_to_impl_to_mapper():
    cands, _ = cli.scan(_FIX / "d6_service_impl")
    a1 = [c for c in cands if c.subtype == "A1"]
    assert a1, "controller → Service 接口 → Impl → Mapper 应命中"
    c = a1[0]
    assert c.endpoint.path == "/api/series/{id}"
    assert "selectById" in c.access.sink_snippet
    assert any("selectById" in f for f in c.access.flow)
    assert c.access.ownership_predicate is False


def test_setter_object_to_mapper():
    cands, _ = cli.scan(_FIX / "d6_object")
    a1 = [c for c in cands if c.subtype == "A1"]
    assert a1, "setter 写入查询对象后应继续跨过程到 Mapper"
    c = [x for x in a1 if x.endpoint.path == "/statisticsInfo/loadDataList"][0]
    assert "selectList" in c.access.sink_snippet
    assert any("findListByPage" in f for f in c.access.flow)


def test_query_object_as_taint_source():
    cands, _ = cli.scan(_FIX / "d6_object")
    paths = {c.endpoint.path for c in cands if c.subtype == "A1"}
    assert "/statisticsInfo/loadDataListQuery" in paths, \
        "无注解 *Query 对象应作为客户端可控污点源"


def test_unauthenticated_add_is_a3():
    cands, _ = cli.scan(_FIX / "d6_object")
    a3 = [c for c in cands if c.subtype == "A3" and c.endpoint.path == "/statisticsInfo/add"]
    assert a3, "add 写操作无鉴权应产出 A3"


# ---------------- D7 ----------------

def test_implicit_param_source_query():
    cands, _ = cli.scan(_FIX / "d7_param")
    a1 = [c for c in cands if c.subtype == "A1"]
    assert a1
    p = [x for x in a1[0].endpoint.params if x.name == "userId"][0]
    assert p.source == ParamSource.QUERY, "不在路径模板中的隐式参数应为 QUERY"


def test_poc_includes_query_param():
    cands, _ = cli.scan(_FIX / "d7_param")
    c = [x for x in cands if x.subtype == "A1"][0]
    poc = build_poc(c.endpoint, 42, "userId")
    assert "?userId=42" in poc
    assert "http://<host>/api/user/userInfo?userId=42" in poc


def test_public_auth_whitelist():
    ep = Endpoint(
        id="x", file="x.java", method="DELETE", path="/account/login",
        handler="AccountController.login", params=[],
        auth=AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                      role_or_perm=None, scope="NONE", line=-1),
        privilege_op=True, line_start=1, line_end=2,
    )
    assert is_public_auth_endpoint(ep)
    ep.path = "/manage/user/{id}"
    ep.handler = "AdminController.deleteUser"
    assert not is_public_auth_endpoint(ep)


def test_public_auth_endpoint_not_a3():
    cands, _ = cli.scan(_FIX / "d7_public")
    assert not [c for c in cands if c.subtype == "A3"], "登录流程不应报 A3"
