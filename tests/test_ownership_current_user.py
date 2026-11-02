"""D2 所有权判定测试：只看实参是否来自当前登录用户。

运行：python -m pytest tests/test_ownership_current_user.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow.taint import _ownership_in_text

_STORE = _REPO / "tests" / "fixtures" / "ownership" / "java_method_name"


# ---------------- 判定规则 ----------------

def test_method_name_no_longer_means_ownership():
    assert not _ownership_in_text("userId")
    assert not _ownership_in_text("getUserAllSeries, userId"), \
        "方法名含 User 不再自动视为归属约束"


def test_current_user_expressions():
    assert _ownership_in_text("tokenUserInfoDto.getUserId(), id")
    assert _ownership_in_text("principal.getName(), id")
    assert _ownership_in_text("req.user.id, id")
    assert _ownership_in_text("current_user()->id, id")
    assert _ownership_in_text("session.getAttribute('user_id'), id")


def test_current_user_local_variable():
    assert _ownership_in_text("uid, id", {"uid"})
    assert not _ownership_in_text("id", {"uid"})


def test_sql_owner_column_alone_is_not_enough():
    assert not _ownership_in_text('"SELECT * FROM t WHERE id = ? AND user_id = ?", id, clientUserId'), \
        "SQL 出现 user_id 列但绑定客户端值 → 仍可越权"
    assert _ownership_in_text('"SELECT * FROM t WHERE id = ? AND user_id = ?", id, current_user.id')


# ---------------- 端到端 ----------------

def _cands():
    cands, _ = cli.scan(_STORE)
    return [c for c in cands if c.subtype == "A1"]


def test_client_user_id_is_reported():
    a1 = _cands()
    paths = {c.endpoint.path for c in a1}
    assert "/api/series/{userId}" in paths, "客户端可控 userId 应作为 A1 报出"
    assert any("getUserAllSeries" in " ".join(c.access.flow) for c in a1)


def test_current_user_constrained_not_reported():
    paths = {c.endpoint.path for c in _cands()}
    assert "/api/series/mine/{userId}" not in paths, "principal 归属约束应过滤"
    assert "/api/series/token/{userId}" not in paths, "当前用户局部变量归属约束应过滤"


# ---------------- 跨语句别名传播（查询对象由当前用户赋值） ----------------

_QUERY_SRC = b"""
package x;
import org.springframework.web.bind.annotation.*;
@RestController
public class C {
    @GetMapping("/a")
    public Object a(String id) {
        UserDto dto = getTokenUserInfoDto();
        ActionQuery q = new ActionQuery();
        q.setItemId(id);
        q.setUserId(dto.getUserId());
        return svc.findListByParam(q);
    }
}
"""


def test_query_object_bound_to_current_user():
    from access_scan.extractor.java import JavaExtractor
    from access_scan.dataflow.taint import _java_current_user_vars

    ext = JavaExtractor()
    ast = ext.parse(_QUERY_SRC)
    ctx = ext.endpoint_contexts(ast, "x/C.java", _QUERY_SRC)["C.a"]
    assert "q" in _java_current_user_vars(ctx), \
        "setter 实参引用当前用户变量（dto）时，查询对象应绑定当前用户"
