"""Java 语言轮修复的回归测试（标识命名 / 会话认证 / 权限注解 / 系统面只读端点）。

运行：python -m pytest tests/test_lang_java_round1.py -q
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli  # noqa: E402
from access_scan.ir import AuthInfo, AuthMechanism, Endpoint, Param, ParamSource  # noqa: E402
from access_scan.rules.idor import is_resource_identifier, recall_idor  # noqa: E402
from access_scan.rules.vertical import recall_vertical  # noqa: E402


def _auth(role=None, mech=AuthMechanism.ANNOTATION):
    return AuthInfo(present=True, mechanism=mech, role_or_perm=role, scope="METHOD")


def _ep(path="/api/orders/{id}", method="GET", auth=None, privilege=False):
    return Endpoint(
        id=f"x:OrderController.detail:{method}:{path}",
        file="OrderController.java",
        method=method,
        path=path,
        handler="OrderController.detail",
        params=[Param("id", ParamSource.PATH, "Long")],
        auth=auth or AuthInfo(present=False, mechanism=AuthMechanism.NONE,
                              role_or_perm=None, scope="NONE"),
        privilege_op=privilege,
        line_start=1,
        line_end=1,
    )


def test_camel_and_plural_identifiers():
    assert is_resource_identifier("orderNo")
    assert is_resource_identifier("docId")
    assert is_resource_identifier("productCode")
    assert is_resource_identifier("ids")
    assert is_resource_identifier("orderNos")
    assert not is_resource_identifier("name")
    assert not is_resource_identifier("status")


def test_a1_suppressed_by_permission_annotation():
    from access_scan.rules.idor import _covers_access_control

    assert _covers_access_control(_ep(auth=_auth("hasRole('ADMIN')")))
    assert _covers_access_control(
        _ep(auth=_auth("@reviewAccess.canRead(#reviewId, authentication.name)")))
    # 只有「已认证」不算覆盖资源级访问控制，A1 仍需继续判定
    assert not _covers_access_control(_ep(auth=_auth("isAuthenticated()")))
    assert not _covers_access_control(_ep(auth=_auth(mech=AuthMechanism.SESSION)))


def test_session_auth_is_not_unauthorized():
    ep = _ep(method="DELETE", privilege=True, auth=_auth(mech=AuthMechanism.SESSION))
    assert recall_vertical(ep, None, ()) == []


def test_sensitive_surface_read_flagged(tmp_path):
    ctrl = tmp_path / "InternalMetricsController.java"
    ctrl.write_text(
        'import org.springframework.jdbc.core.JdbcTemplate;\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\n'
        '@RequestMapping("/internal/metrics")\n'
        'public class InternalMetricsController {\n'
        '    private final JdbcTemplate jdbc;\n'
        '    public InternalMetricsController(JdbcTemplate jdbc) { this.jdbc = jdbc; }\n'
        '    @GetMapping\n'
        '    public Integer metrics() {\n'
        '        return jdbc.queryForObject("select count(*) from user_sessions", Integer.class);\n'
        '    }\n'
        '}\n', encoding="utf-8")
    findings, _ = cli.run(tmp_path, judge=None, adversarial=False)
    assert any(f.subtype == "A3" and f.candidate.endpoint.path == "/internal/metrics"
               for f in findings), "系统面只读端点应产出 A3 发现"
    assert any(f.verdict == "LIKELY" for f in findings), "网关降级后仍应是 LIKELY"


def test_session_endpoint_not_reported_as_a3(tmp_path):
    ctrl = tmp_path / "TicketController.java"
    ctrl.write_text(
        'import jakarta.servlet.http.HttpSession;\n'
        'import org.springframework.jdbc.core.JdbcTemplate;\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\n'
        '@RequestMapping("/api/tickets")\n'
        'public class TicketController {\n'
        '    private final JdbcTemplate jdbc;\n'
        '    public TicketController(JdbcTemplate jdbc) { this.jdbc = jdbc; }\n'
        '    @DeleteMapping("/{ticketId}")\n'
        '    public Integer remove(@PathVariable("ticketId") Long ticketId, HttpSession session) {\n'
        '        Long uid = (Long) session.getAttribute("LOGIN_USER_ID");\n'
        '        return jdbc.update("delete from tickets where id = ? and reporter_id = ?",\n'
        '                           ticketId, uid);\n'
        '    }\n'
        '}\n', encoding="utf-8")
    findings, _ = cli.run(tmp_path, judge=None, adversarial=False)
    assert not [f for f in findings if f.subtype == "A3"], "会话已认证不应再报 A3"
