"""规则 B 之 A2 垂直越权验证。运行：python tests/test_a2_vertical.py"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.rules.vertical import _privilege_sufficient


# ---- 纯函数：授权级别判定 ----
def test_privilege_sufficient_levels():
    # 仅认证 / 普通用户角色 → 授权不足
    assert _privilege_sufficient(None) is False
    assert _privilege_sufficient("") is False
    assert _privilege_sufficient("isAuthenticated()") is False
    assert _privilege_sufficient("hasRole('ROLE_USER')") is False
    assert _privilege_sufficient("hasAuthority('USER')") is False
    # 匿名开放（注册/登录等公开端点）→ 非 A2 范畴，保守通过
    assert _privilege_sufficient("isAnonymous()") is True
    assert _privilege_sufficient("permitAll") is True
    # 管理员 / 高权限角色 → 足够
    assert _privilege_sufficient("hasRole('ROLE_ADMIN')") is True
    assert _privilege_sufficient("ROLE_ADMIN") is True
    assert _privilege_sufficient("admin") is True
    assert _privilege_sufficient("ROLE_STAFF") is True
    # 明确权限表达式（非角色名）→ 保守视为足够
    assert _privilege_sufficient("hasPermission('order', 'write')") is True


# ---- Java 端到端：正样本 A2 / 负样本通过 ----
def test_java_a2_vertical():
    kept, _ = cli.scan(_REPO / "tests" / "fixtures" / "java" / "vertical" / "a2")
    a2 = [c for c in kept if c.subtype == "A2"]
    handlers = {c.endpoint.handler for c in a2}
    assert "AdminControllerWeak.deleteUser" in handlers, f"弱鉴权特权端点应检出 A2: {handlers}"
    assert "AdminControllerStrong.deleteUser" not in handlers, "hasRole('ROLE_ADMIN') 不应检出 A2"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()
