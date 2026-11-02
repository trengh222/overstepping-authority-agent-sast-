"""规则 B：垂直越权 / 未授权召回（方案 §7.2）。

M1 落地（未建全量调用图，以「注解 → 类 → 同扫描集内的拦截器/过滤器/注册器」
作为向上寻找鉴权点的链路）：
1. 端点非特权操作 → 跳过；
2. 方法/类级注解鉴权：
   - 授权足够（管理员/写权限角色）→ 通过；
   - 仅认证或普通用户角色（特权操作授权不足）→ emit Candidate(A2)；
3. 覆盖端点的守卫中存在「有鉴权逻辑且不依赖客户端输入」的 → 通过；
4. 仅被「鉴权依赖客户端可控输入」的守卫覆盖 → emit Candidate(A4)；
5. 无任何守卫 → emit Candidate(A3)。
"""
import re
from typing import List, Sequence, Tuple

from ..dataflow import asts
from ..extractor.base import Guard
from ..extractor.java import find_write_ops as _java_write_ops
from ..ir import AuthMechanism, Candidate, Endpoint, ResourceAccess


# 非 Java 前端的写操作可能藏在原生 SQL 字符串里（Go 的 db.Exec("DELETE FROM …")、
# JS/TS 的 query("UPDATE … SET …")），方法名（Exec/Query/query）本身不含写前缀。
_SQL_WRITE_KIND_RE = re.compile(
    r"\b(DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE|"
    r"UPDATE\s+[\w.`\"\[\]]+\s+SET|INSERT\s+INTO|REPLACE\s+INTO)\b", re.I)


def _sql_write_kind(call) -> str:
    """从调用文本里的原生 SQL 判定写操作类型（delete/update/insert/drop/alter/truncate）。"""
    m = _SQL_WRITE_KIND_RE.search(_node_text(call))
    if not m:
        return ""
    word = m.group(1).split()[0].lower()
    return "insert" if word == "replace" else word


# 资金/权限类写：即使 SQL 动词是 UPDATE，也属高权限操作（改角色、调余额、改状态）
_PRIVILEGE_WRITE_TEXT_RE = re.compile(
    r"\b(?:SET\s+(?:\w+\.)?(?:role|roles|is_admin|admin|permission|permissions|scope|status|"
    r"balance|amount|credit|points|level|vip)\b|GRANT\b|REVOKE\b|user_roles|role_id)", re.I)


def _write_ops(ctx) -> List[Tuple[str, int]]:
    """handler 内敏感写操作调用：[(方法名, 行号)]，按语言分派。"""
    lang = getattr(ctx, "language", "java")
    if lang == "java":
        return _java_write_ops(ctx.node)
    ops: List[Tuple[str, int]] = []
    for call in asts.iter_calls(ctx.node, lang):
        name = (asts.call_name(call) or "").lower()
        if name.startswith(asts.WRITE_OP_PREFIXES):
            ops.append((name, call.start_point[0] + 1))
            continue
        kind = _sql_write_kind(call)
        if kind:
            ops.append((kind, call.start_point[0] + 1))
    return ops


# 内联鉴权：鉴权函数调用名（token 校验/登录校验等）
_INLINE_AUTH_FN_RE = re.compile(
    r"(token_validator|decode_auth_token|login_required|authenticate|authorize|"
    r"check_permission|require_role|has_permission|is_authenticated|"
    r"getAuthentication|hasRole|hasAuthority|isAuthenticated|is_authorized)", re.I,
)
# 内联鉴权：权限检查模式（user.admin / role == 'admin' / has_role(...) 等）
_AUTH_CHECK_RE = re.compile(
    r"(\.admin\b|\.is_admin\b|has_role\s*\(|hasRole\s*\(|"
    r"role\s*==|is_authenticated\s*\(|isAuthenticated\s*\()", re.I,
)

# A2 垂直越权：特权操作（privilege_op）需「授权」而非仅「认证」。以下判定注解鉴权
# 的授权级别是否足够（管理员/高权限角色 → 足够；仅认证/普通用户角色 → 不足）。
# 注意：多角色数组（@Secured({"ROLE_USER","ROLE_ADMIN"})）提取器只取首个 → 可能
# 误报 A2，方向偏保守、交 L5 LLM 复核。
_ADMIN_ROLE_RE = re.compile(
    r"(ROLE_ADMIN|ROLE_STAFF|ROLE_MANAGER|ROLE_SUPERUSER|ROLE_OPERATOR|ROLE_ROOT|"
    r"ROLE_MODERATOR|"
    r"\badmin\b|\bsuperuser\b|\bsuper_user\b|\bmanager\b|\boperator\b|\broot\b|"
    r"\bmoderator\b|\bstaff\b|"
    r"hasRole\s*\(\s*['\"]?(ROLE_)?(ADMIN|STAFF|MANAGER|SUPERUSER|OPERATOR|ROOT|MODERATOR)\b|"
    r"hasAuthority\s*\(\s*['\"]?(ROLE_)?(ADMIN|STAFF|MANAGER|SUPERUSER|OPERATOR|ROOT|MODERATOR)\b)",
    re.I,
)
_ONLY_AUTH_RE = re.compile(
    r"(isAuthenticated|authenticated|"
    r"login_required|jwt_required|login_optional|"
    r"ROLE_USER|ROLE_CUSTOMER|ROLE_GUEST|ROLE_MEMBER|"
    r"hasRole\s*\(\s*['\"]?(ROLE_)?(USER|CUSTOMER|GUEST|MEMBER)\b|"
    r"hasAuthority\s*\(\s*['\"]?(ROLE_)?(USER|CUSTOMER|GUEST|MEMBER)\b)",
    re.I,
)


def _privilege_sufficient(role_or_perm) -> bool:
    """注解鉴权的授权级别是否足够支撑特权操作（A2 触发条件判定）。

    - 空（@login_required/@jwt_required 无参）→ 仅认证 → 不足；
    - 命中管理员/高权限角色 → 足够；
    - 命中仅认证/普通用户角色 → 不足（低权限可调高权限接口 → A2）；
    - 匿名开放（isAnonymous/permitAll）→ 注册/登录等公开端点，非 A2 范畴，保守通过；
    - 其它（hasPermission('order','write') 等明确权限表达式）→ 保守视为足够。
    """
    if not role_or_perm:
        return False
    if _ADMIN_ROLE_RE.search(role_or_perm):
        return True
    if _ONLY_AUTH_RE.search(role_or_perm):
        return False
    return True


# 中间件鉴权：明确的「仅认证」中间件方法名（security.isAuthorized() 等）
_MW_ONLY_AUTH_RE = re.compile(
    r"(isAuthorized|isAuthenticated|authenticate|authorize|login)$", re.I)


def _middleware_sufficient(role_or_perm) -> bool:
    """中间件鉴权授权级别是否足够支撑特权操作（A2 触发条件，JS/TS 中间件）。

    - 明确的「仅认证」中间件（isAuthorized/isAuthenticated/authenticate/authorize）
      → 特权操作授权不足 → A2；
    - 角色/其它中间件（isAdmin/isAccounting/denyAll/appendUserId 等）→ 保守视为足够。
    """
    if not role_or_perm:
        return False
    if str(role_or_perm).startswith("policy:"):
        # 策略引擎（Casbin/OPA）：鉴权规则在数据里，静态不可判定 → 视为授权决策点
        return True
    method = role_or_perm.split(".")[-1]
    if _MW_ONLY_AUTH_RE.search(method):
        return False
    return True


# 高权限写操作前缀（A2 垂直越权：这些操作通常需要角色/权限，而非仅认证）。
# 普通 CRUD（save/update/insert）多为「操作自己的资源」，不算高权限。
_PRIVILEGED_WRITE_PREFIXES = (
    "delete", "remove", "destroy", "drop", "alter", "truncate", "approve", "reject",
    "refund", "transfer", "grant", "revoke", "reset", "publish", "export", "ban",
    "suspend",
)


def _has_privileged_write(ctx) -> bool:
    """handler 内是否有「高权限写操作」（删除/审批/退款/授权/改角色/调余额）。"""
    lang = getattr(ctx, "language", "java")
    for call in asts.iter_calls(ctx.node, lang):
        name = (asts.call_name(call) or "").lower()
        if name.startswith(_PRIVILEGED_WRITE_PREFIXES):
            return True
        if _sql_write_kind(call).startswith(_PRIVILEGED_WRITE_PREFIXES):
            return True
        if _PRIVILEGE_WRITE_TEXT_RE.search(_node_text(call)):
            return True
    return False


def _node_text(node) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _inline_auth(ctx) -> bool:
    """handler 内是否有内联鉴权逻辑（鉴权函数调用 + 权限检查）。

    覆盖 VAmPI 这类「函数体内 token_validator 校验 + user.admin 判断」的鉴权写法，
    避免把有内联鉴权的特权端点误报为 A3（未授权）。
    """
    node = ctx.node
    lang = getattr(ctx, "language", "java")
    for call in asts.iter_calls(node, lang):
        name = (asts.call_name(call) or "").lower()
        if _INLINE_AUTH_FN_RE.search(name):
            return True
    if _AUTH_CHECK_RE.search(_node_text(node)):
        return True
    return False


def _glob_regex(pattern: str) -> str:
    """Ant 风格路径模式转正则：** → .* ，* → [^/]*，? → [^/]。"""
    p = pattern if pattern.startswith("/") else "/" + pattern
    out: List[str] = []
    i = 0
    while i < len(p):
        c = p[i]
        if c == "*":
            if i + 1 < len(p) and p[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c in ".^$+(){}[]|\\":
            out.append("\\" + c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "^" + "".join(out) + "$"


def guard_covers(guard: Guard, path: str) -> bool:
    """守卫是否生效并覆盖该路径（回验器与召回层共用同一套「有效门」定义）。"""
    if not guard.registered:
        return False  # 未注册的拦截器不生效
    if not guard.patterns:
        return True  # 未绑定具体路径 → 视作全局 /**
    return any(re.match(_glob_regex(pat), path) for pat in guard.patterns)


def _same_module(guard: Guard, endpoint: Endpoint) -> bool:
    """D1：守卫只在所属构建模块内生效，跨模块（web/admin 独立部署）不共享覆盖。"""
    return (getattr(guard, "module", "") or "") == (getattr(endpoint, "module", "") or "")


# D7：登录/注册/验证码等公开认证流程，不应报「未授权特权端点」
# health/actuator 只在路径真正落在探测端点上时豁免（/api/ops/health/detail 这类业务健康页不豁免）
_PUBLIC_AUTH_PATH_RE = re.compile(
    r"(^|/)(?:login|logout|register|signup|checkcode|captcha|autologin)(?:/|$)"
    r"|/(?:health|actuator)(?:/(?:health|live|ready|info|prometheus))?$",
    re.I)
_PUBLIC_AUTH_HANDLER_RE = re.compile(
    r"(?:^|[._])(?:login|logout|register|signup|checkCode|captcha|autoLogin|health)(?:$|[A-Z_])",
    re.I)

# 只读但属于系统/管理面的端点：即使没有写操作，也按特权面判定（内部指标/审计/导出/配置）
# init/install/setup/migrate：安装向导类未鉴权端点（如 /init/initMenu 属此列）
_SENSITIVE_PATH_RE = re.compile(
    r"(^|/)(internal|admin|manage|management|sys|system|ops|actuator|debug|"
    r"metrics|monitor|console|backdoor|db|init|install|setup|migrate)(/|$)", re.I)


def _sensitive_surface(endpoint: Endpoint) -> bool:
    """端点是否落在系统/管理面（供 privilege_op 之外的只读特权判定）。"""
    return bool(_SENSITIVE_PATH_RE.search(endpoint.path or ""))


def is_public_auth_endpoint(endpoint: Endpoint) -> bool:
    return bool(_PUBLIC_AUTH_PATH_RE.search(endpoint.path or "")
                or _PUBLIC_AUTH_HANDLER_RE.search(endpoint.handler or ""))


def recall_vertical(endpoint: Endpoint, ctx,
                    guards: Sequence[Guard] = ()) -> List[Candidate]:
    """规则 B：特权端点沿鉴权链找守卫，产出 A2（垂直越权）/ A3（未授权）/ A4（失效访问控制）候选。"""
    # 写操作之外，系统/管理面的只读端点同样属于特权面（内部指标、审计日志、导出、配置）
    if not endpoint.privilege_op and not _sensitive_surface(endpoint):
        return []

    # 会话级认证（HttpSession 取登录用户）＝已有认证：A3 不成立；
    # 归属/角色问题由 A1/A2 规则另行判定。
    if endpoint.auth.present and endpoint.auth.mechanism == AuthMechanism.SESSION:
        return []

    write_ops = _write_ops(ctx)
    chain: List[str] = [f"特权操作: {n} (line {ln})" for n, ln in write_ops] or ["特权操作(声明层级)"]

    # 2. 方法/类级注解鉴权：区分「授权足够」与「仅认证/普通角色」
    if endpoint.auth.present and endpoint.auth.mechanism == AuthMechanism.ANNOTATION:
        if _privilege_sufficient(endpoint.auth.role_or_perm):
            return []
        # 授权级别不足：低权限用户（仅登录/普通角色）可调用特权接口 → A2
        line, text = _first_write_op_line(ctx, write_ops)
        auth_desc = endpoint.auth.role_or_perm or "认证(无角色声明)"
        access = ResourceAccess(
            entity="",
            identifier_param="",
            flow=chain + [f"注解鉴权仅 {auth_desc}", "缺少管理员/写权限级授权（低权限可调高权限接口）"],
            ownership_predicate=False,
            sink_snippet=text or f"{endpoint.file}:{endpoint.line_start}: 授权不足",
        )
        return [Candidate(endpoint=endpoint, access=access, subtype="A2", rule_id="B-a2")]

    # 2.6 方法级中间件鉴权（security.isAuthorized()/isAccounting() 等）：
    #     仅认证中间件对特权操作授权不足 → A2；角色/其它中间件 → 通过
    if endpoint.auth.present and endpoint.auth.mechanism == AuthMechanism.MIDDLEWARE:
        if _middleware_sufficient(endpoint.auth.role_or_perm):
            return []
        # 仅认证 + 普通写（save/update）不算垂直越权；仅高权限写（删除/审批等）触发 A2
        if not _has_privileged_write(ctx):
            return []
        line, text = _first_write_op_line(ctx, write_ops)
        auth_desc = endpoint.auth.role_or_perm or "认证(无角色声明)"
        access = ResourceAccess(
            entity="",
            identifier_param="",
            flow=chain + [f"中间件鉴权仅 {auth_desc}",
                          "缺少角色/权限级授权（低权限可调高权限接口）"],
            ownership_predicate=False,
            sink_snippet=text or f"{endpoint.file}:{endpoint.line_start}: 授权不足",
        )
        return [Candidate(endpoint=endpoint, access=access, subtype="A2", rule_id="B-a2")]

    # 2.5 函数体内联鉴权（token 校验 + 权限判断）→ 通过
    if _inline_auth(ctx):
        return []
    covers = [g for g in guards if _same_module(g, endpoint) and guard_covers(g, endpoint.path)]

    # 3. 自足鉴权守卫覆盖 → 通过
    if any(g.has_auth_check and not g.depends_on_client_input for g in covers):
        return []

    # 4. 失效访问控制：鉴权依赖客户端可控值
    client_dep = [g for g in covers if g.depends_on_client_input]
    if client_dep:
        g = client_dep[0]
        access = ResourceAccess(
            entity="",
            identifier_param="",
            flow=chain + [f"鉴权守卫 {g.name} ({g.kind}, line {g.line}) 依赖客户端可控输入"],
            ownership_predicate=False,
            sink_snippet=f"{g.file or endpoint.file}:{g.line}: 客户端可控鉴权判断({g.kind})",
        )
        return [Candidate(endpoint=endpoint, access=access, subtype="A4", rule_id="B-a4")]

    # 5. 完全无鉴权 → A3（登录/注册等公开认证流程不报）
    if is_public_auth_endpoint(endpoint):
        return []
    line, text = _first_write_op_line(ctx, write_ops)
    access = ResourceAccess(
        entity="",
        identifier_param="",
        flow=chain + ["方法级: 无鉴权注解", "类级: 无鉴权注解", "拦截器/过滤器: 未覆盖"],
        ownership_predicate=False,
        sink_snippet=text or f"{endpoint.file}:{endpoint.line_start}: 无鉴权点",
    )
    return [Candidate(endpoint=endpoint, access=access, subtype="A3", rule_id="B-a3")]


def _first_write_op_line(ctx, write_ops: List[Tuple[str, int]]) -> Tuple[int, str]:
    if not write_ops:
        return -1, ""
    _, line = write_ops[0]
    if ctx.lines and 0 < line <= len(ctx.lines):
        return line, f"{ctx.file}:{line}: {ctx.lines[line - 1].strip()}"
    return line, f"{ctx.file}:{line}"