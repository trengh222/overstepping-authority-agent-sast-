"""规则 A：水平越权（IDOR）召回（方案 §7.1）。

伪代码落地：
1. 参数名命中 {id, *Id, *_id, uuid, code, key} 或类型为数值/主键 → 资源标识；
2. 污点追踪该参数是否流入 DB/文件 sink；
3. 查询无 currentUser 归属约束 → emit Candidate(A1)；
4. 参数为集合（List<Long> ids）时标注批量越权场景。
"""
import re
from typing import List

from ..dataflow.taint import trace_to_sinks
from ..extractor.java import is_scalar_param_type
from ..ir import AuthMechanism, Candidate, Endpoint, ParamSource
from .vertical import is_public_auth_endpoint

_ID_NAME_EXACT = {"id", "uuid", "code", "key", "no", "username", "email", "slug",
                  "book_title", "order_no"}
_ID_TYPE_RE = re.compile(r"(int|integer|long|short|uuid|bigdecimal|number)", re.I)
# 复合名后缀（book_title→title、order_no→no、user_name→name）；要求带 _/-，避免 title/name 单独误报
_ID_SUFFIX_RE = re.compile(r"[_-](id|uuid|code|key|no|name|title|username|email|slug)$", re.I)
# 驼峰复合名（orderNo、docId、userId、productCode…）
_CAMEL_ID_SUFFIX_RE = re.compile(
    r"[a-z](Id|Uid|Uuid|Code|Key|No|Num|Name|Title|Username|Email|Slug)$")
# 复数集合型标识（ids、orderNos、codes…）
_PLURAL_ID_RE = re.compile(
    r"(?:ids|uuids|codes|keys|nos|nums|names|titles|usernames|emails|slugs)$", re.I)
# 权限/资源级 SpEL 注解（角色校验或引用资源参数的表达式）→ 访问控制已覆盖。
# Go 中间件名是驼峰（RequireAdmin/RequireRole/IsStaff），也视为角色级覆盖；
# 纯认证中间件（AuthMiddleware/RequireAuth）不在此列——认证不等于授权。
_PERMISSION_HINT_RE = re.compile(
    r"(hasRole|hasAnyRole|hasAuthority|hasPermission|"
    r"can(?:Read|Write|Edit|Access|View|Modify|Delete|Manage)\w*|"
    r"ROLE_[A-Z_]+|\bADMIN\b|\bMANAGER\b|\bSUPERUSER\b|#\w+|"
    r"Require(?:Admin|Role|Roles|Staff|Superuser|Manager|Permission|Scope)\b|"
    r"Is(?:Admin|Staff|Superuser|Manager)\b|"
    r"Has(?:Role|Roles|Permission|Scope)\b|\bAdminOnly\b)", re.I)
_COLLECTION_RE = re.compile(r"\b(list|set|collection|arraylist|hashset|linkedlist)\b|<[^>]+>|\[\]", re.I)
# 文件/资源路径类参数（客户端可控路径 → 任意文件读取类越权）
_PATH_PARAM_RE = re.compile(
    r"^(?:file|src|path|url|uri|filename|filepath|source_?name|resource_?name|"
    r"resource|attachment|avatar|image_?path|video_?path)$", re.I)

# 非「对象引用」参数：命名空间/检索/分页/代码生成输入。它们客户端可控，但语义上
# 不是「指向某个具体对象」的标识，因此不构成 IDOR（库名进 SQL 属注入类，文件名属
# 检索条件）。按归一化名（去非字母数字、小写）精确匹配，避免影响 userId/orderId 等。
_NON_RESOURCE_NAMES = frozenset({
    "db", "dbname", "database", "databasename", "tablename", "table",
    "schema", "schemaname", "collection", "collectionname",
    "keyword", "keywords", "query", "search", "filter",
    "sort", "sortby", "order", "orderby", "page", "pageindex", "pageno",
    "pagenum", "pagesize", "limit", "offset", "cursor",
    "filename", "filepath", "structname", "templatename", "modelname",
    "packagename", "modulename",
})

# 复合后缀：`HumpPackageName`/`ModelTableName` 这类「前缀+命名空间词」也归为
# 非对象引用（按归一化名后缀匹配，不影响 userId/orderId 这类以 id 结尾的名字）。
_NON_RESOURCE_SUFFIXES = (
    "dbname", "tablename", "schemaname", "databasename", "collectionname",
    "packagename", "structname", "templatename", "modelname", "modulename",
    "filename", "filepath",
)


def _is_non_resource(raw: str) -> bool:
    n = _norm(raw)
    return bool(n) and (n in _NON_RESOURCE_NAMES
                        or any(n.endswith(s) for s in _NON_RESOURCE_SUFFIXES))


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def is_resource_identifier(param_name: str, param_type: str = "") -> bool:
    """规则 7.1 第 1 步：资源标识参数判定。

    覆盖数字主键（id/*Id）与字符串业务键（username/book_title/order_no 等，
    VAmPI 这类 IDOR 的典型资源标识）。对象型参数（非标量类型）由框架按
    query/form 绑定，可能携带资源标识条件，同样作为候选源（是否成立由污点流
    是否到达 sink 决定）。
    """
    if param_type and not is_scalar_param_type(param_type):
        return True
    raw = (param_name or "").strip()
    n = raw.lower()
    if _is_non_resource(raw):
        return False  # 命名空间/检索/分页/代码生成输入，不是对象引用
    if _CAMEL_ID_SUFFIX_RE.search(raw):
        return True
    if _PATH_PARAM_RE.match(n):
        return True  # 文件/资源路径参数
    if n in _ID_NAME_EXACT:
        return True
    if n.endswith("_id") or (len(n) > 2 and n.endswith("id")):
        return True
    if _ID_SUFFIX_RE.search(n):
        return True
    if len(n) >= 3 and _PLURAL_ID_RE.search(n):
        return True
    return bool(_ID_TYPE_RE.search(param_type or ""))


def _covers_access_control(endpoint: Endpoint) -> bool:
    """方法/类级权限注解或角色级中间件已覆盖访问控制 → 不报水平越权。"""
    auth = endpoint.auth
    if not auth.present:
        return False
    if auth.mechanism not in (AuthMechanism.ANNOTATION, AuthMechanism.MIDDLEWARE):
        return False
    return bool(_PERMISSION_HINT_RE.search(auth.role_or_perm or ""))


def recall_idor(endpoint: Endpoint, ctx, method_index=None,
                hierarchy=None) -> List[Candidate]:
    """规则 A：对端点 E 逐参数做标识判定 + 污点追踪 + 归属约束检查。

    method_index（Java 跨过程）：`{ClassName.methodName: ctx}` 全局方法体索引。
    hierarchy（Java 继承链）：`{类型名: [父类型]}`，用于接口→实现类/父类方法体解析。
    """
    out: List[Candidate] = []
    if is_public_auth_endpoint(endpoint):
        return out  # 登录/注册/验证码等认证流程：身份凭证是输入，不是资源引用
    if _covers_access_control(endpoint):
        return out
    for p in endpoint.params:
        if p.source not in (ParamSource.PATH, ParamSource.QUERY, ParamSource.BODY):
            continue
        if not is_resource_identifier(p.name, p.type):
            continue
        for access in trace_to_sinks(ctx.node, p.name, ctx, method_index, hierarchy):
            if access.ownership_predicate:
                continue  # 查询含 currentUser 归属约束 → 不是越权
            if _COLLECTION_RE.search(p.type or ""):
                access.flow.append("[批量] List 型 ID 参数（批量越权场景）")
            out.append(Candidate(endpoint=endpoint, access=access,
                                 subtype="A1", rule_id="A1-idor"))
    return out