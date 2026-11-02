"""L3 污点追踪（方案 §6.2）：把「来自客户端」的 ID 参数标记为污点，命中 DB/ORM
sink 即产出 ResourceAccess。

按 ctx.language 分派：
- **Java**：真数据流——`defuse.JavaFlow` 做局部赋值/别名前向传播，再沿调用链
  跨过程进入 Service/Repository 层，直到命中 DB sink（Repository/Mapper/JdbcTemplate
  等）或到达无法解析的外部方法；flow 记录真实调用链，归属约束在中间层也识别。
- **JavaScript / Go**：同样真数据流（CFG + def-use），各自识别客户端读取
  表达式（req.params/query/body.X、c.Param/Query("X")）为污点源，
  跨语句传播到 ORM/DB sink 调用。

归属约束判定（ownership_predicate）：D2 起只看「实参是否来自当前登录用户」
（getCurrentUser/principal/tokenUserInfo/req.user/session 用户属性/当前用户变量），
方法名含 user、SQL 出现 user_id 列都不再作为依据。
"""
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from ..ir import ResourceAccess
from .asts import call_arg_texts, call_full_text, call_name
from .defuse import JavaFlow, GoFlow, JsFlow

# ---------- 通用 ----------
# D2：归属约束只看「实参是否来自当前登录用户」，不再看方法名/列名。
_CURRENT_USER_RE = re.compile(
    r"(getCurrentUser|current[-_ ]?user|principal|SecurityContext"
    r"|authentication|loginUser|token[-_ ]?user[-_ ]?info|req\.user|request\.user)", re.I,
)
# session 仅当伴随「用户属性/取值」访问时才算当前用户来源；裸 session（如
# session.commit()/session.query(...)）太泛，会误判 ownership=True 导致漏报。
_SESSION_USER_RE = re.compile(
    r"(?:getSession\s*\(\s*\)\s*\.\s*(?:getAttribute|get)\s*\(|"
    r"session\s*\[\s*['\"]?\w+['\"]?\s*\]|"
    r"session\s*\.\s*(?:get|getAttribute)\s*\(|"
    r"session\s*\.\s*(?:user_?id|userI[dD]|uid|current_?user|currentUser|"
    r"account_?id|accountId|member_?id|memberId|user)\b)", re.I,
)
# 非资源查询的 get* 调用，避免被通用 sink 前缀误判
_NON_SINK_GET_RE = re.compile(r"getSession|getCurrentUser|getPrincipal|getAuthentication", re.I)
# 接收者类型未知时，只有强标识查询（findById/findByUsername/…）才当 sink
_STRONG_ID_LOOKUP_RE = re.compile(
    r"By(?:Id|Uuid|Guid|Code|No|Key|Username|Slug|Email|Title|OrderNo)\b", re.I)
# 新建资源的写操作（insert/create/save…）不是「访问他人已有资源」的 A1 sink
_CREATE_SINK_RE = re.compile(r"^(?:insert|create|save|add|post|append|upload)\w*$", re.I)
_SQL_FROM_RE = re.compile(r"\bfrom\s+([\w.]+)", re.I)
_ENTITY_SUFFIX_RE = re.compile(r"(ServiceImpl|serviceImpl|Service|Repository|Repo|Mapper|DAO|Dao|Gateway|Store|Model)$")

# ---------- 文件资源「读取」访问（路径来自客户端 → 读任意文件） ----------
# 只收读取语义：写入（FileOutputStream/FileWriter/File）不算越权读
_FILE_CTOR_RE = re.compile(r"^(?:FileInputStream|FileReader|RandomAccessFile)$")
# 方法型：Files.readAllBytes / FileUtils.readFileToString / IOUtils.copy（输入流来自污点）
_FILE_API_RE = re.compile(
    r"^(?:readAllBytes|readString|readAllLines|newInputStream|newBufferedReader|"
    r"readFileToByteArray|readFileToString|readLines|copyInputStreamToFile)$", re.I)
# 显式归属校验：obj.getUserId().equals(<当前用户>) / Objects.equals(obj.getOwnerId(), user)
_OWNER_GETTER_RE = re.compile(r"\.\s*get(?:UserId|OwnerId|CreatorId|Uid|UploaderId|TenantId)\s*\(\s*\)",
                              re.I)
_DENY_BRANCH_RE = re.compile(
    r"(?:throw\s+new|return\s+(?:Response|R|Result)\w*\.\w*ERROR|"
    # Spring 惯用的拒绝写法：return ResponseEntity.status(HttpStatus.FORBIDDEN)…
    # / return new ResponseEntity<>(HttpStatus.NOT_FOUND) / ResponseEntity.notFound()
    r"return\s+ResponseEntity\s*\.\s*(?:status|notFound|badRequest|unprocessableEntity)|"
    r"HttpStatus\s*\.\s*(?:FORBIDDEN|UNAUTHORIZED|NOT_FOUND|BAD_REQUEST|UNPROCESSABLE_ENTITY)|"
    r"return\s+new\s+ResponseEntity\s*[<(]|"
    r"return\s+false|throw\s+\w+Exception)", re.I)

# 原生 SQL 语句文本（跨语言通用数据访问信号）：调用实参含 SQL 即视为数据访问 sink，
# 不依赖方法名白名单/接收者类型，覆盖 PDO、node-postgres、psycopg2、Knex raw、
# JDBC 直连、`.Raw()/.nativeQuery()` 等「方法名不统一」的原生 driver 写法。
_SQL_TEXT_RE = re.compile(
    r"\bSELECT\b[\s\S]*?\bFROM\b|\bUPDATE\b[\s\S]*?\bSET\b|\bDELETE\s+FROM\b|\bINSERT\s+INTO\b",
    re.I,
)
# 数据访问接收者名（变量/对象名像 DAO）：企业自研基类与二次封装无法枚举方法名，
# 故放宽「方法名白名单」——接收者像 DAO 时不再要求方法名像查询。
# 分两类：
# 1) 独立词：db/conn/repo/dao/mapper/store/model/object/collection（db.query、conn.execute）；
# 2) 复合名后缀：以 Repo/Repository/Dao/Mapper 结尾的标识符（orderRepo/user_repo/orderDao/
#    UserRepository）。这些后缀几乎不出现在方法名里，可放心放宽；而 store/model/object/
#    collection 只在独立词形态放宽，避免 getModel()/saveToStore() 等方法名被误判。
_DAO_RECEIVER_RE = re.compile(
    r"(?i)(?:\b[a-z0-9_]+(?:repository|repo|dao|mapper)\b"
    r"|\b(?:db|conn|connection|cursor|repo|repository|dao|mapper|store|models?|objects?|collection)\b)"
)


def _text(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


# Go 的当前用户来自中间件注入的上下文：Gin `c.Get("uid")` / `c.GetInt64("uid")`
# / `c.MustGet`，Echo `c.Get("user")`、Fiber `c.Locals`、标准库 `ctx.Value`。
# c.Param("uid") 是客户端可控参数，明确排除。
_GO_CU_KEYS = (r"(?:uid|user_?id|userID|userId|current_?user|currentUser|sub|"
               r"tenant_?id|tenantID|account_?id|accountID|member_?id|memberID)")
_GO_CU_READ_RE = re.compile(
    rf"\.(?:Get\w*|MustGet|Locals|Value)\s*\(\s*[\"`]{_GO_CU_KEYS}[\"`]", re.I)
_GO_CU_ASSIGN_RE = re.compile(
    rf"(\w+)\s*(?:,\s*\w+)?\s*:?=\s*[^\n=]*\.(?:Get\w*|MustGet|Locals|Value)\s*\(\s*[\"`]"
    rf"{_GO_CU_KEYS}[\"`]", re.I)


def is_current_user_expr(text: str) -> bool:
    """判定表达式是否来自「当前登录用户」来源。"""
    return bool(_CURRENT_USER_RE.search(text) or _SESSION_USER_RE.search(text)
                or _GO_CU_READ_RE.search(text))


def _go_current_user_vars(ctx: Any) -> Set[str]:
    """Go handler 内「从上下文取当前用户」的局部变量（uid / userID / …）。"""
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return set()
    text = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])
    return {m.group(1) for m in _GO_CU_ASSIGN_RE.finditer(text)}


def _balanced(text: str, open_pos: int) -> str:
    """取 text[open_pos] 处 '(' 的平衡括号内容（不含外层括号）。"""
    if open_pos < 0 or open_pos >= len(text) or text[open_pos] != "(":
        return ""
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i]
    return text[open_pos + 1:]


_OWNER_OBJ_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\.\s*get(?:UserId|OwnerId|CreatorId|Uid|UploaderId|TenantId)\s*\(")

# 读取「父引用」的 getter：comment.getVideoId() / item.getOrderNo() 之类。
# 用于识别「子资源绑定到父资源」的显式校验（父子绑定），不限于具体字段名。
_BIND_FIELD_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\.\s*get\w*(?:Id|Uid|No|Code|Key|Sn)\s*\(\s*\)")

# 带联合条件的仓储方法调用：deleteByIdAndVideoId(cid, id) / findByPostIdAndUserId(...)
_AND_CALL_RE = re.compile(r"\.\s*(\w*[Aa]nd\w*)\s*\(([^()]*)\)")


def _java_method_params(node: Any) -> List[str]:
    """方法形参名（用于把归属校验归属到具体参数）。"""
    out: List[str] = []
    if node is None or not hasattr(node, "child_by_field_name"):
        return out
    params = node.child_by_field_name("parameters")
    for p in (params.named_children if params is not None else []):
        if p.type not in ("formal_parameter", "spread_parameter"):
            continue
        name = p.child_by_field_name("name")
        if name is not None:
            out.append(_text(name))
    return out


def _java_bound_params(text: str, param_names: Iterable[str],
                       verified: set) -> set:
    """子资源绑定到已校验父资源的形参（父子绑定，通用）。

    两类证据：
    1. 显式字段绑定：`c = svc.findById(cid); if (!c.getVideoId().equals(id)) throw`
       且 `id` 已被归属校验覆盖 → `cid` 被父资源限定，视为已覆盖。
    2. 联合条件仓储方法：`repo.deleteByIdAndVideoId(cid, id)`，`id` 已验证 →
       方法名 `*And*` 表明两个条件同时成立，`cid` 被父资源限定。
    """
    names = set(param_names)
    out: set = set()
    edges: dict = {}
    for m in re.finditer(r"\bif\s*\(", text):
        cond = _balanced(text, text.find("(", m.start()))
        if not cond:
            continue
        if is_current_user_expr(cond) or _refs_current_user(cond, ()):
            continue
        objs = {om.group(1) for om in _BIND_FIELD_RE.finditer(cond)}
        if not objs:
            continue
        tail = text[text.find("(", m.start()) + len(cond) + 2:][:240]
        if not _DENY_BRANCH_RE.search(tail):
            continue
        parents = {p for p in names if re.search(rf"\b{re.escape(p)}\b", cond)}
        if not parents:
            continue
        for obj in objs:
            assign = None
            for am in re.finditer(rf"\b{re.escape(obj)}\s*=(?!=)\s*([^;\n]+)",
                                  text[:m.start()]):
                assign = am
            if assign is None:
                continue
            for child in names:
                if re.search(rf"\b{re.escape(child)}\b", assign.group(1)):
                    edges.setdefault(child, set()).update(parents)
    for child, parents in edges.items():
        if parents & verified:
            out.add(child)
    for m in _AND_CALL_RE.finditer(text):
        args = [a.strip() for a in m.group(2).split(",")]
        idents = [a for a in args if re.fullmatch(r"[A-Za-z_]\w*", a or "")]
        if len(idents) < 2 or not (set(idents) & verified):
            continue
        for a in idents:
            if a in names and a not in verified:
                out.add(a)
    return out


def _java_ownership_scope(ctx: Any, cu_vars: Iterable[str] = ()):
    """显式归属校验覆盖了哪些形参。

    返回 `(是否存在校验, 覆盖的形参集合)`；集合为 `None` 表示校验对象不是由某个形参
    加载的（如 `x = currentUser.getX()` / 无从归属），此时按「覆盖全部」处理，避免误报。
    典型：`v = svc.findById(id); if (!v.getUserId().equals(当前用户)) throw` → 只覆盖 `id`；
    同一 handler 里删/改另一个对象（`cid`）不受该校验保护（跨对象越权）。
    """
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return False, set()
    start, end = node.start_point[0], node.end_point[0]
    text = "\n".join(lines[start:end + 1])
    param_names = _java_method_params(node)
    covered: set = set()
    unattributed = False
    found = False
    for m in re.finditer(r"\bif\s*\(", text):
        cond = _balanced(text, text.find("(", m.start()))
        if not cond:
            continue
        if not _OWNER_GETTER_RE.search(cond):
            continue
        if not (is_current_user_expr(cond) or _refs_current_user(cond, cu_vars)):
            continue
        tail = text[text.find("(", m.start()) + len(cond) + 2:][:240]
        if not _DENY_BRANCH_RE.search(tail):
            continue
        found = True
        objs = [om.group(1) for om in _OWNER_OBJ_RE.finditer(cond)]
        if not objs:
            unattributed = True  # 比较对象不是 getter 形态，无法归属到参数
            continue
        for obj in objs:
            assign = None
            for am in re.finditer(rf"\b{re.escape(obj)}\s*=(?!=)\s*([^;\n]+)", text[:m.start()]):
                assign = am
            if assign is None:
                unattributed = True  # 对象不是本方法内由调用加载（字段/会话），无法归属
                continue
            expr = assign.group(1)
            ps = {p for p in param_names
                  if re.search(rf"\b{re.escape(p)}\b", expr)}
            if ps:
                covered |= ps
            else:
                unattributed = True
    if not found:
        return False, set()
    if unattributed:
        return True, None
    if covered:
        # 父子绑定闭包：子资源字段/联合查询绑定到已校验的父参数时，子参数一并视为已覆盖
        covered |= _java_bound_params(text, param_names, covered)
    return True, covered


def java_explicit_ownership(ctx: Any, cu_vars: Iterable[str] = (),
                            param_name: str = "") -> bool:
    """handler 内是否有「显式归属校验」，且是否覆盖给定参数。

    通用形态（不依赖具体命名）：`x.getUserId().equals(currentUser...)` /
    `Objects.equals(x.getOwnerId(), <当前用户>)` / `x.getCreatorId() != <当前用户>`，
    且同一 if 条件块内 throw / 返回错误。

    比较对象可以是「直接会话表达式」，也可以是局部变量（`uid = session.getAttribute(..)`
    之后再 `x.getUserId().equals(uid)`）——由调用方传入 cu_vars 传递闭包。

    `param_name` 非空时按参数维度判定：仅当被校验对象由该形参加载（`v = svc.findById(id)`）
    时才算该参数已有归属约束。这样「校验视频归属、删除评论」不会把评论 id 一并豁免。
    """
    found, scope = _java_ownership_scope(ctx, cu_vars)
    if not found:
        return False
    if not param_name or scope is None:
        return True
    return param_name in scope


def has_sql_text(node: Any) -> bool:
    """调用是否携带原生 SQL 语句文本（通用数据访问信号，不依赖方法名/接收者类型）。"""
    return bool(_SQL_TEXT_RE.search(_text(node)))


def is_dao_receiver(text: str) -> bool:
    """调用接收者（链式文本）是否像数据访问对象——自研基类/二次封装的方法名兜底放宽。"""
    return bool(_DAO_RECEIVER_RE.search(text or ""))


def _ownership_in_text(args_text: str, current_user_vars: Iterable[str] = ()) -> bool:
    """D2：只有「实参来自当前登录用户」才算归属约束。

    方法名含 user（getUserAllSeries）、SQL 出现 user_id 列、ORM where 里写 userId
    都不能证明绑定的是当前用户——客户端可控 userId 照样能越权，因此不再作为依据。
    """
    if is_current_user_expr(args_text):
        return True
    for var in current_user_vars:
        if var and re.search(rf"\b{re.escape(var)}\b", args_text or ""):
            return True
    return False


def _entity_from_sql(call: Any) -> Optional[str]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for a in args.named_children:
        t = _text(a)
        m = _SQL_FROM_RE.search(t)
        if m:
            return m.group(1).split(".")[-1]
    return None


def _mk_access(ctx: Any, param_name: str, mname: str, entity: str,
               ownership: bool, call: Any, chain: str = "",
               slices: Optional[List[Dict[str, Any]]] = None) -> ResourceAccess:
    line = call.start_point[0] + 1
    line_text = ctx.lines[line - 1].strip() if ctx.lines and 0 < line <= len(ctx.lines) else ""
    flow = [f"{param_name} -> {chain or mname} -> {entity}"]
    return ResourceAccess(
        entity=entity, identifier_param=param_name, flow=flow,
        ownership_predicate=ownership,
        sink_snippet=f"{ctx.file}:{line}: {line_text}", sink_line=line,
        chain_slices=slices or [],
    )


# 方法体源码切片行数上限（避免跨过程切片导致 prompt 膨胀）
_MAX_SLICE_LINES = 60


def _method_slice(ctx: Any, label: str) -> Dict[str, Any]:
    """摘取跨过程目标方法体源码切片（调用链上真实 API 代码，供 LLM 核验归属约束）。

    ctx 为 method_index 中的目标方法上下文（node=method_declaration，lines=文件全行）。
    超过 _MAX_SLICE_LINES 行则截断并标记，避免深方法体撑爆证据包。
    """
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", [])
    if node is None or not lines:
        return {"call": label, "file": getattr(ctx, "file", ""),
                "line_start": 0, "line_end": 0, "code": "", "truncated": False}
    start = node.start_point[0]
    end = node.end_point[0]
    body = lines[start:end + 1]
    truncated = len(body) > _MAX_SLICE_LINES
    if truncated:
        body = body[:_MAX_SLICE_LINES]
    return {
        "call": label,
        "file": getattr(ctx, "file", ""),
        "line_start": start + 1,
        "line_end": start + len(body),
        "code": "\n".join(s.rstrip() for s in body),
        "truncated": truncated,
    }


# ---------- Java：真数据流（def-use + 跨过程） ----------
_SINK_CALL_RE = re.compile(
    r"^(find|get|load|select|query|read|search|fetch|retrieve)(by|all|one|list|page|first|last|for)?\w*$",
    re.I,
)
_SQL_CALLS = {"query", "queryforobject", "queryforlist", "queryformap", "execute", "update"}
_DB_TYPE_RE = re.compile(
    r"(Repository|Mapper|Dao|DAO|JdbcTemplate|NamedParameterJdbcTemplate|SqlSession|EntityManager)")
_SERVICE_TYPE_RE = re.compile(r"(Service|ServiceImpl|Manager|Facade)")
_MAX_DEPTH = 12


def is_sink_call(name: str) -> bool:
    n = name.lower()
    if n in {"getbyid", "findbyid", "getone", "findone", "findbypk", "selectbyid",
             "selectbyprimarykey", "selectone", "querybyid"}:
        return True
    if _NON_SINK_GET_RE.search(n):
        return False
    if _CURRENT_USER_RE.search(n):
        return False
    return bool(_SINK_CALL_RE.match(n))


def _join_chain(segments: List[str]) -> str:
    """拼接污点链文本，折叠相邻重复段（跨过程重启链路时会出现重复实体）。"""
    out: List[str] = []
    for s in segments:
        if not out or out[-1] != s:
            out.append(s)
    return " -> ".join(out)


def _receiver_type(call: Any, ctx: Any) -> str:
    obj = call.child_by_field_name("object")
    if obj is None:
        return ""
    name = _text(obj).split(".")[-1]
    return ctx.fields.get(name, "")


def _formal_params(method_node: Any) -> List[str]:
    params_node = method_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    out: List[str] = []
    for fp in params_node.named_children:
        if fp.type in ("formal_parameter", "spread_parameter"):
            name_node = fp.child_by_field_name("name")
            if name_node is not None:
                out.append(_text(name_node))
    return out


def _trace_java(method_node: Any, param_name: str, ctx: Any,
                method_index=None, hierarchy=None) -> List[ResourceAccess]:
    results: List[ResourceAccess] = []
    # @RequestBody DTO 拆包出的字段参数：承载它的形参也是污点源（request.getDocId()）
    sources = {param_name}
    alias = (getattr(ctx, "body_aliases", None) or {}).get(param_name)
    if alias:
        sources.add(alias)
    flow = JavaFlow(method_node, sources).analyze()
    cu_vars = _java_current_user_vars(ctx)
    # 显式归属校验（归属字段 vs 当前用户[或会话派生变量] + 拒绝分支）→ 整条链路视为已有归属约束
    ownership_ok = java_explicit_ownership(ctx, cu_vars, param_name)
    for call, tainted_idxs in flow.calls:
        _chase(call, tainted_idxs, param_name, ctx, method_index, results, [],
               [], ownership_ok, [], cu_vars, hierarchy)
    # 同一次数据访问可能经包装透传与跨过程两条路径重复产出 → 按 sink 位置+污点链去重
    seen = set()
    out: List[ResourceAccess] = []
    for r in results:
        key = (r.sink_line, tuple(r.flow))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


_ASSIGN_RE = re.compile(r"(\w+)\s*=(?!=)\s*([^;\n]+)")
# 任意对象的 setter 调用（实参由 _balanced 按括号平衡截取，支持嵌套调用）
_SETTER_CALL_RE = re.compile(r"(\w+)\s*\.\s*(?:set|with)[A-Z]\w*\s*\(")
# 字段赋值：query.userId = <当前用户>
_FIELD_ASSIGN_RE = re.compile(r"(\w+)\s*\.\s*\w+\s*=(?!=)\s*([^;\n]+)")


def _java_current_user_vars(ctx: Any) -> set:
    """handler 内「绑定当前登录用户」的变量集合。

    两类通用形态（与具体命名无关）：
    - 局部变量赋值：`uid = tokenUserInfoDto.getUserId()`；
    - 对象 setter 写入：`comment.setUserId(tokenUserInfoDto.getUserId())` → comment 归属已绑定当前用户。
    后者用于识别「创建/写入时归属来自会话」的场景（避免把正常发帖误判为越权）。
    """
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return set()
    start, end = node.start_point[0], node.end_point[0]
    text = "\n".join(lines[start:end + 1])
    out = set()
    for m in _ASSIGN_RE.finditer(text):
        if is_current_user_expr(m.group(2)):
            out.add(m.group(1))
    # 传递闭包：对象/变量写入「已知当前用户变量」也算绑定当前用户
    # （uid = tokenUserInfo.getUserId(); query.setUserId(uid)）
    pending = True
    while pending:
        pending = False
        # 对象 setter 写入当前用户：obj.setUserId(<当前用户>)
        # 实参可能含嵌套调用（getUserId()），必须按平衡括号取整个实参文本
        for m in _SETTER_CALL_RE.finditer(text):
            obj = m.group(1)
            if obj in out:
                continue
            arg = _balanced(text, text.find("(", m.end() - 1))
            if _refs_current_user(arg, out):
                out.add(obj)
                pending = True
        # 对象字段赋值：query.userId = <当前用户>
        for m in _FIELD_ASSIGN_RE.finditer(text):
            if m.group(1) not in out and _refs_current_user(m.group(2), out):
                out.add(m.group(1))
                pending = True
    return out


def _refs_current_user(expr: str, cu_vars: Iterable[str]) -> bool:
    """表达式是否直接是当前用户来源，或引用了已知的当前用户变量。"""
    if is_current_user_expr(expr):
        return True
    return any(re.search(rf"\b{re.escape(v)}\b", expr or "") for v in cu_vars if v)


def _nested_method_calls(node: Any):
    """遍历调用节点内部的嵌套方法调用（如 getSuccessResponseVO(svc.findById(id))）。"""
    for ch in node.named_children:
        if ch.type == "method_invocation":
            yield ch
        yield from _nested_method_calls(ch)


def _arg_idxs_with(call: Any, param_name: str) -> List[int]:
    args = call.child_by_field_name("arguments")
    out: List[int] = []
    if args is None:
        return out
    rx = re.compile(rf"\b{re.escape(param_name)}\b")
    for i, a in enumerate(args.named_children):
        if rx.search(_text(a)):
            out.append(i)
    return out


def _own_method_names(ctx: Any) -> set:
    """当前类中定义的方法名集合（缓存）。

    通用判定依据：调用目标是「本类自身方法」时，它是内部辅助/包装方法，不是
    数据访问 sink（响应包装 getSuccessResponseVO、本地 readFile 等都属此类），
    无需依赖具体方法名黑名单。
    """
    cached = getattr(ctx, "_own_methods", None)
    if cached is not None:
        return cached
    names: set = set()
    cn = getattr(ctx, "class_node", None)
    body = cn.child_by_field_name("body") if cn is not None else None
    if body is not None:
        for m in body.named_children:
            if m.type == "method_declaration":
                n = m.child_by_field_name("name")
                if n is not None:
                    names.add(_text(n))
    try:
        ctx._own_methods = names
    except Exception:
        pass
    return names


def _is_local_call(call: Any, ctx: Any) -> bool:
    """调用是否指向本类方法（无接收者或 this 接收者）。"""
    obj = call.child_by_field_name("object")
    if obj is not None and _text(obj).strip() not in ("", "this"):
        return False
    return (call_name(call) or "") in _own_method_names(ctx)


def _ctx_class_name(ctx: Any) -> str:
    cn = getattr(ctx, "class_node", None)
    if cn is None:
        return ""
    n = cn.child_by_field_name("name")
    return _text(n) if n is not None else ""


def _resolve_java_target(method_index, rtype: str, mname: str, hierarchy=None):
    """D6 + 继承链：从调用点接收者类型解析到真正的方法体。

    解析顺序（命中即返回）：
    1. 同名类型（`UserService.get`）；
    2. 命名约定 `UserService` → `UserServiceImpl`（无继承事实时的兜底）；
    3. 继承链向下：接口/抽象父类的子类实现（`BaseService` → `VideoServiceImpl`）；
    4. 继承链向上：子类未覆写时取父类方法体（`ChildController.load` → `BaseController.load`）。
    """
    if method_index is None:
        return None, None
    for key in (f"{rtype}.{mname}", f"{rtype}Impl.{mname}"):
        if key in method_index:
            return key, method_index[key]
    if not hierarchy:
        return None, None
    for t in hierarchy.descendants_of(rtype) + hierarchy.ancestors_of(rtype):
        key = f"{t}.{mname}"
        if key in method_index:
            return key, method_index[key]
    return None, None


def _chase(call: Any, tainted_idxs: List[int], param_name: str, ctx: Any,
           method_index, results: List[ResourceAccess], stack: List[str],
           chain: List[str], inherited_ownership: bool,
           slices: List[Dict[str, Any]], cu_vars: set = frozenset(),
           hierarchy=None):
    mname = call_name(call) or ""
    rtype = _receiver_type(call, ctx)
    receiver = _text(call.child_by_field_name("object") or "").strip()[:60] or "?"
    args_text = call_arg_texts(call)
    cur_ownership = inherited_ownership or _ownership_in_text(args_text, cu_vars)
    new_chain = chain + [f"{receiver}.{mname}"]

    # 通用：外层调用（本类包装/透传）的实参里若有真实数据访问调用，先递归追踪。
    # 例：wrap(svc.findById(id)) 中 wrap 本身不是 sink，但内层 findById 是。
    if _is_local_call(call, ctx):
        for sub in _nested_method_calls(call):
            idxs = _arg_idxs_with(sub, param_name)
            if idxs:
                _chase(sub, idxs, param_name, ctx, method_index, results,
                       stack, chain, cur_ownership, slices, cu_vars, hierarchy)

    # 尝试跨过程：接收者是 Service 且能解析到方法体（D6：接口 → Impl）
    target = None
    key = ""
    obj_node = call.child_by_field_name("object")
    cross_type = rtype
    if not cross_type and (obj_node is None or _text(obj_node).strip() in ("", "this")):
        cross_type = _ctx_class_name(ctx)  # D6：this/同类方法分发（ServiceImpl 内部 helper）
    if method_index is not None and cross_type and (
            _SERVICE_TYPE_RE.search(cross_type) or cross_type == _ctx_class_name(ctx)
            or (hierarchy and hierarchy.related_types(cross_type))):
        key, target = _resolve_java_target(method_index, cross_type, mname, hierarchy)
        if target is not None and key in stack:
            target = None
    if target is not None:
        # 进入目标方法体之前，先把实参里的真实调用走一遍：
        # `getSuccessResponseVO(svc.find(id))` 这类包装方法的实参本身带污点调用，
        # 进了包装方法体就看不到内层 sink（父类包装方法尤其常见）。
        for sub in _nested_method_calls(call):
            idxs = _arg_idxs_with(sub, param_name)
            if idxs:
                _chase(sub, idxs, param_name, ctx, method_index, results,
                       stack, chain, cur_ownership, slices, cu_vars, hierarchy)
        params = _formal_params(target.node)
        args = call.child_by_field_name("arguments")
        sources: set = set()
        if args is not None:
            arg_nodes = args.named_children
            for idx in tainted_idxs:
                if idx < len(params):
                    sources.add(params[idx])
        if sources and len(stack) < _MAX_DEPTH:
            next_slices = slices + [_method_slice(target, key)]  # 记录真实方法体源码
            sub = JavaFlow(target.node, sources).analyze()
            for c2, idx2 in sub.calls:
                _chase(c2, idx2, param_name, target, method_index, results,
                       stack + [key], new_chain, cur_ownership, next_slices, cu_vars,
                       hierarchy)
        return  # 已进入 Service 层，不在此层产出

    # 无法跨过程 → 判断是否产出 sink
    local = _is_local_call(call, ctx)  # 本类自身方法：内部辅助/包装，不是数据 sink
    sql_here = has_sql_text(call)  # 原生 SQL 文本 → 数据访问 sink（不依赖方法名/接收者类型）
    file_here = bool(_FILE_CTOR_RE.match(mname) or _FILE_API_RE.match(mname))
    if file_here and tainted_idxs:
        # 文件资源访问：路径由客户端可控参数构造（new FileInputStream(x) / Files.readAllBytes(x)）
        entity = "File"
        flow_str = _join_chain(new_chain)  # 实体名由 _mk_access 统一追加，避免重复
        results.append(_mk_access(ctx, param_name, flow_str, entity, cur_ownership,
                                  call, chain=flow_str, slices=slices))
        return
    if local and not sql_here:
        emit = False
    elif sql_here:
        emit = True
    elif _DB_TYPE_RE.search(rtype):
        # 新建（insert/create/save）不是越权读取已有资源；IDOR 只关注按 id 的读写删
        emit = not _CREATE_SINK_RE.search(mname)
    elif _SERVICE_TYPE_RE.search(rtype):
        # Service 但解析不到方法体：仅方法名像资源查询（find/get/select…）才产出，
        # 否则 exists/validate/process 等非资源 Service 方法会被误当 sink。
        emit = is_sink_call(mname)
    else:
        # 接收者类型未知：只有强标识查询（findById/…）或接收者像 DAO 才产出
        emit = ((is_sink_call(mname) and _STRONG_ID_LOOKUP_RE.search(mname))
                or is_dao_receiver(receiver) or is_dao_receiver(rtype))

    if not emit:
        # 包装/辅助调用本身不是 sink，但其参数里的真实 DAO 调用仍要追踪
        if local or is_sink_call(mname):
            for sub in _nested_method_calls(call):
                idxs = _arg_idxs_with(sub, param_name)
                if idxs:
                    _chase(sub, idxs, param_name, ctx, method_index, results,
                           stack, chain, cur_ownership, slices, cu_vars, hierarchy)
        return
    sql = _text(call) if (mname.lower() in _SQL_CALLS or sql_here) else ""
    if sql:
        cur_ownership = cur_ownership or _ownership_in_text(args_text, cu_vars)
    entity = _entity_from_sql(call) if sql else _java_entity(call, ctx)
    flow_str = " -> ".join(new_chain)
    results.append(_mk_access(ctx, param_name, flow_str, entity, cur_ownership,
                              call, chain=flow_str, slices=slices))


def _java_entity(call: Any, ctx: Any) -> str:
    obj = call.child_by_field_name("object")
    if obj is not None:
        name = _text(obj).split(".")[-1]
        ftype = ctx.fields.get(name, "")
        if ftype:
            return _ENTITY_SUFFIX_RE.sub("", ftype)
    cls_name = _text(ctx.class_node.child_by_field_name("name") or "")
    return _ENTITY_SUFFIX_RE.sub("", re.sub(r"Controller$", "", cls_name))


# ---------- JavaScript（Express + Prisma/Sequelize） ----------
_JS_SINKS = {"findunique", "findfirst", "findmany", "findbypk", "findbyid",
             "findone", "find", "findall", "findoneby", "get", "getbyid", "queryone",
             "destroy", "delete", "remove", "deleteone", "removeone"}


def _js_formal_params(fn_node: Any) -> List[str]:
    """提取 JS 函数/方法形参名（跨过程进入方法体后，实参索引对齐形参）。"""
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        return []
    names: List[str] = []
    for p in params.named_children:
        name = None
        if p.type == "identifier":
            name = _text(p)
        elif p.type in ("required_parameter", "optional_parameter"):
            pat = p.child_by_field_name("pattern") or p.child_by_field_name("name")
            name = _text(pat) if pat is not None else None
        elif p.type in ("assignment_pattern", "rest_pattern"):
            for ch in p.named_children:
                if ch.type == "identifier":
                    name = _text(ch)
                    break
        if name:
            names.append(name)
    return names


# JS/TS handler 内「把当前用户存进局部变量」的写法：
#   const uid = req.session.userId;  const me = req.user;  let userId = req.user.id;
_JS_CU_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?[^\n;]*(?:req|request)\s*\.\s*"
    r"(?:session\s*\.\s*(?:user_?id|userI[dD]|uid|current_?user|currentUser|user|"
    r"account_?id|accountId|member_?id|memberId)"
    r"|user\b|userId\b|currentUser\b)", re.I)


def _js_current_user_vars(ctx: Any) -> Set[str]:
    """JS/TS handler 内「当前登录用户」局部变量（uid / userId / me …）。"""
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return set()
    text = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])
    return {m.group(1) for m in _JS_CU_ASSIGN_RE.finditer(text)}


def _node_chase(call: Any, tainted_idxs: List[int], param_name: str, ctx: Any,
                method_index, results: List[ResourceAccess], stack: List[str],
                chain: List[str], inherited_ownership: bool,
                slices: List[Dict[str, Any]], cu_vars: Set[str] = frozenset()):
    """JavaScript 跨过程追踪：同名方法在 method_index 优先进入，否则 sink 产出。"""
    mname = call_name(call) or ""
    args_text = call_arg_texts(call)
    cur_ownership = inherited_ownership or _ownership_in_text(args_text, cu_vars)
    chain_str = call_full_text(call) or mname
    new_chain = chain + [chain_str]
    # 放宽：方法名白名单 或 接收者像 DAO（自研基类）或 实参含原生 SQL 文本
    is_sink = mname.lower() in _JS_SINKS or is_dao_receiver(chain_str) or has_sql_text(call)

    # 优先跨过程（同名方法可能既是 Service 方法又是 sink 名，先进入真实方法体）
    if method_index is not None and mname and mname not in stack and mname in method_index:
        target = method_index[mname]
        if getattr(target, "node", None) is not None:
            params = _js_formal_params(target.node)
            args = call.child_by_field_name("arguments")
            sources: set = set()
            if args is not None:
                for idx in tainted_idxs:
                    if idx < len(params):
                        sources.add(params[idx])
            if sources and len(stack) < _MAX_DEPTH:
                next_slices = slices + [_method_slice(target, mname)]
                sub = JsFlow(target.node, param_name, sources=sources).analyze()
                for c2, idx2 in sub.calls:
                    _node_chase(c2, idx2, param_name, target, method_index, results,
                                stack + [mname], new_chain, cur_ownership, next_slices, cu_vars)
            return

    if not is_sink:
        return
    entity = _js_entity(call)
    results.append(_mk_access(ctx, param_name, chain_str or mname, entity,
                              cur_ownership, call, chain=chain_str, slices=slices))


def _trace_node(fn_node: Any, param_name: str, ctx: Any,
                method_index=None) -> List[ResourceAccess]:
    """JavaScript：真数据流——req.params/query/body.<param> → 赋值别名 → sink 调用（可跨过程）。"""
    results: List[ResourceAccess] = []
    cu_vars = _js_current_user_vars(ctx)
    flow = JsFlow(fn_node, param_name).analyze()
    for call, tainted_idxs in flow.calls:
        _node_chase(call, tainted_idxs, param_name, ctx, method_index, results,
                    [], [], False, [], cu_vars)
    return results


def _js_entity(call: Any) -> str:
    chain = call_full_text(call)
    parts = [p for p in re.split(r"[.\s]", chain) if p]
    if not parts:
        return "Resource"
    first = parts[0]
    if first.lower() in {"prisma", "models", "db", "sequelize", "mongoose"} and len(parts) > 1:
        first = parts[1]  # prisma.user.findUnique → user
    cand = _ENTITY_SUFFIX_RE.sub("", first)
    return cand[0].upper() + cand[1:] if cand and cand[0].islower() else (cand or "Resource")


# ---------- Go（Gin + database/sql / GORM） ----------
_GO_SINKS = {"query", "queryrow", "querycontext", "queryx", "first", "find",
             "findbyid", "take", "gets", "get", "select", "exec",
             # GORM 的写入口（IDOR 修改/删除形态：Where("id = ?", body.ID).Delete/Updates）
             "save", "create", "insert", "update", "updates", "delete", "deletebyid",
             # GORM 条件构造：客户端可控值进入 WHERE 即视为数据访问点
             "where"}
# 归属字段/取值器（Go 惯用大驼峰：order.UserID / o.GetOwnerID()）
_GO_OWNER_REF_RE = re.compile(
    r"\.(?:User|Owner|Creator|Uploader|Author|Account|Member|Tenant|Customer)_?ID\b"
    r"|\.(?:Get)?(?:User|Owner|Creator|Uploader|Author|Tenant)ID\s*\(\s*\)", re.I)
# 拒绝分支：Go/Echo/Gin/Fiber 的 401/403 写法
_GO_DENY_RE = re.compile(
    r"(?:StatusForbidden|StatusUnauthorized|ErrForbidden|ErrUnauthorized|"
    r"NewHTTPError\s*\(\s*http\.Status(?:Forbidden|Unauthorized)|"
    r"AbortWithStatus\w*\s*\(\s*[^)]*(?:401|403|Forbidden|Unauthorized)|"
    r"Abort\s*\(\s*(?:401|403)|SendStatus\s*\(\s*(?:401|403))", re.I)


def _go_explicit_ownership(ctx: Any, cu_vars: Iterable[str] = ()) -> bool:
    """Go handler 内显式归属校验：`if o.UserID != uid { return 403 }` 形态。

    条件里必须有「归属字段/取值器」与「当前用户」（上下文读取或 cu_vars 变量），
    且同块内有 401/403 拒绝 → 整条链路的归属约束成立。
    """
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return False
    text = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])
    # Go 的 if 条件不带括号：取 `if` 到第一个 `{` 之间的文本作为条件
    for m in re.finditer(r"\bif\b", text):
        cond = text[m.end():m.end() + 300].split("{", 1)[0]
        if not cond or not _GO_OWNER_REF_RE.search(cond):
            continue
        if not (is_current_user_expr(cond) or _refs_current_user(cond, cu_vars)):
            continue
        if _GO_DENY_RE.search(text[m.start():m.start() + 500]):
            return True
    return False


def _go_formal_params(fn_node: Any) -> List[str]:
    """提取 Go 函数/方法形参名（receiver 不在 parameters 字段，天然对齐实参索引）。"""
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        return []
    names: List[str] = []
    for p in params.named_children:
        if p.type == "parameter_declaration":
            n = p.child_by_field_name("name")
            if n is not None:
                names.append(_text(n))
    return names


def _go_chase(call: Any, tainted_idxs: List[int], param_name: str, ctx: Any,
              method_index, results: List[ResourceAccess], stack: List[str],
              chain: List[str], inherited_ownership: bool,
              slices: List[Dict[str, Any]], cu_vars: Set[str] = frozenset()):
    """Go 跨过程追踪：同名方法在 method_index 优先进入，否则 sink 产出。"""
    mname = call_name(call) or ""
    args_text = call_arg_texts(call)
    cur_ownership = inherited_ownership or _ownership_in_text(args_text, cu_vars)
    chain_str = call_full_text(call) or mname
    new_chain = chain + [chain_str]
    # 放宽：方法名白名单 或 接收者像 DAO（自研基类）或 实参含原生 SQL 文本
    is_sink = mname.lower() in _GO_SINKS or is_dao_receiver(chain_str) or has_sql_text(call)

    args = call.child_by_field_name("arguments")
    arg_nodes = args.named_children if args is not None else []
    if method_index is not None and mname and mname not in stack and mname in method_index:
        target = method_index[mname]
        if getattr(target, "node", None) is not None:
            params = _go_formal_params(target.node)
            sources: set = set()
            for idx in tainted_idxs:
                if idx < len(params):
                    sources.add(params[idx])
            # 当前用户随实参传入子函数（repo.GetByIDAndUser(id, uid) → 子函数 uid 也属当前用户）
            sub_cu = set(cu_vars)
            for idx, a in enumerate(arg_nodes):
                if idx >= len(params):
                    break
                atext = _text(a).strip()
                if is_current_user_expr(atext) or atext in cu_vars:
                    sub_cu.add(params[idx])
            if sources and len(stack) < _MAX_DEPTH:
                next_slices = slices + [_method_slice(target, mname)]
                sub = GoFlow(target.node, param_name, sources=sources).analyze()
                for c2, idx2 in sub.calls:
                    _go_chase(c2, idx2, param_name, target, method_index, results,
                              stack + [mname], new_chain, cur_ownership, next_slices, sub_cu)
            return

    if not is_sink:
        return
    full = _text(call)
    sql = full if (_SQL_FROM_RE.search(full) or has_sql_text(call)) else ""
    ownership = cur_ownership or _ownership_in_text(full, cu_vars)
    entity = _entity_from_sql(call) if sql else _go_entity(call, full)
    results.append(_mk_access(ctx, param_name, chain_str or mname, entity,
                              ownership, call, chain=chain_str, slices=slices))


def _go_dto_vars(ctx: Any) -> Set[str]:
    """Handler 里通过 `c.ShouldBind*(&x)` 绑定的 DTO 变量（定义在 `var x T` / `x := T{}`）。"""
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return set()
    text = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])
    out: Set[str] = set()
    for m in re.finditer(r"(?:ShouldBind\w*|Bind\w*)\s*\(\s*&\s*(\w+)", text):
        name = m.group(1)
        if (re.search(rf"\bvar\s+{re.escape(name)}\s+[\w.]+", text)
                or re.search(rf"\b{re.escape(name)}\s*:=\s*[\w.]+\s*\{{\s*\}}", text)):
            out.add(name)
    return out


def _go_direct_source(ctx: Any, param_name: str) -> bool:
    """param 是否被 `c.Param/Query/...("param")` 直接读取（否则来自 DTO 字段）。"""
    node = getattr(ctx, "node", None)
    lines = getattr(ctx, "lines", None) or []
    if node is None or not lines:
        return False
    text = "\n".join(lines[node.start_point[0]:node.end_point[0] + 1])
    return bool(re.search(
        r"c\.(?:Param|Query|QueryParam|DefaultQuery|PostForm|FormValue|DefaultPostForm)"
        rf"\(\s*[\"`]{re.escape(param_name)}[\"`]", text))


def _trace_go(fn_node: Any, param_name: str, ctx: Any,
              method_index=None) -> List[ResourceAccess]:
    """Go：真数据流——c.Param/Query/PostForm/QueryParam("param") → 别名 → sink（可跨过程）。

    DTO 场景：`c.ShouldBindJSON(&req)` 的字段作为 body 参数时，handler 里没有
    `c.Query("param")` 这样的直接读取，改为把绑定变量整体作为污点源（过近似），
    否则 body 里的资源标识（`setUserInfo` 的 id）永远到不了 sink。
    """
    results: List[ResourceAccess] = []
    cu_vars = _go_current_user_vars(ctx)
    inherited = _go_explicit_ownership(ctx, cu_vars)
    dto = _go_dto_vars(ctx)
    sources = dto if (dto and not _go_direct_source(ctx, param_name)) else None
    flow = GoFlow(fn_node, param_name, sources=sources).analyze()
    for call, tainted_idxs in flow.calls:
        _go_chase(call, tainted_idxs, param_name, ctx, method_index, results,
                  [], [], inherited, [], cu_vars)
    return results


def _go_entity(call: Any, full: str) -> str:
    m = re.search(r"(&?\w+)\s*\)\.Scan|var\s+\w+\s+(\w+)|new\((\w+)\)", full)
    if m:
        return next((g for g in m.groups() if g), "Resource")
    return "Resource"


# ---------- 分派 ----------
_TRACERS = {
    "javascript": _trace_node,
    "go": _trace_go,
}


def trace_to_sinks(handler_node: Any, param_name: str, ctx: Any,
                   method_index=None, hierarchy=None) -> List[ResourceAccess]:
    """按 ctx.language 分派的污点追踪入口（各语言前端统一调用）。

    method_index：全局函数/方法体索引（`{函数名/ClassName.methodName: ctx}`），
    供跨过程进入 Service/Repository 层；为空则退回 handler 内单层判定。
    hierarchy：Java 类型继承链 `{类型名: [父类型]}`，用于接口→实现类/父类方法体解析。
    """
    lang = getattr(ctx, "language", "java")
    if lang == "java":
        return _trace_java(handler_node, param_name, ctx, method_index, hierarchy)
    return _TRACERS.get(lang, _trace_java)(handler_node, param_name, ctx, method_index)