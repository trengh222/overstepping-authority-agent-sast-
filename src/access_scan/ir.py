# 核心数据结构（统一 IR）—— 直接摘自方案 §5
# 各层契约：extractor 产出 IR，dataflow 消费 IR，rules 产出 Candidate，llm 产出 Finding
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class ParamSource(str, Enum):
    PATH = "PATH"
    QUERY = "QUERY"
    BODY = "BODY"
    HEADER = "HEADER"


class AuthMechanism(str, Enum):
    ANNOTATION = "ANNOTATION"   # @PreAuthorize / @Secured / decorator
    MIDDLEWARE = "MIDDLEWARE"   # Express 中间件 / Gin middleware
    FILTER = "FILTER"           # Spring Interceptor / Django middleware
    SESSION = "SESSION"         # 会话取登录用户（HttpSession/Session）＝已认证
    NONE = "NONE"


@dataclass
class Param:
    name: str
    source: ParamSource
    type: str                   # 声明类型（Long / str / int ...）


@dataclass
class AuthInfo:
    present: bool
    mechanism: AuthMechanism
    role_or_perm: Optional[str]      # 如 "ROLE_ADMIN" / "order:read"
    scope: str                       # GLOBAL | CLASS | METHOD
    line: int = -1
    annotation: Optional[str] = None  # 命中的鉴权注解/装饰器名（回验器精确核验 LLM 声称的门）


@dataclass
class Endpoint:
    id: str                          # 稳定 id，如 file:method:path
    file: str
    method: str                      # GET/POST/...
    path: str
    handler: str                     # 函数/方法全名
    params: List[Param]
    auth: AuthInfo
    privilege_op: bool               # 是否执行写/删/导出等敏感操作
    line_start: int
    line_end: int
    container: Optional[str] = None  # 路由容器名（Flask 蓝本 / Express Router），注册可达判定用
    module: Optional[str] = None     # 构建模块（Maven/Gradle 多模块相对路径），守卫作用域隔离用


@dataclass
class FieldFact:                     # 对象字段事实（字段级敏感性，规则 B6 用）
    name: str
    type: str = ""
    annotations: List[str] = field(default_factory=list)  # 声明注解（@JsonIgnore / @JsonProperty …）
    sensitive: bool = False           # 字段名命中 config/ownership.yaml sensitive_fields
    protected: bool = False           # 有序列化忽略/脱敏标记（@JsonIgnore / @Transient）


@dataclass
class ResourceAccess:                # 一次资源访问（数据流 sink）
    entity: str                      # Order / User / File ...
    identifier_param: str            # 充当资源 ID 的参数名
    flow: List[str]                  # 污点传播路径描述，如 ["id -> orderService.findById -> t_order WHERE id"]
    ownership_predicate: bool        # SQL/ORM 是否含 owner 约束
    sink_snippet: str                # 关键语句原文（带行号）
    sink_line: int = -1              # sink 所在行号（符号执行"可触发"定位用）
    chain_slices: List[Any] = field(default_factory=list)  # 跨过程调用链真实方法体源码切片（供 LLM 核验）
    sensitive_fields: List[str] = field(default_factory=list)  # 暴露的敏感字段名（B6）
    dynamic: bool = False            # 调用链含反射/动态分派（静态不可判定）
    dynamic_sites: List[Any] = field(default_factory=list)     # [{kind,name,line,snippet}]


@dataclass
class Resource:
    entity: str
    identifier_field: str            # 主键，如 id
    owner_field: Optional[str]       # 归属字段，如 user_id / tenant_id
    privacy: str                     # PRIVATE | PUBLIC | UNKNOWN
    confidence: float                # 私密性置信度 0~1
    fields: List[FieldFact] = field(default_factory=list)  # 字段级事实（含敏感性标注）


@dataclass
class Candidate:                     # L4 产出
    endpoint: Endpoint
    access: ResourceAccess
    subtype: str                     # A1/A2/A3/A4
    rule_id: str
    flag_refs: List[Any] = field(default_factory=list)  # 配置开关引用 [{name, declared}]，交 LLM 判定可达性
    reachability_hints: Dict[str, str] = field(default_factory=dict)  # 确定性可达性提示 {build, registration}


@dataclass
class Finding:                       # L5 产出
    candidate: Candidate
    verdict: str                     # CONFIRMED | LIKELY | UNCERTAIN
    subtype: str
    confidence: float
    llm_reasoning: Optional[str]     # LLM 意见（可空，与静态证据分离）
    evidence: Dict[str, Any]         # 静态证据（数据流/反例/归属字段）
    poc: Optional[str] = None           # 可选 PoC
    fix_suggestion: Optional[str] = None
    reachability_class: str = "none"    # build|registration|config|permission|data|none
    disposition: str = "keep"           # auto_close|downgrade_ticket|downgrade_annotate|keep|promote


# ---- 序列化（增量扫描基线 / 报告用） ----
def _v(x):
    return x.value if isinstance(x, Enum) else x


def candidate_to_dict(c: Candidate) -> Dict[str, Any]:
    ep, acc = c.endpoint, c.access
    return {
        "subtype": c.subtype,
        "rule_id": c.rule_id,
        "flag_refs": list(c.flag_refs),
        "reachability_hints": dict(c.reachability_hints),
        "endpoint": {
            "id": ep.id, "file": ep.file, "method": ep.method, "path": ep.path,
            "handler": ep.handler,
            "params": [{"name": p.name, "source": _v(p.source), "type": p.type} for p in ep.params],
            "auth": {"present": ep.auth.present, "mechanism": _v(ep.auth.mechanism),
                     "role_or_perm": ep.auth.role_or_perm, "scope": ep.auth.scope,
                     "line": ep.auth.line, "annotation": ep.auth.annotation},
            "privilege_op": ep.privilege_op,
            "line_start": ep.line_start, "line_end": ep.line_end,
            "container": ep.container, "module": ep.module,
        },
        "access": {
            "entity": acc.entity, "identifier_param": acc.identifier_param,
            "flow": list(acc.flow),
            "ownership_predicate": acc.ownership_predicate,
            "sink_snippet": acc.sink_snippet,
            "sink_line": acc.sink_line,
            "chain_slices": list(acc.chain_slices),
            "sensitive_fields": list(acc.sensitive_fields),
            "dynamic": acc.dynamic,
            "dynamic_sites": list(acc.dynamic_sites),
        },
    }


def candidate_from_dict(d: Dict[str, Any]) -> Candidate:
    ep, acc = d["endpoint"], d["access"]
    ea = ep["auth"]
    return Candidate(
        endpoint=Endpoint(
            id=ep["id"], file=ep["file"], method=ep["method"], path=ep["path"],
            handler=ep["handler"],
            params=[Param(name=p["name"], source=ParamSource(p["source"]), type=p["type"])
                    for p in ep["params"]],
            auth=AuthInfo(present=ea["present"], mechanism=AuthMechanism(ea["mechanism"]),
                          role_or_perm=ea.get("role_or_perm"), scope=ea["scope"],
                          line=ea.get("line", -1), annotation=ea.get("annotation")),
            privilege_op=ep["privilege_op"],
            line_start=ep["line_start"], line_end=ep["line_end"],
            container=ep.get("container"), module=ep.get("module"),
        ),
        access=ResourceAccess(
            entity=acc["entity"], identifier_param=acc["identifier_param"],
            flow=list(acc["flow"]),
            ownership_predicate=acc["ownership_predicate"],
            sink_snippet=acc["sink_snippet"],
            sink_line=acc.get("sink_line", -1),
            chain_slices=list(acc.get("chain_slices", [])),
            sensitive_fields=list(acc.get("sensitive_fields", [])),
            dynamic=bool(acc.get("dynamic", False)),
            dynamic_sites=list(acc.get("dynamic_sites", [])),
        ),
        subtype=d["subtype"], rule_id=d["rule_id"],
        flag_refs=list(d.get("flag_refs", [])),
        reachability_hints=dict(d.get("reachability_hints", {})),
    )


def resource_to_dict(r: Resource) -> Dict[str, Any]:
    return {"entity": r.entity, "identifier_field": r.identifier_field,
            "owner_field": r.owner_field, "privacy": r.privacy, "confidence": r.confidence,
            "fields": [{"name": f.name, "type": f.type, "annotations": list(f.annotations),
                        "sensitive": f.sensitive, "protected": f.protected}
                       for f in (r.fields or [])]}


def resource_from_dict(d: Dict[str, Any]) -> Resource:
    data = dict(d)
    raw = data.pop("fields", []) or []
    return Resource(**data, fields=[FieldFact(**f) for f in raw])