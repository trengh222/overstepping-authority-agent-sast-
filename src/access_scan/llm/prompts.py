"""Prompt 模板（方案 §9.3 / §9.4）与证据包构建（§9.1）。"""
import json
import re
from typing import Any, Dict, List, Optional

from ..ir import Candidate

_SINK_LOC_RE = re.compile(r"^(.+?\.java):(\d+):")

SYSTEM_PROMPT = """你是一名白盒越权漏洞审计专家。你会收到一个候选风险点的精确证据包。
严格规则：
1. 只依据证据包中的代码片段判断，不得假设片段之外存在校验。
2. 判断片段之外是否存在鉴权时，参考证据包的 framework_guards 字段（项目已识别的
   全局鉴权设施清单，含覆盖路径 patterns 与鉴权能力）：
   - 若当前端点路径落在某个 guard 的 patterns 内，说明存在上层鉴权，判 is_vulnerable=false
     且 subtype=NONE 并填写 uncertain_reason；
   - 若 framework_guards 为空或该端点路径不在任何 guard 覆盖范围内，不得假设片段之外存在校验。
3. 区分"公开资源"与"私有资源"：商品/公开文章/字典表不是越权。
4. 输出必须是合法 JSON，符合给定 schema。
5. reasoning 必须引用证据包中的具体行号与字段。
6. 若证据包含 call_chain_source（跨过程调用链上真实方法体源码），必须核验其中的
   Repository/Service 方法体是否真的缺少归属过滤（user_id/owner 约束）；reasoning 必须
   引用 call_chain_source 里的具体行号。若切片被截断（truncated=true）或缺失，无法从
   源码核验归属约束时，应降低 confidence 并填写 uncertain_reason，不得臆断。
7. 若证据包含 feature_flags（handler 内读取的配置开关及其声明值），据此判定该路径的
   可达性（reachability）并填入输出字段：
   - declared=false 表示该功能被配置关闭，路径可能不可达 → reachability="unreachable"，
     并在 reasoning 中说明；
   - declared=true 或未声明（declared=null）时，默认按可达处理 → reachability="reachable"
     或 "needs_config"（未声明且无法确定时）。
   不得臆断声明值之外的开关状态。
8. 若判定 is_vulnerable=false 且原因是「存在拦截门」（鉴权/守卫/归属校验），必须输出
   blocking_gate 字段说明拦截门的类型与名称：
   - type: "guard"（全局守卫/中间件）、"annotation"（鉴权注解）、"ownership"（归属校验）；
   - name: 门的具体名称（守卫名/注解名/归属字段名）。
   不得虚构不存在的门；若「不是漏洞」但无明确门依据（如公开资源），blocking_gate 置 null。"""

# 对抗式复核（高危候选二次验证，§9.4）：从三个视角尝试否定，任一成立则否定漏洞
ADVERSARIAL_PROMPT = """请从以下三个视角尝试否定上一条结论：
Q1 公开资源视角：这个实体是否本就对所有人开放？
Q2 框架鉴权视角：是否存在注解/中间件/网关在更上层做了校验？
Q3 数据归属视角：查询/JOIN 里是否其实已按当前用户过滤？
若任一视角能成立，则否定该漏洞。
只输出 JSON：{"refuted": true/false, "reasoning": "..."}"""

_OUTPUT_FORMAT = """请只输出一个合法 JSON 对象，字段要求：
- is_vulnerable: boolean（该候选是否构成越权）
- subtype: "A1" | "A2" | "A3" | "A4" | "B6" | "NONE"（B6=属性级越权/敏感字段暴露；NONE 表示不构成越权）
- confidence: number，0~1
- resource_privacy: "PRIVATE" | "PUBLIC" | "UNKNOWN"（涉及资源实体的私密性推断）
- reasoning: string，引用证据包中的行号与字段
- evidence_lines: string 数组，支撑结论的证据条目；每条必须以「文件:行号」开头
  （如 `OrderService.java:22: selectById 无归属过滤`），且至少一条必须覆盖 sink 所在行
  （证据包 sink.file / sink.line），否则该结论无法通过引用回验
- uncertain_reason: string，当无法确定时说明原因
- reachability: "reachable" | "unreachable" | "needs_config"（仅当证据含 feature_flags 时输出，默认可达）
- blocking_gate: object 或 null（当 is_vulnerable=false 且被门拦截时，给出 {"type": "guard"|"annotation"|"ownership", "name": "..."}；否则 null）"""


def _sink_location(candidate: Candidate) -> Optional[Dict[str, Any]]:
    """sink 的（文件, 行号）：优先 sink_snippet 前缀「文件:行: 代码」。"""
    acc = candidate.access
    m = _SINK_LOC_RE.search((acc.sink_snippet or "").replace("\\", "/"))
    if m:
        return {"file": m.group(1), "line": int(m.group(2))}
    line = int(getattr(acc, "sink_line", 0) or 0)
    if line:
        return {"file": candidate.endpoint.file, "line": line}
    return None


def _guards_summary(guards, limit: int = 30) -> List[Dict[str, Any]]:
    """把 Guard 清单压成 LLM 可用的框架上下文摘要（RAG，方向一）。

    只保留「生效且相关」的守卫：registered 且（含鉴权检查或依赖客户端输入）。
    后者与 A4（鉴权决策依赖客户端可控输入）直接相关，值得暴露给 LLM。
    """
    relevant = [g for g in guards
                if getattr(g, "registered", True)
                and (getattr(g, "has_auth_check", False)
                     or getattr(g, "depends_on_client_input", False))]
    if not relevant:
        relevant = list(guards)
    out: List[Dict[str, Any]] = []
    for g in relevant[:limit]:
        out.append({
            "kind": getattr(g, "kind", ""),
            "name": getattr(g, "name", ""),
            "patterns": getattr(g, "patterns", None) or ["**"],
            "has_auth_check": getattr(g, "has_auth_check", False),
            "depends_on_client_input": getattr(g, "depends_on_client_input", False),
        })
    return out


def build_evidence_pkg(candidate: Candidate, guards: Optional[List] = None) -> Dict[str, Any]:
    """组装精确证据包（§9.1）：只送端点/鉴权/污点路径等静态事实，不送整文件。

    guards 为项目已识别的全局鉴权设施清单（Guard 列表），作为框架上下文（RAG）
    注入 framework_guards 字段，供 LLM 判断「片段之外是否存在上层鉴权」，
    避免盲目保守降级或盲目假设。guards 为空时不注入，保持缓存 key 与旧版一致。
    """
    ep = candidate.endpoint
    acc = candidate.access
    pkg: Dict[str, Any] = {
        "candidate_subtype": candidate.subtype,
        "rule_id": candidate.rule_id,
        "endpoint": f"{ep.method} {ep.path}  @{ep.file}:{ep.line_start}-{ep.line_end}",
        "handler": ep.handler,
        "auth": {
            "present": ep.auth.present,
            "mechanism": ep.auth.mechanism.value,
            "role_or_perm": ep.auth.role_or_perm,
            "scope": ep.auth.scope,
        },
        "taint_flow": acc.flow,
        "entity": acc.entity or None,
        "ownership_predicate": acc.ownership_predicate,
        "sink_snippet": acc.sink_snippet,
    }
    sink = _sink_location(candidate)
    if sink:
        pkg["sink"] = sink  # 供 LLM 引用可被回验的 sink 行（trace.py 覆盖性检查）
    # 字段级证据（规则 B6）：返回对象命中的敏感字段
    if getattr(acc, "sensitive_fields", None):
        pkg["sensitive_fields"] = acc.sensitive_fields
    # 反射/动态分派点（M7）：静态不可判定，提示模型不要据「未见校验」断言安全
    if getattr(acc, "dynamic_sites", None):
        pkg["dynamic_dispatch"] = [s.get("kind") if isinstance(s, dict) else str(s)
                                   for s in acc.dynamic_sites][:8]
    if guards:
        # D1 守卫隔离：只注入候选所属模块的守卫，避免 admin 拦截器污染 web 端点的 LLM 判定
        mod = ep.module or ""
        scoped = [g for g in guards if (getattr(g, "module", "") or "") == mod]
        if scoped:
            pkg["framework_guards"] = _guards_summary(scoped)
    if acc.chain_slices:
        pkg["call_chain_source"] = acc.chain_slices
    if candidate.flag_refs:
        pkg["feature_flags"] = candidate.flag_refs
    return pkg


def build_user_prompt(pkg: Dict[str, Any]) -> str:
    return ("请对以下候选风险点做出判定。\n" + _OUTPUT_FORMAT
            + "\n\n候选证据包：\n" + json.dumps(pkg, ensure_ascii=False, indent=2))


def build_adversarial_prompt(pkg: Dict[str, Any], verdict: Dict[str, Any]) -> str:
    return ("\n\n候选证据包：\n" + json.dumps(pkg, ensure_ascii=False, indent=2)
            + "\n\n此前的判定结果：\n" + json.dumps(verdict, ensure_ascii=False, indent=2))