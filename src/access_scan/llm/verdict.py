"""结构化判定结果校验 + verdict 判定流程（方案 §9.2 / §7.4）。"""
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Sequence

from ..cache import evidence_key
from ..ir import AuthMechanism, Candidate, Finding
from ..rules.vertical import guard_covers
from .prompts import build_evidence_pkg
from .trace import verify_citations

# §9.2 结构化输出 JSON Schema
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerable": {"type": "boolean"},
        "subtype": {"enum": ["A1", "A2", "A3", "A4", "NONE"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "resource_privacy": {"enum": ["PRIVATE", "PUBLIC", "UNKNOWN"]},
        "reasoning": {"type": "string"},
        "evidence_lines": {"type": "array", "items": {"type": "string"}},
        "uncertain_reason": {"type": "string"},
        "reachability": {"enum": ["reachable", "unreachable", "needs_config"]},
        "blocking_gate": {
            "type": ["object", "null"],
            "properties": {
                "type": {"enum": ["guard", "annotation", "ownership"]},
                "name": {"type": "string"},
            },
        },
    },
    "required": ["is_vulnerable", "subtype", "confidence", "reasoning"],
}

_SUBTYPES = ("A1", "A2", "A3", "A4", "B6", "NONE")
_PRIVACY = ("PRIVATE", "PUBLIC", "UNKNOWN")
_MIN_NEGATIVE_CONF = 0.6  # 负结论置信度下限：低于此值不直接关闭（保留疑似漏洞）

# 门回验（②）两个分支的置信度口径：
#   llm.confidence 是「模型认为无漏洞」的安全性置信度，Finding.confidence 是「存在漏洞」的
#   嫌疑度，两者方向相反——因此按嫌疑度反向折算：suspicion = 0.5 - 0.2 * safety，落在
#   [0.3, 0.5)；门回验失败（模型编的门）比「门真实存在」更可疑，固定 0.55，保证
#   通过分支严格低于失败分支。
_GATE_SAFETY_BASE = 0.5
_GATE_SAFETY_SLOPE = 0.2
_GATE_PASSED_FLOOR = 0.3
_GATE_PASSED_CEIL = 0.5
_GATE_FAILED_CONF = 0.55

# 可达性事实/推断 → 处置边界（方案 §7.4 / 用户策略矩阵）
#   ✅ 可关（确定性事实，程序可核验）：构建不可达 / 注册不可达 / 数据不可达(unsat)
#   ⚠ 只降级（推断，事实存在≠风险不存在）：配置推断 / 权限推断（注解·守卫·归属回验）
#   ⛔ 不动判定（模型猜测，仅标注）：公开资源、内部接口、对抗复核否定
# 关闭权限（close_authority）随证据落盘，报告里可逐条核验。
_FACT_KIND = {
    "build": "fact", "registration": "fact", "data": "fact",
    "config": "inference", "permission": "inference", "none": "guess",
}
_CLOSE_AUTHORITY = {
    "fact": "close_allowed",       # 事实：允许自动关闭
    "inference": "downgrade_only",  # 推断：只降级，不关闭
    "guess": "annotate_only",       # 猜测：不改判定，只标注
}


def _mark_policy(ev: Dict[str, Any], cls: str) -> Dict[str, Any]:
    """把「可达性类别 → 事实类别 → 关闭权限」写进证据，供报告逐条核验。"""
    kind = _FACT_KIND.get(cls, "guess")
    ev["fact_class"] = kind
    ev["close_authority"] = _CLOSE_AUTHORITY[kind]
    return ev

# 非法输出的整包降级（不抛出，保证流水线鲁棒）
_FALLBACK = {
    "is_vulnerable": False,
    "subtype": "NONE",
    "confidence": 0.0,
    "resource_privacy": "UNKNOWN",
    "reasoning": "LLM 输出不可解析或不符合 schema，按不确定处理。",
    "evidence_lines": [],
    "uncertain_reason": "LLM 输出非法/不完整",
}

_FIX_HINTS = {
    "A1": "校验资源归属：{entity} 的 owner 字段必须等于当前登录用户，或查询条件带上 user_id/owner 约束。",
    "A2": "补充最小权限注解/角色校验（如 @PreAuthorize）。",
    "A3": "特权端点缺少鉴权：补充 @PreAuthorize/@Secured 或注册鉴权拦截器。",
    "A4": "鉴权决策依赖客户端可控输入（参数/头/Cookie），应改为基于服务端会话/安全上下文。",
    "B6": "对返回体做字段级裁剪：{entity} 中的敏感字段必须脱敏（置空/mask），或仅当前角色可读。",
}


def validate(raw: Any) -> Dict[str, Any]:
    """按 VERDICT_SCHEMA 校验并规范化；校验失败 → 整包降级为不确定（不抛出）。"""
    if not isinstance(raw, dict):
        return dict(_FALLBACK)
    if not isinstance(raw.get("is_vulnerable"), bool) or raw.get("subtype") not in _SUBTYPES:
        return dict(_FALLBACK)
    try:
        conf = max(0.0, min(1.0, float(raw.get("confidence", 0.0))))
    except (TypeError, ValueError):
        conf = 0.0
    privacy = raw.get("resource_privacy", "UNKNOWN")
    if privacy not in _PRIVACY:
        privacy = "UNKNOWN"
    evidence_lines = raw.get("evidence_lines")
    if not isinstance(evidence_lines, list) or not all(isinstance(s, str) for s in evidence_lines):
        evidence_lines = []

    def _s(key: str) -> str:
        v = raw.get(key) or ""
        return v if isinstance(v, str) else str(v)

    reach = raw.get("reachability", "reachable")
    if reach not in ("reachable", "unreachable", "needs_config"):
        reach = "reachable"
    gate = raw.get("blocking_gate")
    if not isinstance(gate, dict) or gate.get("type") not in ("guard", "annotation", "ownership"):
        gate = None

    return {
        "is_vulnerable": raw["is_vulnerable"],
        "subtype": raw["subtype"],
        "confidence": conf,
        "resource_privacy": privacy,
        "reasoning": _s("reasoning"),
        "evidence_lines": evidence_lines,
        "uncertain_reason": _s("uncertain_reason"),
        "reachability": reach,
        "blocking_gate": gate,
    }


def _static_evidence(candidate: Candidate) -> Dict[str, Any]:
    acc = candidate.access
    ev: Dict[str, Any] = {
        "rule_id": candidate.rule_id,
        "taint_flow": acc.flow,
        "ownership_predicate": acc.ownership_predicate,
        "sink_snippet": acc.sink_snippet,
    }
    # 字段敏感性（规则 B6）：敏感字段名单作为可核验事实落证据
    if getattr(acc, "sensitive_fields", None):
        ev["sensitive_fields"] = list(acc.sensitive_fields)
    # 反射/动态分派点（M7）：静态不可判定 → 记录以便降级与人工复核
    if getattr(acc, "dynamic_sites", None):
        ev["dynamic_sites"] = [s.get("kind") if isinstance(s, dict) else str(s)
                               for s in acc.dynamic_sites][:8]
    return ev


def _fix_text(candidate: Candidate) -> Optional[str]:
    hint = _FIX_HINTS.get(candidate.subtype)
    if not hint:
        return None
    return hint.format(entity=candidate.access.entity or "资源")


def _norm_name(name: str) -> str:
    """归一化门名称（去掉 @ / 包名点号 / 大小写），用于精确比对。"""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _sink_text(candidate: Candidate) -> str:
    """sink 侧可核验文本：sink 原文 + 污点流 + 跨过程切片。"""
    acc = candidate.access
    return _norm_name(
        " ".join([acc.sink_snippet or "", " ".join(str(x) for x in (acc.flow or [])),
                  " ".join(str(x) for x in (acc.chain_slices or []))])
    )


def _flag_refs(candidate: Candidate) -> List[Any]:
    return list(getattr(candidate, "flag_refs", None) or [])


def _flag_declared_false(candidate: Candidate) -> bool:
    """静态开关声明中是否存在明确的 declared=false（LLM 不可达声明的核验依据）。"""
    return any(isinstance(r, dict) and r.get("declared") is False
               for r in _flag_refs(candidate))


def verify_gate(candidate: Candidate, gate: Optional[Dict[str, Any]],
                guards=None) -> bool:
    """回验器（流水线④）：程序校验 LLM 声称的 blocking_gate 是否真实存在。

    - guard：名称精确命中、已注册且确有鉴权逻辑、路径被覆盖；
    - annotation：端点确有该鉴权注解/装饰器（名称核验，可退化为注解参数核验）；
    - ownership：sink 查询是否真实含 LLM 声称的归属字段。
    """
    if not isinstance(gate, dict):
        return False
    gtype = gate.get("type")
    name = (gate.get("name") or "").strip()
    if not name:
        return False
    target = _norm_name(name)
    if not target:
        return False
    if gtype == "guard":
        path = candidate.endpoint.path
        mod = candidate.endpoint.module or ""
        return any(
            (getattr(g, "module", "") or "") == mod
            and getattr(g, "has_auth_check", False)
            and not getattr(g, "depends_on_client_input", False)
            and _norm_name(getattr(g, "name", "") or "") == target
            and guard_covers(g, path)
            for g in (guards or [])
        )
    if gtype == "annotation":
        auth = candidate.endpoint.auth
        if not auth.present or auth.mechanism != AuthMechanism.ANNOTATION:
            return False
        role = _norm_name(auth.role_or_perm or "")
        # 放行类注解（isAnonymous/permitAll）不是拦截门
        if any(k in role for k in ("isanonymous", "permitall")):
            return False
        ann = _norm_name(getattr(auth, "annotation", "") or "")
        if ann and ann == target:
            return True
        # 注解参数中的角色/权限（如 hasRole('ADMIN')）同样可作为可核验依据
        return target in role
    if gtype == "ownership":
        if not candidate.access.ownership_predicate:
            return False
        return target in _sink_text(candidate)
    return False


def reachability_finding(candidate: Candidate, reason: str, cls: str) -> Finding:
    """确定性可达性判定为「不可达」（构建/注册）→ 自动关闭（UNCERTAIN），不调用 LLM。"""
    ev = _mark_policy(_static_evidence(candidate), cls)
    ev["reachability_reason"] = reason
    return Finding(
        candidate=candidate, verdict="UNCERTAIN", subtype=candidate.subtype,
        confidence=0.0,
        llm_reasoning=f"可达性判定（{cls}）：{reason}，按不可达自动关闭。",
        evidence=ev, fix_suggestion=None,
        reachability_class=cls, disposition="auto_close",
    )


def data_fact_finding(candidate: Candidate, reason: str) -> Finding:
    """数据流事实（归属约束已存在）→ 无越权风险，确定性关闭。"""
    ev = _mark_policy(_static_evidence(candidate), "data")
    ev["data_fact"] = reason
    return Finding(
        candidate=candidate, verdict="UNCERTAIN", subtype=candidate.subtype,
        confidence=0.0,
        llm_reasoning=f"数据流事实：{reason}，按无越权风险自动关闭。",
        evidence=ev, fix_suggestion=None,
        reachability_class="data", disposition="auto_close",
    )


def _decide(candidate: Candidate, llm: Dict[str, Any],
           upheld: Optional[bool] = None, adv_reason: str = "",
           guards=None, root=None) -> Finding:
    """方案 §7.4 verdict 判定流程 + 策略矩阵（事实/推断 → 处置边界）。

    判定依据按「可信度」分三层，处置权限严格区分（用户策略矩阵）：

    | 层级 | 依据 | 例子 | 处置 |
    |------|------|------|------|
    | 事实 | 程序可核验的确定性事实 | 模块未在 settings.gradle、包不在扫描根且无 @Import、路径约束 unsat | ✅ 可自动关闭 |
    | 推断 | 存在性可核验、但「风险不存在」仍是推断 | 配置键未声明、鉴权注解/守卫/归属回验通过 | ⚠ 只降级（verdict 保持 LIKELY，降 confidence + 工单/标注） |
    | 猜测 | 模型自述 | 「看起来是内部接口」「公开资源」「对抗复核否定」 | ⛔ 不改判定，只标注 |

    每次判定给出 reachability_class（build/registration/config/permission/data/none）、
    disposition（auto_close / downgrade_ticket / downgrade_annotate / keep / promote）
    与 evidence 中的 fact_class / close_authority（close_allowed / downgrade_only /
    annotate_only），报告可逐条核验「这条为什么被关」。
    """
    ev = _static_evidence(candidate)
    ev["llm_evidence_lines"] = llm.get("evidence_lines") or []  # 供 CONFIRMED 门槛校验证据充分性
    # 记录模型自身结论：符号反例升级时需要知道「模型原先否定过」，以便改写说明（避免报告自相矛盾）。
    ev["model_conclusion"] = "vulnerable" if llm.get("is_vulnerable") else "not_vulnerable"
    # 引用锚点回验（可追溯性）：把 LLM 给的「文件:行」落回真实源码，失败记录逐条原因。
    # 结果只用于降级/拦截升级，不因引用缺失而丢弃候选（保持召回）。
    citation_check = verify_citations(candidate, ev["llm_evidence_lines"], root)
    if citation_check["total"]:
        ev["citation_check"] = citation_check
    if llm.get("reachability"):
        ev["reachability"] = llm["reachability"]
    hints = getattr(candidate, "reachability_hints", None) or {}

    # ① 注册可达（确定性事实）：容器未见挂载 → 自动关闭（策略矩阵 行2 ✅）。
    #    模型坚持漏洞时保留并记 fact_conflict，避免单点断言直接丢告警。
    if hints.get("registration") and llm.get("is_vulnerable"):
        ev["fact_conflict"] = "LLM 坚持漏洞，注册事实暂不关闭，转人工复核"
    if hints.get("registration") and not llm.get("is_vulnerable"):
        _mark_policy(ev, "registration")
        ev["reachability_reason"] = hints["registration"]
        return Finding(
            candidate=candidate, verdict="UNCERTAIN", subtype=candidate.subtype,
            confidence=0.0,
            llm_reasoning=f"注册可达：{hints['registration']}；LLM 未坚持漏洞，按未挂载自动关闭。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=None,
            reachability_class="registration", disposition="auto_close",
        )

    # ② 回验器：LLM 声称「被门拦截」→ 程序校验门是否真实存在（防幻觉）。
    #    权限属推断（门存在≠该资源访问被拦）：回验通过只降级留痕，不据此关闭（行5 ⚠）。
    gate = llm.get("blocking_gate")
    if not llm.get("is_vulnerable") and gate:
        if verify_gate(candidate, gate, guards):
            ev["gate_verification"] = "passed"
            _mark_policy(ev, "permission")
            safety = max(0.0, min(1.0, float(llm.get("confidence", 0.0) or 0.0)))
            # 方向取反：模型越确信「无漏洞」，本条的嫌疑度越低（门真实存在 → 只降级）
            conf = round(min(_GATE_PASSED_CEIL,
                             max(_GATE_PASSED_FLOOR,
                                 _GATE_SAFETY_BASE - _GATE_SAFETY_SLOPE * safety)), 2)
            ev["gate_verified_confidence"] = {
                "model_safety_confidence": safety,
                "suspicion": conf,
                "rule": "suspicion = clamp(0.5 - 0.2 * safety, [0.3, 0.5))",
            }
            return Finding(
                candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
                confidence=conf,
                llm_reasoning=f"回验确认拦截门真实存在（{gate.get('type')}: {gate.get('name')}）；"
                              "权限推断仅降级、不自动关闭，需人工确认拦截是否覆盖该资源访问。"
                              f"嫌疑度按模型安全置信度 {safety:.2f} 反向折算为 {conf:.2f}。"
                              + (llm.get("reasoning") or ""),
                evidence=ev, fix_suggestion=_fix_text(candidate),
                reachability_class="permission", disposition="downgrade_annotate",
            )
        # 门不存在（LLM 幻觉）→ 翻转，保留为疑似漏洞（比「门真实存在」更可疑）
        ev["gate_verification"] = "failed"
        _mark_policy(ev, "permission")
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=_GATE_FAILED_CONF,
            llm_reasoning="LLM 声称被门拦截但回验未找到该门，按疑似漏洞保留。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=_fix_text(candidate),
            reachability_class="permission", disposition="keep",
        )

    # ③ 配置可达（半确定 + LLM）：仅当静态开关声明确为关闭时才自动关闭
    if llm.get("reachability") == "unreachable":
        if _flag_declared_false(candidate):
            # 声明中明确 declared=false 属静态事实（不是推断）→ 允许关闭
            ev["fact_class"] = "fact"
            ev["close_authority"] = "close_allowed"
            return Finding(
                candidate=candidate, verdict="UNCERTAIN", subtype=candidate.subtype,
                confidence=max(0.1, round(llm.get("confidence", 0.5) * 0.5, 2)),
                llm_reasoning="LLM 判定该路径不可达（配置开关关闭）。" + (llm.get("reasoning") or ""),
                evidence=ev, fix_suggestion=None,
                reachability_class="config", disposition="downgrade_ticket",
            )
        # 无 declared=false 证据 → 不采信「不可达」，保留告警并转配置工单
        ev["reachability_verification"] = "no_disabled_flag"
        _mark_policy(ev, "config")
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=max(0.5, llm.get("confidence", 0.5)),
            llm_reasoning="LLM 声明该路径不可达，但静态开关声明未给出关闭证据"
                          "（无 declared=false），不直接关闭；按配置可达降级工单。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=_fix_text(candidate),
            reachability_class="config", disposition="downgrade_ticket",
        )

    # ④ 公开资源：模型猜测（行6 ⛔）→ 不改判定，只标注
    if llm.get("resource_privacy") == "PUBLIC":
        ev["model_inference"] = "PUBLIC 公开资源属模型推断，未作为关闭依据"
        _mark_policy(ev, "none")
        conf = round(min(0.6, max(0.4, float(llm.get("confidence", 0.5) or 0.5))), 2)
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=conf,
            llm_reasoning="LLM 推断为公开资源（PUBLIC）属模型猜测，不改变判定，仅标注待人工确认。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=_fix_text(candidate),
            reachability_class="none", disposition="keep",
        )

    # ⑤ 非漏洞负结论：A4 高危信号或低置信负结论缺少可核验门 → 不直接关闭
    if not llm.get("is_vulnerable"):
        conf = llm.get("confidence", 0.0)
        if candidate.subtype == "A4" or conf < _MIN_NEGATIVE_CONF:
            ev["negative_verification"] = "unverified"
            why = ("A4（鉴权决策依赖客户端可控输入）的负结论缺少可核验拦截门"
                   if candidate.subtype == "A4"
                   else f"负结论置信度 {conf:.2f} 低于 {_MIN_NEGATIVE_CONF}")
            return Finding(
                candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
                confidence=max(0.5, conf),
                llm_reasoning=f"LLM 判定非漏洞，但{why}，按疑似漏洞保留。"
                              + (llm.get("reasoning") or ""),
                evidence=ev, fix_suggestion=_fix_text(candidate),
                reachability_class="none", disposition="keep",
            )
        # 自信负结论同样只是模型推断（行6 ⛔）→ 不改变判定，仅标注
        ev["model_inference"] = "自信负结论属模型推断，未作为关闭依据"
        _mark_policy(ev, "none")
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=round(min(0.6, max(0.4, conf)), 2),
            llm_reasoning=f"LLM 判定非漏洞（模型推断，置信 {conf:.2f}），不改变判定，仅标注待人工确认。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=_fix_text(candidate),
            reachability_class="none", disposition="keep",
        )

    # ⑥ 配置可达：仅当证据包含开关引用时才接受 needs_config → 降级 + 工单
    if llm.get("reachability") == "needs_config" and _flag_refs(candidate):
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=llm.get("confidence", 0.5),
            llm_reasoning="该路径依赖配置开关且取值未声明，需确认配置后复核。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=_fix_text(candidate),
            reachability_class="config", disposition="downgrade_ticket",
        )
    if upheld is False:
        # 对抗复核否定 = 模型猜测（行6 ⛔）→ 不改判定，只标注
        reason = f"对抗复核否定该漏洞：{adv_reason}" if adv_reason else "对抗复核否定该漏洞"
        ev["model_inference"] = "对抗复核否定属模型推断，未作为关闭依据"
        _mark_policy(ev, "none")
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=round(min(0.6, max(0.4, float(llm.get("confidence", 0.5) or 0.5))), 2),
            llm_reasoning=reason + "（模型推断，不改变判定，仅标注待人工复核）",
            evidence=ev, fix_suggestion=_fix_text(candidate),
            reachability_class="none", disposition="keep",
        )
    # ⑦ 数据事实：类型收窄属于「不可枚举」运行时假设（行7 ⚠）→ 只降级，不关闭
    downgrade = hints.get("data_downgrade")
    if downgrade and llm.get("is_vulnerable"):
        ev["data_downgrade"] = downgrade
        ev["fact_class"] = "data"
        ev["close_authority"] = "downgrade_only"
        return Finding(
            candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
            confidence=min(llm.get("confidence", 0.5), 0.3),
            llm_reasoning=f"数据事实：{downgrade}；按运行时假设降级，不自动关闭。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=None,
            reachability_class="data", disposition="downgrade_annotate",
        )
    # ⑧ 数据可达成立 → 先做正向确定性断言，再保持告警（待符号执行进一步判定 sat/unsat）
    conf = llm.get("confidence", 0.5)
    if not _positive_evidence_ok(candidate):
        ev["positive_verification"] = "failed"
        return Finding(
            candidate=candidate, verdict="UNCERTAIN", subtype=candidate.subtype,
            confidence=min(conf, 0.3),
            llm_reasoning="LLM 判定为漏洞，但缺少确定性静态证据"
                          "（污点流为空 / 已有归属约束 / A4 无客户端可控断言），不直接告警。"
                          + (llm.get("reasoning") or ""),
            evidence=ev, fix_suggestion=None,
            reachability_class="none", disposition="downgrade_annotate",
        )
    return Finding(
        candidate=candidate, verdict="LIKELY", subtype=candidate.subtype,
        confidence=conf,
        llm_reasoning=llm.get("reasoning") or None,
        evidence=ev, poc=None, fix_suggestion=_fix_text(candidate),
        reachability_class="data", disposition="keep",
    )


# 会切断静态数据流/字段授权的反射点类型（bean-copy 只记录不降级：值复制不改变归属）
_DYNAMIC_CLAMP_KINDS = frozenset({
    "classloader", "reflective-field", "reflective-method", "method-invoke",
    "accessible-bypass", "dynamic-proxy", "deserialize", "container-lookup",
    "dynamic-access",
})


def _apply_dynamic_clamp(candidate: Candidate, finding: Finding) -> Finding:
    """handler 存在反射/动态分派点时：降置信度并标注，不得据此给出确定结论。

    方案风险表口径：动态分派/反射 → 降级转人工；这里统一作用在 decide 的所有出口，
    避免某个分支（如「无门可核验」）在反射存在时被当成确定性证据。
    """
    sites = getattr(candidate.access, "dynamic_sites", None) or []
    if not sites:
        return finding
    kinds = {s.get("kind") for s in sites if isinstance(s, dict)}
    ev = dict(finding.evidence or {})
    ev.setdefault("dynamic_sites", sorted(k for k in kinds if k))
    if not (kinds & _DYNAMIC_CLAMP_KINDS):
        return finding
    ev["dynamic_downgrade"] = (
        f"handler 含 {len(sites)} 处反射/动态分派点（{', '.join(sorted(kinds & _DYNAMIC_CLAMP_KINDS))}），"
        "静态不可判定其校验行为，结论需人工复核")
    finding.evidence = ev
    finding.confidence = max(0.1, round(finding.confidence * 0.6, 2))
    note = "动态分派提示：反射/动态调用可能绕过静态校验，" + \
           "、".join(sorted(kinds & _DYNAMIC_CLAMP_KINDS)) + "，人工复核后再定级。"
    finding.llm_reasoning = (finding.llm_reasoning + "\n" + note) if finding.llm_reasoning else note
    return finding


def _citation_review(finding: Finding) -> Finding:
    """引用回验的处置：LLM 引用的源码行核验不过 → 降置信度并标注待人工确认。

    - 一条都核验不了（文件/行号/内容对不上）：证据链视为不可追溯，confidence 封顶 0.3；
    - 核验通过但没覆盖 sink 行：结论与漏洞点脱节，标注并要求人工确认定位。
    都保持 LIKELY（不自动关闭），只调整 disposition 与证据，符合策略矩阵「推断只降级」。
    """
    ev = finding.evidence or {}
    chk = ev.get("citation_check") or {}
    if not chk.get("total"):
        return finding
    sink = chk.get("sink") or {}
    if not chk.get("verified"):
        ev["citation_review"] = (
            "LLM 引用的 %d 处「文件:行」均无法核验（%s），证据链不可追溯，转人工确认"
            % (chk.get("total", 0), _broken_brief(chk.get("broken") or [])))
        finding.confidence = min(finding.confidence, 0.3)
        if finding.verdict == "LIKELY":
            finding.disposition = "downgrade_annotate"
    elif not chk.get("sink_covered"):
        ev["citation_review"] = (
            "LLM 引用已核验 %d 处，但未覆盖 sink 行（%s:%s），结论与漏洞点需人工对齐"
            % (chk.get("verified", 0), sink.get("file", "?"), sink.get("line", "?")))
        if finding.verdict == "LIKELY":
            finding.disposition = "downgrade_annotate"
    return finding


def _broken_brief(broken: List[Dict[str, Any]]) -> str:
    parts = []
    for b in broken[:3]:
        parts.append("%s(%s)" % (b.get("citation", "?"), b.get("reason", "?")))
    return "；".join(parts) or "-"


def decide(candidate: Candidate, llm: Dict[str, Any],
           upheld: Optional[bool] = None, adv_reason: str = "",
           guards=None, root=None) -> Finding:
    """decide 的对外入口：既有判定流程 + 反射降级 + 引用回验处置。"""
    finding = _apply_dynamic_clamp(
        candidate, _decide(candidate, llm, upheld, adv_reason, guards, root))
    return _citation_review(finding)


def static_only_finding(candidate: Candidate) -> Finding:
    """LLM 不可用/超时/拒绝：候选保留为 LIKELY，静态证据不丢失（§9.5）。"""
    return _apply_dynamic_clamp(candidate, Finding(
        candidate=candidate, verdict="LIKELY", subtype=candidate.subtype, confidence=0.5,
        llm_reasoning=None, evidence=_static_evidence(candidate),
        poc=None, fix_suggestion=_fix_text(candidate),
    ))


_MEANINGFUL_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
_LINE_REF_RE = re.compile(
    r"(?:第\s*)?(\d{1,6})\s*行|line\s*(\d{1,6})|:(\d{1,6})(?:\s*[-~]\s*(\d{1,6}))?",
    re.I,
)
_GENERIC_IDENTS = {
    "return", "public", "private", "static", "void", "true", "false", "none", "null",
    "class", "import", "package", "self", "this", "string", "object", "number",
    "boolean", "select", "insert", "update", "delete", "where", "values", "orderby",
    "groupby", "limit", "offset", "join", "system", "tests", "fixtures", "src",
    "java", "javascript", "typescript", "node", "golang", "localhost",
}


def _line_refs(text: str) -> List[int]:
    out: List[int] = []
    for m in _LINE_REF_RE.finditer(text or ""):
        for g in m.groups():
            if g:
                out.append(int(g))
    return out


def _code_part(text: str) -> str:
    """取 "文件:行号: 代码" 形式的代码部分（丢弃路径/行号，避免路径片段被当证据）。"""
    return text.split(": ", 1)[1] if ": " in (text or "") else (text or "")


def _evidence_ranges(candidate: Candidate) -> List[tuple]:
    """证据行号的可核验范围：handler 行区间 + 跨过程切片行区间。"""
    ep, acc = candidate.endpoint, candidate.access
    ranges = [(ep.line_start, ep.line_end)]
    for s in acc.chain_slices or []:
        if isinstance(s, dict):
            lo, hi = s.get("line_start"), s.get("line_end")
            if isinstance(lo, int) and isinstance(hi, int) and lo > 0 and hi >= lo:
                ranges.append((lo, hi))
    return [(lo, hi) for lo, hi in ranges if lo and hi and hi >= lo]


def _meaningful_idents(text: str) -> set:
    return {t.lower() for t in _MEANINGFUL_IDENT_RE.findall(text or "")
            if t.lower() not in _GENERIC_IDENTS}


def _evidence_sufficient(finding: Finding) -> bool:
    """CONFIRMED 门槛（"无证据不升级"）：evidence_lines 必须能落到真实证据上。

    与旧的「非空即通过」不同，这里要求至少一条证据满足：
    - 引用行号落在 handler 或跨过程切片行区间内；或
    - 含 sink 代码 / 跨过程切片代码中的真实标识符。
    仅有结论或编造的行号/片段无法升级 CONFIRMED。
    """
    lines = [s for s in (finding.evidence.get("llm_evidence_lines") or [])
             if isinstance(s, str) and s.strip()]
    if not lines:
        return False
    # 引用回验：若给出了「文件:行」却一条都核验不了，视为无证据（不允许升级）。
    chk = finding.evidence.get("citation_check") or {}
    if chk.get("total") and not chk.get("verified"):
        return False
    cand = finding.candidate
    acc = cand.access
    ranges = _evidence_ranges(cand)
    sink_idents = _meaningful_idents(_code_part(acc.sink_snippet or ""))
    chain_idents = _meaningful_idents(" ".join(
        str(s.get("code", "")) for s in (acc.chain_slices or []) if isinstance(s, dict)))
    for raw in lines:
        low = raw.lower()
        nums = _line_refs(raw)
        if nums and any(lo <= n <= hi for n in nums for lo, hi in ranges):
            return True
        if any(t in low for t in sink_idents):
            return True
        if any(t in low for t in chain_idents):
            return True
    return False


def _positive_evidence_ok(candidate: Candidate) -> bool:
    """正向告警的确定性断言：静态证据链存在；A4 还需客户端可控鉴权的真实证据。"""
    acc = candidate.access
    flow = " ".join(str(x) for x in (acc.flow or []))
    if candidate.subtype == "B6":
        return bool(flow) and bool(getattr(acc, "sensitive_fields", None))
    if candidate.subtype == "A4":
        return bool(flow) and ("客户端可控" in flow or "客户端可控" in (acc.sink_snippet or ""))
    return bool(flow) and not acc.ownership_predicate


def promote_with_counterexample(finding: Finding, ce: Dict[str, Any]) -> Finding:
    """维度二（可触发）满足：反例 + PoC 落证据。

    升级 CONFIRMED 需同时满足三维条件：
    1. LLM 对抗复核通过（llm_reasoning 非空）；
    2. LLM 给出了可核验证据（evidence_lines 能落到真实源码/标识符上）—— 只有结论、无证据不得升级；
    3. 引用（若给了「文件:行」）通过回验且覆盖 sink 行；
    4. 不存在「回验已确认拦截门真实存在」的反证（gate_verification == "passed"）。

    第 4 条的依据：符号执行只证明「数据路径可达」，不证明「授权缺失」。当回验器已在源码里
    找到注解/守卫/归属校验时，反例恰恰说明数据能到 sink，而门是否覆盖该资源访问仍属推断
    （策略矩阵 行5 ⚠ 只降级），因此不得借此把 LIKELY 升为 CONFIRMED。

    模型原先否定漏洞、但静态污点流 + 符号反例成立时仍可升级（证据优先于模型），但会改写
    reasoning 并记 model_verdict_overridden，避免报告里 CONFIRMED 与「非漏洞」文案并存。
    """
    ev = dict(finding.evidence)
    ev["counterexample"] = ce.get("counterexample")
    ev["symbolic_reachability"] = "sat"
    chk = ev.get("citation_check") or {}
    sink_ok = True
    if chk.get("total"):
        # 可追溯性闸门：引用必须能落到真实源码行，且覆盖 sink 行，才允许升级 CONFIRMED。
        sink_ok = bool(chk.get("verified")) and bool(chk.get("sink_covered"))
        if not sink_ok:
            ev["citation_block"] = "引用未通过回验（verified=%s, sink_covered=%s）" % (
                chk.get("verified"), chk.get("sink_covered"))
    # 反证闸门：回验器已确认拦截门存在时，数据可达不构成越权证据（行5：权限只降级）。
    gate_verified = ev.get("gate_verification") == "passed"
    if gate_verified:
        ev["promotion_block"] = "gate_verified"
    confirmed = (finding.llm_reasoning is not None and _evidence_sufficient(finding)
                 and sink_ok and not gate_verified)
    ev["evidence_verification"] = "passed" if confirmed else "failed"

    reasoning = finding.llm_reasoning
    if confirmed and ev.get("model_conclusion") == "not_vulnerable":
        ident = getattr(finding.candidate.access, "identifier_param", "") or "id"
        cev = ce.get("counterexample")
        example = f"（{ident}={cev}）" if cev is not None else ""
        ev["model_verdict_overridden"] = True
        reasoning = ("模型结论为「非漏洞」，但静态污点流成立且符号执行给出可满足反例"
                     f"{example}，按证据优先推翻模型否定。原模型结论：") + (reasoning or "")

    return Finding(
        candidate=finding.candidate,
        verdict="CONFIRMED" if confirmed else finding.verdict,
        subtype=finding.subtype,
        confidence=min(1.0, round(finding.confidence + 0.1, 2)) if confirmed else finding.confidence,
        llm_reasoning=reasoning,
        evidence=ev,
        poc=ce.get("poc"),
        fix_suggestion=finding.fix_suggestion,
        reachability_class="data",
        disposition="promote" if confirmed else finding.disposition,
    )


def unreachable_finding(finding: Finding, reach: Dict[str, Any]) -> Finding:
    """数据可达判定为 unsat（符号执行确定性证明不可触发）→ 自动关闭。"""
    ev = dict(finding.evidence)
    ev["symbolic_reachability"] = "unsat"
    ev["fact_class"] = "fact"
    ev["close_authority"] = "close_allowed"
    return Finding(
        candidate=finding.candidate, verdict="UNCERTAIN", subtype=finding.subtype,
        confidence=0.1,
        llm_reasoning="符号执行证明路径约束不可满足（数据路径不可触发），按不可达自动关闭。"
                      + (finding.llm_reasoning or ""),
        evidence=ev, fix_suggestion=None,
        reachability_class="data", disposition="auto_close",
    )


class VerdictPipeline:
    """候选 → Finding 的判定流程：缓存查询 → LLM 判定（+ 对抗复核）→ verdict。"""

    def __init__(self, judge=None, cache=None, adversarial: bool = True, samples: int = 3,
                 guards=None, max_seconds: float = 0.0, parallel_samples: bool = False):
        self.judge = judge
        self.cache = cache
        self.adversarial = adversarial
        self.samples = max(1, samples)  # 采样投票次数（reasoning 模型非确定性 → 多数投票稳定）
        self.guards = guards  # 框架鉴权上下文（RAG）：注入证据包供 LLM 判断上层鉴权
        self.cache_hits = 0
        self.llm_used = False
        self.max_seconds = max(0.0, max_seconds)  # D10：LLM 总预算（秒，0=不限）
        self.parallel_samples = parallel_samples  # D10：采样并发
        self.budget_exhausted = False

    @property
    def llm_available(self) -> bool:
        return self.judge is not None and bool(getattr(self.judge, "available", False))

    def _judge_vote(self, pkg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """多次采样投票（reasoning 模型非确定性）：多数 is_vulnerable + 平均 confidence。

        单次采样（samples=1）直接返回；多次采样按多数投票聚合，投票分歧时 confidence 打折、
        reasoning 标注采样一致性，避免单次 reasoning 波动导致结论翻转。
        """
        if self.samples <= 1:
            return self.judge.judge(pkg)
        if self.parallel_samples:
            with ThreadPoolExecutor(max_workers=min(self.samples, 4)) as ex:
                futures = [ex.submit(self.judge.judge, pkg) for _ in range(self.samples)]
                votes = [f.result() for f in futures]  # 保序，投票聚合仍可复现
        else:
            votes = [self.judge.judge(pkg) for _ in range(self.samples)]
        votes = [v for v in votes if v is not None]
        if not votes:
            return None
        n = len(votes)
        vuln = sum(1 for v in votes if v.get("is_vulnerable"))
        merged = dict(votes[0])
        merged["is_vulnerable"] = vuln > n / 2
        merged["confidence"] = round(sum(v.get("confidence", 0.0) for v in votes) / n, 3)
        agree = vuln if merged["is_vulnerable"] else (n - vuln)
        if agree < n:
            merged["confidence"] = round(merged["confidence"] * 0.7, 3)
            merged["reasoning"] = f"[{agree}/{n} 采样一致，存在分歧] " + (votes[0].get("reasoning") or "")
        else:
            merged["reasoning"] = f"[{agree}/{n} 采样一致] " + (votes[0].get("reasoning") or "")
        return merged

    def run(self, candidates: Sequence[Candidate], root=None) -> List[Finding]:
        findings: List[Finding] = []
        started = time.perf_counter()
        for c in candidates:
            build_hint = (getattr(c, "reachability_hints", None) or {}).get("build")
            if build_hint:
                # 构建不可达（确定性）→ 自动关闭，不调用 LLM
                findings.append(reachability_finding(c, build_hint, "build"))
                continue
            hints = getattr(c, "reachability_hints", None) or {}
            if hints.get("registration_deterministic") and hints.get("registration"):
                # Spring 扫描事实（代码事实，非 LLM 推断）→ 自动关闭，不调用 LLM
                findings.append(reachability_finding(c, hints["registration"], "registration"))
                continue
            if hints.get("data"):
                # 数据流事实（sink 已含归属约束）→ 自动关闭，不调用 LLM
                findings.append(data_fact_finding(c, hints["data"]))
                continue
            pkg = build_evidence_pkg(c, self.guards)
            key = evidence_key(pkg)
            cached = self.cache.get(key) if self.cache is not None else None
            if cached is not None:
                self.cache_hits += 1
                findings.append(decide(c, cached["llm"],
                                       cached.get("upheld"), cached.get("adv_reason", ""),
                                       self.guards, root))
                continue
            if not self.llm_available:
                findings.append(static_only_finding(c))
                continue
            if self.max_seconds and time.perf_counter() - started > self.max_seconds:
                # D10：总时长超预算 → 快速降级为静态 LIKELY，避免整轮卡死
                self.budget_exhausted = True
                findings.append(static_only_finding(c))
                continue
            self.llm_used = True
            llm = self._judge_vote(pkg)
            if llm is None:
                findings.append(static_only_finding(c))  # 超时/拒绝 → LIKELY 兜底
                continue
            upheld: Optional[bool] = None
            adv_reason = ""
            if self.adversarial and llm.get("is_vulnerable"):
                adv = self.judge.adversarial(pkg, llm)
                if adv is not None:
                    upheld = not bool(adv.get("refuted"))
                    adv_reason = adv.get("reasoning", "")
            f = decide(c, llm, upheld, adv_reason, self.guards, root)
            if self.cache is not None:
                self.cache.put(key, {"llm": llm, "upheld": upheld, "adv_reason": adv_reason})
            findings.append(f)
        return findings