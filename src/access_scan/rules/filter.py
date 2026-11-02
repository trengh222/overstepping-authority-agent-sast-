"""L4 过滤层（方案 §6.3）：排除前缀、公开资源丢弃、网关保护降级。"""
import re
from typing import Dict, List, Sequence, Tuple

from ..ir import Candidate, Finding, Resource


def _norm_entity(entity: str) -> List[str]:
    """实体名归一化候选：'Order' -> ['order']；'t_order' -> ['t_order', 'order']。"""
    e = (entity or "").lower().strip()
    if not e:
        return []
    out = [e]
    if e.startswith("t_"):
        out.append(e.split("_", 1)[1])
    return out


def _entity_privacy(resources: Sequence[Resource]) -> Dict[str, str]:
    m: Dict[str, str] = {}
    for r in resources:
        for k in _norm_entity(r.entity):
            m.setdefault(k, r.privacy)
    return m


# 写/删/改类 sink：公开资源只豁免「读」，写入他人（或任意）记录仍属越权
_WRITE_SINK_RE = re.compile(
    r"(?:^|\.)(?:save|insert|upsert|update|delete|remove|add|batch|approve|reject|"
    r"refund|transfer|publish|audit|grant)\w*$", re.I)


def _is_write_access(access) -> bool:
    flow = access.flow or []
    if not flow:
        return False
    return bool(_WRITE_SINK_RE.search(str(flow[-1]).strip()))


def apply_filters(candidates: Sequence[Candidate], rules_cfg: Dict,
                  resources: Sequence[Resource]) -> Tuple[List[Candidate], List[Candidate]]:
    """按 config/rules.yaml 与所有权模型过滤。

    返回 (kept, gateway_downgrade)：
    - 丢弃：路径命中 exclude_prefixes；A1 且实体隐私为 PUBLIC；
    - 降级：A2/A3/A4 且路径命中 gateway_protected_prefixes（校验可能在网关）。
    """
    excludes = rules_cfg.get("exclude_prefixes") or []
    gateways = rules_cfg.get("gateway_protected_prefixes") or []
    priv_map = _entity_privacy(resources)

    kept: List[Candidate] = []
    gateway: List[Candidate] = []
    for c in candidates:
        path = c.endpoint.path
        if any(path.startswith(p) for p in excludes):
            continue
        if c.subtype == "A1":
            # 公开资源（所有权模型声明 PUBLIC）只豁免读访问；写/删仍按越权处理
            if any(priv_map.get(k) == "PUBLIC" for k in _norm_entity(c.access.entity)) \
                    and not _is_write_access(c.access):
                continue
        if c.subtype in ("A2", "A3", "A4") and any(path.startswith(p) for p in gateways):
            gateway.append(c)
            continue
        kept.append(c)
    return kept, gateway


def gateway_finding(candidate: Candidate) -> Finding:
    """网关保护前缀命中 → 保留候选但降级置信度（方案 §6.3：校验可能在网关）。

    语义按方案「降级」而非「隐藏」：仍以 LIKELY 输出 + 低置信度，
    降级理由写入证据，由人工/后续阶段决定是否排除。
    """
    return Finding(
        candidate=candidate, verdict="LIKELY", subtype=candidate.subtype, confidence=0.3,
        llm_reasoning="命中 gateway_protected_prefixes（config/rules.yaml），鉴权可能在网关完成，置信度降级",
        disposition="keep",
        evidence={"rule_id": candidate.rule_id, "taint_flow": candidate.access.flow,
                  "gateway_protected": True, "fact_class": "inference",
                  "close_authority": "downgrade_only"},
        fix_suggestion=None,
    )