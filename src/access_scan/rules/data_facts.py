"""数据事实模块：把「数据流到 sink」相关的可执行证据归并为处置提示。

三类事实（只有前两类可确定性关闭，类型收窄只降级）：
1. **归属约束**：sink 查询已含 owner 过滤（ownership_predicate=true）→ 无越权风险，
   可自动关闭（规则 A 已在上游过滤，本层作为防御性事实）；
2. **数据流可达性**：符号执行三态（sat/unsat/unsound）由 symexec 判定 —— unsat
   自动关闭、sat 升级、unsound 保持不动（不重复实现，只在 hint 中标注）；
3. **类型收窄**：资源标识为 UUID/GUID/ULID/ObjectId —— 这是「不可枚举」的运行时
   假设，不是代码事实，因此只降级标注，绝不自动关闭。
"""
import re
from typing import Any, Dict, Optional

from ..ir import Candidate

_NARROW_TYPE_RE = re.compile(r"\b(?:uuid|guid|ulid)\b|objectid", re.I)


def identifier_param(candidate: Candidate) -> Optional[Any]:
    ident = (candidate.access.identifier_param or "").strip()
    if not ident:
        return None
    for p in candidate.endpoint.params:
        if p.name == ident:
            return p
    return None


def is_type_narrowed(param_type: str) -> bool:
    """资源标识类型是否属于不可枚举类（UUID/GUID/ULID/ObjectId）。"""
    return bool(_NARROW_TYPE_RE.search(param_type or ""))


def data_fact_hints(candidate: Candidate) -> Dict[str, str]:
    """数据事实 → 可达性提示（供 verdict 层关闭 / 降级）。"""
    acc = candidate.access
    flow = " ".join(str(x) for x in (acc.flow or []) if str(x).strip())
    if not flow or not acc.sink_snippet:
        return {}  # 数据流未到 sink：无事实可用
    if acc.ownership_predicate:
        return {"data": "sink 查询已含归属约束（ownership_predicate=true）"}
    param = identifier_param(candidate)
    if param is not None and is_type_narrowed(getattr(param, "type", "")):
        return {"data_downgrade":
                f"资源标识类型为 {param.type}（不可枚举假设，仅降级不关闭）"}
    return {}
