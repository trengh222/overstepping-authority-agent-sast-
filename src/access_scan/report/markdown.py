"""Markdown 人读报告（方案 §6.5 / §11.3）：证据链 + PoC + 修复建议。"""
from collections import Counter
from typing import Sequence

from ..ir import Finding

# 结论标记（避免 emoji，纯文本兼容）
_LEVEL_MARK = {"CONFIRMED": "[严重]", "LIKELY": "[疑似]", "UNCERTAIN": "[待定]"}
_SUBTYPE_DESC = {
    "A1": "水平越权（IDOR）",
    "A2": "垂直越权",
    "A3": "未授权访问",
    "A4": "失效访问控制",
    "B6": "属性级越权（敏感字段暴露）",
}
# 五类可达性 + 处置边界
_CLASS_DESC = {
    "build": "构建可达", "registration": "注册可达", "config": "配置可达",
    "permission": "权限可达", "data": "数据可达", "none": "未知可达",
}
_DISP_DESC = {
    "auto_close": "自动关闭", "downgrade_ticket": "降级+工单",
    "downgrade_annotate": "降级+标注", "keep": "保持", "promote": "确定性升级",
}


def render(findings: Sequence[Finding]) -> str:
    if not findings:
        return "# 越权检测报告\n\n未发现越权候选。\n"

    stats = Counter(f.verdict for f in findings)
    disp = Counter(f.disposition for f in findings)
    lines = [
        "# 越权检测报告",
        "",
        "## 结论汇总",
        "",
        "| 结论 | 数量 |",
        "|---|---|",
        f"| CONFIRMED（确认） | {stats['CONFIRMED']} |",
        f"| LIKELY（疑似） | {stats['LIKELY']} |",
        f"| UNCERTAIN（待定） | {stats['UNCERTAIN']} |",
        "",
        "| 处置 | 数量 |",
        "|---|---|",
        f"| 自动关闭 | {disp['auto_close']} |",
        f"| 降级+工单 | {disp['downgrade_ticket']} |",
        f"| 降级+标注 | {disp['downgrade_annotate']} |",
        f"| 保持 | {disp['keep']} |",
        f"| 确定性升级 | {disp['promote']} |",
        "",
        "---",
        "",
    ]

    for i, f in enumerate(findings, 1):
        ep = f.candidate.endpoint
        acc = f.candidate.access
        lines.append(
            f"## {i}. {_LEVEL_MARK.get(f.verdict, '')} "
            f"{_SUBTYPE_DESC.get(f.subtype, f.subtype)}（{f.verdict}）"
        )
        lines.append("")
        lines.append(f"- **端点**: `{ep.method} {ep.path}`")
        lines.append(f"- **位置**: `{ep.file}:{ep.line_start}-{ep.line_end}`")
        lines.append(f"- **置信度**: {f.confidence:.2f}")
        lines.append(f"- **证据链**: `{' → '.join(acc.flow)}`")
        lines.append(f"- **sink**: `{acc.sink_snippet}`")
        if acc.sensitive_fields:
            lines.append(f"- **敏感字段**: `{', '.join(acc.sensitive_fields)}`（返回体未脱敏）")
        dyn = f.evidence.get("dynamic_sites")
        if dyn:
            lines.append(f"- **动态分派**: {', '.join(str(x) for x in dyn)}（反射点存在，需人工复核）")

        if f.reachability_class != "none":
            lines.append(
                f"- **可达性**: {_CLASS_DESC.get(f.reachability_class, f.reachability_class)}"
                f"（处置：{_DISP_DESC.get(f.disposition, f.disposition)}）")
        authority = f.evidence.get("close_authority")
        if authority:
            lines.append(f"- **关闭权限**: `{authority}`（事实类别 `{f.evidence.get('fact_class')}`）")
        if f.evidence.get("model_inference"):
            lines.append(f"- **模型推断（未作为证据）**: {f.evidence['model_inference']}")

        if f.evidence.get("counterexample") is not None:
            lines.append(f"- **符号反例**: 资源 ID = `{f.evidence['counterexample']}`")

        if f.llm_reasoning:
            lines.append("")
            lines.append("**LLM 判定意见**")
            lines.append("")
            lines.append(f.llm_reasoning)

        if f.poc:
            lines.append("")
            lines.append("**PoC**")
            lines.append("")
            lines.append("```")
            lines.append(f.poc.rstrip("\n"))
            lines.append("```")

        if f.fix_suggestion:
            lines.append("")
            lines.append(f"**修复建议**: {f.fix_suggestion}")

        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
