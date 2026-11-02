"""SARIF 2.1.0 输出（方案 §6.5）。

映射：ruleId = A1/A2/A3/A4；level = CONFIRMED→error / LIKELY→warning / UNCERTAIN→note；
region 用行号；partialFingerprints 用 code_hash（file:line:subtype）保证增量去重。
"""
import hashlib
from typing import Any, Dict, List, Sequence

from ..ir import Finding

_LEVEL = {"CONFIRMED": "error", "LIKELY": "warning", "UNCERTAIN": "note"}

_RULES = {
    "A1": "水平越权（IDOR）：篡改资源 ID 访问他人资源",
    "A2": "垂直越权：低权限用户调用高权限接口",
    "A3": "未授权访问：接口无任何鉴权即访问资源",
    "A4": "失效的访问控制：鉴权逻辑可被客户端输入绕过",
    "B6": "属性级越权：返回体暴露敏感字段（字段级授权缺失）",
}


def _code_hash(finding: Finding) -> str:
    ep = finding.candidate.endpoint
    raw = f"{ep.file}:{ep.line_start}:{finding.subtype}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _message(finding: Finding) -> str:
    base = ""
    if finding.llm_reasoning:
        base = finding.llm_reasoning
    else:
        acc = finding.candidate.access
        base = (f"[{finding.subtype}] 静态证据: {' | '.join(acc.flow)} "
                f"({finding.candidate.endpoint.method} {finding.candidate.endpoint.path})")
    if finding.poc:
        base += f"\nPoC: {finding.poc}"
    fields = (finding.evidence or {}).get("sensitive_fields")
    if fields:
        base += f"\n敏感字段: {', '.join(str(x) for x in fields)}"
    return base


def render(findings: Sequence[Finding]) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for f in findings:
        ep = f.candidate.endpoint
        region = {"startLine": ep.line_start}
        if ep.line_end >= ep.line_start:
            region["endLine"] = ep.line_end
        results.append({
            "ruleId": f.subtype,
            "level": _LEVEL.get(f.verdict, "warning"),
            "message": {"text": _message(f)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": ep.file.replace("\\", "/")},
                    "region": region,
                }
            }],
            "partialFingerprints": {"accessScanCodeHash": _code_hash(f)},
            "properties": {
                "verdict": f.verdict,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "fix": f.fix_suggestion,
                "poc": f.poc,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "access-scan",
                    "informationUri": "https://example.invalid/access-scan",
                    "rules": [
                        {"id": k, "name": k, "shortDescription": {"text": v}}
                        for k, v in _RULES.items()
                    ],
                }
            },
            "results": results,
        }],
    }