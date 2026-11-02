"""easylive 人工基线 vs access-scan 结果比对（TP/FP/FN + 精确率/召回率）。

基线来源：人工审计结论（runs 目录外的 m00303 回答），逐条标注 TP（真漏洞）/TN（安全/公开）。
用法: python tools/compare_baseline.py <findings.json> [--out report.txt]
"""
import json
import re
import sys
from pathlib import Path

# (path 正则, 期望, 说明) —— 期望 TP=真漏洞应报, TN=安全不应报
BASELINE = [
    (r"^/statisticsInfo/loadDataList$", "TP", "B1 未授权读统计"),
    (r"^/statisticsInfo/add$", "TP", "B1 未授权写统计"),
    (r"^/statisticsInfo/addBatch$", "TP", "B1 未授权批量写统计"),
    (r"^/statisticsInfo/addOrUpdateBatch$", "TP", "B1 未授权批量写"),
    (r"^/statisticsInfo/getStatisticsInfoByStatisticsDateAndUserIdAndDataType$", "TP", "B1/C2 任意 userId 读"),
    (r"^/statisticsInfo/updateStatisticsInfoByStatisticsDateAndUserIdAndDataType$", "TP", "B1/C2 任意 userId 改"),
    (r"^/statisticsInfo/deleteStatisticsInfoByStatisticsDateAndUserIdAndDataType$", "TP", "B1/C2 任意 userId 删"),
    (r"^/uhome/loadUserCollection$", "TP", "B2 注解被注释，未登录读他人收藏"),
    (r"^/uhome/series/loadVideoSeriesWithVideo$", "TP", "B3 未授权枚举他人合集"),
    (r"^/uhome/series/getVideoSeriesDetail$", "TP", "B4 未授权任意 seriesId"),
    (r"^/uhome/series/loadVideoSeries$", "TP", "C1 登录后任意 userId 读他人合集"),
    (r"^/history/test$", "TP", "B5 内部统计接口暴露"),
    (r"^/file/getResource$", "TP", "B6 未授权读 file/ 资源"),
    (r"^/file/videoResource/\{fileId\}$", "TP", "B6/C3 未授权按 fileId 取视频"),
    (r"^/file/videoResource/\{fileId\}/\{ts\}$", "TP", "B6 ts 参数未过 pathIsOk"),
    (r"^/comment/topComment$", "TP", "B7 缺鉴权注解 + 服务层校验"),
    (r"^/comment/cancelTopComment$", "TP", "B7 缺鉴权注解 + 服务层校验"),
    (r"^/comment/userDelComment$", "TP", "B7 缺鉴权注解 + 服务层校验"),
    # ---- 负样本：安全或设计上公开 ----
    (r"^/ucenter/getVideoByVideoId$", "TN", "D1 显式 owner 校验"),
    (r"^/ucenter/deleteVideo$", "TN", "D2 服务层 owner 校验"),
    (r"^/ucenter/saveVideoInteraction$", "TN", "D3 update 带 userId"),
    (r"^/ucenter/delDanmu$", "TN", "D5 服务层 owner 校验"),
    (r"^/uhome/series/saveSeriesVideo$", "TN", "D4 服务层 userId"),
    (r"^/uhome/series/delSeriesVideo$", "TN", "D4 服务层 userId"),
    (r"^/uhome/series/delVideoSeries$", "TN", "D4 服务层 userId"),
    (r"^/comment/postComment$", "TN", "D5 需登录"),
    (r"^/comment/loadComment$", "TN", "公开评论列表"),
    (r"^/uhome/getUserInfo$", "TN", "D7 公开资料，UserInfoVO 无敏感字段"),
    (r"^/video/getVideoInfo$", "TN", "公开视频信息"),
    (r"^/video/getVideoRecommend$", "TN", "公开推荐"),
    (r"^/video/reportVideoPlayOnline$", "TN", "匿名播放上报"),
    (r"^/file/uploadVideo$", "TN", "需登录（@GlobalInterceptor 未识别→已知误报源）"),
    (r"^/file/delUploadVideo$", "TN", "需登录（同上）"),
    (r"^/ucenter/delComment$", "TN", "需登录（同上）"),
]


def main(path: str) -> None:
    data = json.load(open(path, encoding="utf-8"))
    items = data.get("findings") if isinstance(data, dict) else data
    reported = {}
    for f in items or []:
        ep = (f.get("candidate") or {}).get("endpoint") or {}
        p = ep.get("path") or ""
        reported.setdefault(p, []).append(f)

    tp = fp = fn = tn = 0
    lines = [f"findings 总数={len(items or [])}，去重端点={len(reported)}", ""]
    lines.append(f"{'期望':<4} {'实际':<10} {'路径':<64} 说明")
    for pat, expect, note in BASELINE:
        rx = re.compile(pat)
        hits = [p for p in reported if rx.match(p)]
        if expect == "TP":
            if hits:
                tp += 1
                verdicts = sorted({str(f.get("verdict")) for p in hits for f in reported[p]})
                lines.append(f"{'TP':<4} {'命中':<10} {pat[:64]:<64} {note}  [{','.join(verdicts)}]")
            else:
                fn += 1
                lines.append(f"{'TP':<4} {'漏报':<10} {pat[:64]:<64} {note}")
        else:
            if hits:
                fp += 1
                lines.append(f"{'TN':<4} {'误报':<10} {pat[:64]:<64} {note}")
            else:
                tn += 1
                lines.append(f"{'TN':<4} {'正确未报':<10} {pat[:64]:<64} {note}")

    labeled = {re.compile(p) for p, _, _ in BASELINE}
    extra = [p for p in reported if not any(rx.match(p) for rx in labeled)]
    lines += ["", f"未标注端点（既不在基线正样本也不在负样本）：{len(extra)}"]
    for p in sorted(extra):
        lines.append(f"    ? {p}")

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    lines += ["", f"TP={tp} FP={fp} FN={fn} TN={tn}",
              f"精确率 precision = {prec:.1%}  ({tp}/{tp + fp})",
              f"召回率 recall    = {rec:.1%}  ({tp}/{tp + fn})"]
    text = "\n".join(lines)
    print(text)
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else None
    if out:
        Path(out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "findings.json")
