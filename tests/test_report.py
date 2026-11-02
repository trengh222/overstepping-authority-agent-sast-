"""Markdown 报告渲染验证。"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.report.markdown import render


def test_markdown_empty():
    assert "未发现越权候选" in render([])


def test_markdown_finding():
    from access_scan import cli
    fs, _ = cli.run(_REPO / "tests" / "fixtures" / "java" / "idor_branch",
                    judge=None, adversarial=False, symbolic=False)
    md = render(fs)
    assert "# 越权检测报告" in md
    assert "GET /api/order/{id}" in md
    assert "证据链" in md
    assert "修复建议" in md
    assert "LIKELY" in md
