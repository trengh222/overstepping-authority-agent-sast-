"""仓库配置键解析 + 配置可达证据测试。

运行：python -m pytest tests/test_repo_config.py -q
覆盖：application.yml/properties/.env 解析、嵌套键展平、profile 冲突/动态值、
工具配置优先级，以及「声明 false → 降级工单」「键缺失 → 只降级不关闭」。
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.llm.verdict import decide
from access_scan.rules.reachability import collect_flag_refs
from access_scan.rules.repo_config import collect_repo_flags

_REACH = _REPO / "tests" / "fixtures" / "reachability"

_LLM = {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
        "resource_privacy": "PRIVATE", "reasoning": "仅按 id 查询",
        "evidence_lines": ["第 12 行：Order.query.get(oid) 无归属过滤"]}

_SRC = "if not config['orders.export.enabled']:\n    return 'disabled', 403"


def _w(root: Path, name: str, text: str) -> Path:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---------------- 解析 ----------------

def test_yaml_nested_flatten(tmp_path):
    _w(tmp_path, "application.yml", "orders:\n  export:\n    enabled: false\n")
    assert collect_repo_flags(tmp_path) == {"orders.export.enabled": False}


def test_properties_and_env(tmp_path):
    props = tmp_path / "props"
    _w(props, "application.properties", "orders.export.enabled=true\n")
    assert collect_repo_flags(props)["orders.export.enabled"] is True
    env = tmp_path / "env"
    _w(env, ".env", "ORDERS_EXPORT_ENABLED=0\n")
    assert collect_repo_flags(env)["orders.export.enabled"] is False, \
        "env 键归一化并按 0/1 解析"


def test_profile_conflict_is_unknown(tmp_path):
    _w(tmp_path, "application.yml", "orders:\n  export:\n    enabled: true\n")
    _w(tmp_path, "application-prod.yaml", "orders:\n  export:\n    enabled: false\n")
    flags = collect_repo_flags(tmp_path)
    assert "orders.export.enabled" in flags and flags["orders.export.enabled"] is None


def test_dynamic_value_is_unknown(tmp_path):
    _w(tmp_path, "application.yml",
       "orders:\n  export:\n    enabled: ${ORDERS_EXPORT_ENABLED:true}\n")
    flags = collect_repo_flags(tmp_path)
    assert flags["orders.export.enabled"] is None


def test_key_missing_not_declared(tmp_path):
    _w(tmp_path, "application.yml", "other:\n  flag: true\n")
    assert "orders.export.enabled" not in collect_repo_flags(tmp_path)


def test_non_config_files_ignored(tmp_path):
    _w(tmp_path, "random.yml", "orders:\n  export:\n    enabled: false\n")
    assert collect_repo_flags(tmp_path) == {}


# ---------------- flag_refs 合并 ----------------

def test_explicit_config_wins_over_repo():
    refs = collect_flag_refs(_SRC, {"orders.export.enabled": True},
                             {"orders.export.enabled": False})
    assert refs == [{"name": "orders.export.enabled", "declared": True}]


def test_repo_value_used_when_not_explicit():
    refs = collect_flag_refs(_SRC, {}, {"orders.export.enabled": False})
    assert refs == [{"name": "orders.export.enabled", "declared": False}]


# ---------------- 端到端 ----------------

def _cand(fixture: str, path: str):
    cands, _ = cli.scan(_REACH / fixture)
    return [c for c in cands if c.endpoint.path == path][0]


def test_scan_repo_config_off():
    c = _cand("java_repo_off", "/api/orders/{oid}")
    assert c.flag_refs == [{"name": "orders.export.enabled", "declared": False}]


def test_decide_repo_config_off_downgrades():
    c = _cand("java_repo_off", "/api/orders/{oid}")
    f = decide(c, dict(_LLM, reachability="unreachable"))
    assert f.verdict == "UNCERTAIN"
    assert f.reachability_class == "config" and f.disposition == "downgrade_ticket"


def test_scan_repo_config_missing():
    c = _cand("java_repo_missing", "/api/shipment/{oid}")
    assert c.flag_refs == [{"name": "shipment.export.enabled", "declared": None}]


def test_decide_repo_missing_only_downgrades():
    c = _cand("java_repo_missing", "/api/shipment/{oid}")
    f = decide(c, dict(_LLM, reachability="needs_config"))
    assert f.verdict == "LIKELY" and f.disposition == "downgrade_ticket"
    assert f.reachability_class == "config"
    f2 = decide(c, dict(_LLM, reachability="unreachable"))
    assert f2.verdict == "LIKELY", "键缺失时不得按不可达关闭"
    assert f2.evidence.get("reachability_verification") == "no_disabled_flag"
