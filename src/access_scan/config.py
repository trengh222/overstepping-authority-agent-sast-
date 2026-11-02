"""配置加载：ownership.yaml / rules.yaml（方案 §8 / §6.3）。"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]  # src/access_scan -> src -> 仓库根
DEFAULT_CONFIG_DIR = _PACKAGE_ROOT / "config"


def load_yaml(name: str, config_dir: Optional[Path] = None) -> Dict[str, Any]:
    d = config_dir or Path(os.environ.get("ACCESS_SCAN_CONFIG_DIR", str(DEFAULT_CONFIG_DIR)))
    path = d / f"{name}.yaml"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_rules(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """L4 过滤规则（exclude_prefixes / gateway_protected_prefixes）。"""
    return load_yaml("rules", config_dir)


def load_feature_flags(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """配置开关声明：{flag_name: bool}（config/feature_flags.yaml，可达性剪枝用）。"""
    cfg = load_yaml("feature_flags", config_dir)
    return cfg.get("flags", {}) or {}


def load_llm(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """LLM 判定层配置：{model, base_url, auth_token}（config/llm.yaml）。"""
    return load_yaml("llm", config_dir)


def load_ownership(config_dir: Optional[Path] = None) -> Dict[str, Any]:
    """所有权模型：{entity(lower) -> 声明} + default_privacy。

    合并来源：config/ownership.yaml（人工声明）+ config/ownership.feedback.yaml（打标反馈），
    反馈条目后写入，覆盖同名实体的声明（方案 §8 反馈闭环）。
    """
    cfg = load_yaml("ownership", config_dir)
    fb = load_yaml("ownership.feedback", config_dir)
    table: Dict[str, Dict[str, Any]] = {}
    for r in (cfg.get("resources", []) or []) + (fb.get("resources", []) or []):
        table[r["entity"].lower()] = r
    return {"table": table, "default_privacy": cfg.get("default_privacy", "UNKNOWN")}


def lookup_ownership(entity: Optional[str], model: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not entity:
        return None
    return model["table"].get(entity.lower())


# 字段级敏感性默认名单（config/ownership.yaml 的 sensitive_fields 可覆盖；正则，匹配字段名）
DEFAULT_SENSITIVE_FIELDS = [
    r"phone", r"mobile", r"tel", r"email", r"mail", r"id_?card", r"idcard",
    r"real_?name", r"address", r"bank_?card", r"card_?no", r"balance",
    r"salary", r"password", r"passwd", r"pwd", r"access_?token",
    r"refresh_?token", r"birthday", r"birth_?date", r"ssn",
]


def load_sensitive_fields(config_dir: Optional[Path] = None) -> List[str]:
    """字段级敏感性名单（规则 B6：属性级越权/敏感字段暴露）。

    读 config/ownership.yaml 的 `sensitive_fields`；未声明则用内置默认名单。
    名单元素是正则片段，匹配字段名（匹配时忽略大小写与下划线）。
    """
    cfg = load_yaml("ownership", config_dir)
    declared = cfg.get("sensitive_fields") or []
    out = [str(p) for p in declared if str(p).strip()]
    return out or list(DEFAULT_SENSITIVE_FIELDS)


def record_ownership_feedback(entity: str, privacy: str, reason: str = "",
                              config_dir: Optional[Path] = None) -> Path:
    """人工打标回写（方案 M3.1）：追加/覆盖 ownership.feedback.yaml 中该实体的声明。"""
    d = config_dir or Path(os.environ.get("ACCESS_SCAN_CONFIG_DIR", str(DEFAULT_CONFIG_DIR)))
    path = d / "ownership.feedback.yaml"
    data: Dict[str, Any] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    res = [r for r in data.get("resources", []) or []
           if str(r.get("entity", "")).lower() != entity.lower()]
    entry: Dict[str, Any] = {"entity": entity, "privacy": privacy}
    if reason:
        entry["comment"] = reason
    res.append(entry)
    data["resources"] = res
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path