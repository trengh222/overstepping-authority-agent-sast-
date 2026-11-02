"""M7-① 字段敏感性 / 属性级越权（规则 B6）离线验证。

运行：python tests/test_m7_field_exposure.py
覆盖：敏感字段命中、@JsonIgnore 脱敏豁免、公开认证路径豁免、字段类型解析
（局部变量 / new 构造 / 包装解剥）、config 名单加载、decide 层 B6 正向判定。
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.config import load_sensitive_fields
from access_scan.llm.verdict import decide, static_only_finding, _static_evidence

_CONTROLLER = """package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/order")
public class OrderController {

    @GetMapping("/detail/{orderId}")
    public Object detail(Integer orderId) {
        OrderDetailVO vo = new OrderDetailVO();
        vo.setOrderId(orderId);
        return getSuccessResponseVO(vo);
    }

    @GetMapping("/login")
    public Object login() {
        OrderDetailVO vo = new OrderDetailVO();
        return getSuccessResponseVO(vo);
    }

    @GetMapping("/plain/{orderId}")
    public Object plain(Integer orderId) {
        OrderPlainVO vo = new OrderPlainVO();
        return getSuccessResponseVO(vo);
    }
}
"""

_VO_SENSITIVE = """package com.demo;

public class OrderDetailVO {
    private Integer orderId;
    private String email;
    private String phone;
    private String userName;
    private String avatar;
}
"""

_VO_IGNORED = """package com.demo;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class OrderDetailVO {
    private Integer orderId;
    private String email;
    @JsonIgnore
    private String phone;
}
"""

_VO_PLAIN = """package com.demo;

public class OrderPlainVO {
    private Integer orderId;
    private String userName;
    private String avatar;
}
"""

_VULN_LLM = {
    "is_vulnerable": True, "subtype": "B6", "confidence": 0.8,
    "resource_privacy": "PRIVATE", "reasoning": "返回体含 email/phone",
    "evidence_lines": ["line 12: return getSuccessResponseVO(vo)"],
    "uncertain_reason": "", "reachability": "reachable", "blocking_gate": None,
}


def _scan(tmp: Path, controller: str, vo: str) -> list:
    (tmp / "OrderController.java").write_text(controller, encoding="utf-8")
    (tmp / "OrderDetailVO.java").write_text(vo, encoding="utf-8")
    cands, _gateway = cli.scan(tmp)
    return cands


def _b6(cands: list):
    return [c for c in cands if c.subtype == "B6"]


def test_sensitive_fields_detected():
    with tempfile.TemporaryDirectory() as d:
        cands = _b6(_scan(Path(d), _CONTROLLER, _VO_SENSITIVE))
        assert cands, "敏感字段 VO 应产出 B6 候选"
        c = cands[0]
        assert c.rule_id == "B6-field-exposure"
        assert sorted(c.access.sensitive_fields) == ["email", "phone"], c.access.sensitive_fields
        assert c.access.entity == "OrderDetailVO"
        assert "/order/detail" in c.endpoint.path
        print("ok: 敏感字段命中 email/phone")


def test_json_ignore_exempts_field():
    with tempfile.TemporaryDirectory() as d:
        cands = _b6(_scan(Path(d), _CONTROLLER, _VO_IGNORED))
        assert cands, "仍有 email 未脱敏，应产出 B6"
        assert cands[0].access.sensitive_fields == ["email"], cands[0].access.sensitive_fields
        print("ok: @JsonIgnore 字段被豁免")


def test_public_login_path_exempt():
    with tempfile.TemporaryDirectory() as d:
        cands = _b6(_scan(Path(d), _CONTROLLER, _VO_SENSITIVE))
        paths = {c.endpoint.path for c in cands}
        assert not any("/order/login" in p for p in paths), paths
        print("ok: 登录路径豁免")


def test_no_sensitive_field_no_candidate():
    with tempfile.TemporaryDirectory() as d:
        cands = _b6(_scan(Path(d), _CONTROLLER, _VO_PLAIN))
        assert not any("/order/plain" in c.endpoint.path for c in cands), \
            [c.endpoint.path for c in cands]
        print("ok: 无敏感字段不产出")


def test_sensitive_list_loaded_from_config():
    patterns = load_sensitive_fields()
    assert patterns and any("email" in p for p in patterns), patterns
    print(f"ok: config 敏感名单 {len(patterns)} 条")


def test_decide_keeps_b6_as_likely_with_evidence():
    with tempfile.TemporaryDirectory() as d:
        cands = _b6(_scan(Path(d), _CONTROLLER, _VO_SENSITIVE))
        cand = cands[0]
        f = decide(cand, dict(_VULN_LLM))
        assert f.verdict == "LIKELY", f.verdict
        assert f.disposition == "keep", f.disposition
        assert f.evidence.get("sensitive_fields") == cand.access.sensitive_fields
        static = static_only_finding(cand)
        assert static.verdict == "LIKELY"
        assert static.evidence.get("sensitive_fields")
        print("ok: decide 层 B6 保持 LIKELY 并落敏感字段证据")


if __name__ == "__main__":
    test_sensitive_fields_detected()
    test_json_ignore_exempts_field()
    test_public_login_path_exempt()
    test_no_sensitive_field_no_candidate()
    test_sensitive_list_loaded_from_config()
    test_decide_keeps_b6_as_likely_with_evidence()
    print("all M7 field-exposure tests passed")
