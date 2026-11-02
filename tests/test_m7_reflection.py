"""M7-② 反射 / 动态分派识别离线验证。

运行：python tests/test_m7_reflection.py
覆盖：反射点识别（方法反射/类加载/BeanUtils 拷贝）、hint 文本、
scan 层把 dynamic 标记写到 ResourceAccess、verdict 层按反射点降置信度
（bean-copy 只记录不降级）、静态兜底同样降级。
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.dataflow import asts
from access_scan.extractor.java import JavaExtractor
from access_scan.llm.verdict import decide, static_only_finding
from access_scan.rules.reflection import has_reflection_text, reflection_hint, reflection_sites

_REFLECT_CTRL = """package com.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.BeanUtils;

@RestController
@RequestMapping("/admin")
public class AdminReflectController {

    @GetMapping("/run/{id}")
    public Object run(Integer id) throws Exception {
        OrderDao dao = new OrderDao();
        Object row = dao.selectById(id);
        java.lang.reflect.Method m = getClass().getDeclaredMethod("handle", Integer.class);
        m.invoke(this, row);
        return row;
    }

    @GetMapping("/copy/{id}")
    public Object copy(Integer id) {
        OrderDao dao = new OrderDao();
        Object row = dao.selectById(id);
        BeanUtils.copyProperties(row, row);
        return row;
    }

    @GetMapping("/plain/{id}")
    public Object plain(Integer id) {
        OrderDao dao = new OrderDao();
        return dao.selectById(id);
    }
}
"""


def _scan(tmp: Path) -> list:
    (tmp / "AdminReflectController.java").write_text(_REFLECT_CTRL, encoding="utf-8")
    cands, _gateway = cli.scan(tmp)
    return cands


def test_reflection_sites_java():
    ext = JavaExtractor()
    src = b"""class A {
    void f(Object x) throws Exception {
        java.lang.reflect.Method m = getClass().getDeclaredMethod("h");
        m.invoke(this, x);
        BeanUtils.copyProperties(x, x);
        Class.forName("com.demo.Hidden");
    }
}"""
    tree = ext.parse(src)
    sites = reflection_sites(tree, "java")
    kinds = {s["kind"] for s in sites}
    assert "method-invoke" in kinds, kinds
    assert "reflective-method" in kinds, kinds
    assert "classloader" in kinds, kinds
    assert "bean-copy" in kinds, kinds
    lines = [s["line"] for s in sites]
    assert lines == sorted(lines), lines
    print(f"ok: 反射点识别 {sorted(kinds)}")


def test_no_sites_on_plain_code():
    ext = JavaExtractor()
    tree = ext.parse(b"class A { void f() { dao.selectById(1); } }")
    assert reflection_sites(tree, "java") == []
    assert not has_reflection_text("dao.selectById(1)", "java")
    assert has_reflection_text("m.invoke(this, x)", "java")
    print("ok: 普通代码不误报反射")


def test_hint_text():
    hint = reflection_hint([{"kind": "method-invoke", "line": 12, "name": "m.invoke",
                             "snippet": "m.invoke(this, row)"}])
    assert "反射" in hint and "12" in hint, hint
    print("ok: 反射提示文本")


def test_scan_marks_dynamic():
    with tempfile.TemporaryDirectory() as d:
        cands = _scan(Path(d))
        run = [c for c in cands if c.endpoint.path.endswith("/run/{id}")]
        assert run, [c.endpoint.path for c in cands]
        c = run[0]
        assert c.access.dynamic is True
        assert {s["kind"] for s in c.access.dynamic_sites} >= {"reflective-method", "method-invoke"}
        assert "反射" in (c.reachability_hints or {}).get("reflection", "")
        print("ok: scan 层写入 dynamic 标记与 reflection hint")


def test_decide_clamps_confidence_on_reflection():
    with tempfile.TemporaryDirectory() as d:
        cands = _scan(Path(d))
        run = [c for c in cands if c.endpoint.path.endswith("/run/{id}")][0]
        copy = [c for c in cands if c.endpoint.path.endswith("/copy/{id}")][0]
        plain = [c for c in cands if c.endpoint.path.endswith("/plain/{id}")][0]

    llm = {"is_vulnerable": True, "subtype": run.subtype, "confidence": 0.9,
           "resource_privacy": "PRIVATE", "reasoning": "疑似越权",
           "evidence_lines": ["line 14: dao.selectById(id)"],
           "uncertain_reason": "", "reachability": "reachable", "blocking_gate": None}

    f_run = decide(run, dict(llm))
    assert f_run.verdict == "LIKELY", f_run.verdict
    assert abs(f_run.confidence - 0.54) < 1e-6, f_run.confidence   # 0.9 * 0.6
    assert "dynamic_downgrade" in f_run.evidence
    assert "动态分派提示" in (f_run.llm_reasoning or "")

    # bean-copy 只记录，不降级
    f_copy = decide(copy, dict(llm))
    assert "dynamic_downgrade" not in f_copy.evidence, f_copy.evidence
    assert f_copy.evidence.get("dynamic_sites") == ["bean-copy"], f_copy.evidence

    # 无反射点：不降级
    f_plain = decide(plain, dict(llm))
    assert abs(f_plain.confidence - 0.9) < 1e-6, f_plain.confidence

    static = static_only_finding(run)
    assert abs(static.confidence - 0.3) < 1e-6, static.confidence  # 0.5 * 0.6
    print("ok: 反射点降置信度（bean-copy 豁免、静态兜底同样降级）")


if __name__ == "__main__":
    test_reflection_sites_java()
    test_no_sites_on_plain_code()
    test_hint_text()
    test_scan_marks_dynamic()
    test_decide_clamps_confidence_on_reflection()
    print("all M7 reflection tests passed")
