"""Java/Spring 注册可达事实测试（确定性扫描根 + @Import + 安全闸）。

运行：python -m pytest tests/test_spring_registration.py -q
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.llm.verdict import VerdictPipeline
from access_scan.rules.spring_registration import (collect_spring_facts,
                                                   java_unregistered_reason,
                                                   project_blockers)

_FIX = _REPO / "tests" / "fixtures"
_REG = _FIX / "registration"


def _facts(roots=("com.app",), imports=(), multi=False, uncertain=False, has=True):
    return {"has_scan_config": has, "roots": set(roots), "imports": set(imports),
            "multi_app": multi, "uncertain": uncertain}


# ---------------- 事实收集 ----------------

def test_collect_scan_roots_explicit():
    texts = [("java", 'package com.app;\n@SpringBootApplication(scanBasePackages = {"com.app", "com.app.web"})\n'
                      'public class A {}')]
    f = collect_spring_facts(texts)
    assert f["has_scan_config"] and f["roots"] == {"com.app", "com.app.web"}


def test_collect_scan_default_package():
    texts = [("java", "package com.app;\n@SpringBootApplication\npublic class A {}")]
    assert collect_spring_facts(texts)["roots"] == {"com.app"}


def test_collect_import_and_dynamic_uncertain():
    texts = [("java", 'package com.app;\n@SpringBootApplication\n@Import({OtherController.class})\n'
                      'public class A {}')]
    f = collect_spring_facts(texts)
    assert "OtherController" in f["imports"]
    assert not f["uncertain"]
    dyn = collect_spring_facts([("java", '@Import(DynamicSelector.class)\npublic class A {}')])
    assert dyn["uncertain"] is False, "普通类名不判为动态导入"
    dyn2 = collect_spring_facts([("java", '@Import(MyImportSelector.class)\npublic class A {}')])
    assert dyn2["uncertain"] is True, "ImportSelector 无法静态确定导入目标"
    scan = collect_spring_facts([("java", '@ComponentScan(basePackages="com.app", basePackageClasses=X.class)')])
    assert scan["uncertain"] is True, "basePackageClasses 无法静态确定包 → 不确定"


def test_collect_multiple_apps():
    texts = [("java", "@SpringBootApplication\npublic class A {}"),
             ("java", "@SpringBootApplication\npublic class B {}")]
    assert collect_spring_facts(texts)["multi_app"] is True


def test_project_blockers(tmp_path):
    xml = tmp_path / "beans.xml"
    xml.write_text('<beans><bean id="x" class="Y"/></beans>', encoding="utf-8")
    assert project_blockers([xml]) == {"xml_beans": True, "auto_config": False}
    fac = tmp_path / "spring.factories"
    fac.write_text("x=Y", encoding="utf-8")
    assert project_blockers([fac]) == {"xml_beans": False, "auto_config": True}


# ---------------- 判定规则 ----------------

def test_unregistered_reason():
    f = _facts()
    assert java_unregistered_reason("com.other.C", f, True, "x.java")
    assert not java_unregistered_reason("com.app.web.C", f, True, "x.java")
    assert not java_unregistered_reason("com.app.C", f, True, "x.java")


def test_unregistered_requires_safe_conditions():
    f = _facts()
    assert not java_unregistered_reason("com.other.C", f, False), "单文件/增量不判定"
    assert not java_unregistered_reason("com.other.C", _facts(multi=True), True), "多启动类不判定"
    assert not java_unregistered_reason("com.other.C", _facts(uncertain=True), True)
    assert not java_unregistered_reason("com.other.C", _facts(roots=()), True), "无扫描根不判定"
    assert not java_unregistered_reason("com.other.C", _facts(has=False), True)
    assert not java_unregistered_reason("com.other.C", f, True, "src/test/java/X.java"), \
        "测试源集不做产品级关闭"
    assert not java_unregistered_reason("com.other.C", _facts(imports=("C",)), True)


# ---------------- 端到端 ----------------

def _a1(path: Path):
    cands, _ = cli.scan(path)
    return [c for c in cands if c.subtype == "A1"]


def test_java_unscanned_fixture_has_deterministic_hint():
    a1 = _a1(_REG / "java_unscanned")
    assert a1, "fixture 应先产出 A1 候选"
    c = a1[0]
    assert c.endpoint.container == "com.example.other.UnscannedController"
    assert c.reachability_hints.get("registration_deterministic") == "1"
    assert "不覆盖包" in c.reachability_hints.get("registration", "")


def test_java_scanned_fixture_no_hint():
    assert _a1(_REG / "java_scanned")
    assert not any(c.reachability_hints.get("registration") for c in _a1(_REG / "java_scanned"))


def test_java_imported_fixture_no_hint():
    assert _a1(_REG / "java_imported")
    assert not any(c.reachability_hints.get("registration") for c in _a1(_REG / "java_imported"))


def test_java_xml_blocked_fixture_no_hint():
    assert _a1(_REG / "java_xml_blocked")
    assert not any(c.reachability_hints.get("registration") for c in _a1(_REG / "java_xml_blocked"))


def test_deterministic_registration_closes_without_llm():
    class Boom:
        available = True

        def judge(self, pkg):
            raise AssertionError("确定性注册关闭不应调用 LLM")

        def adversarial(self, pkg, verdict):
            raise AssertionError("不应调用对抗复核")

    cands, _ = cli.scan(_REG / "java_unscanned")
    fs = VerdictPipeline(judge=Boom()).run(cands)
    assert len(fs) == len(cands) >= 1
    assert all(f.reachability_class == "registration" and f.disposition == "auto_close"
               and f.verdict == "UNCERTAIN" for f in fs)
