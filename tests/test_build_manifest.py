"""Maven/Gradle 多模块构建事实测试。

运行：python -m pytest tests/test_build_manifest.py -q
覆盖：根 pom 的 modules、settings.gradle include、profile/占位符/动态 include
安全闸、模块归属（已列出 / 未列出 / 嵌套），以及端到端确定性关闭。
"""
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan import cli
from access_scan.llm.verdict import VerdictPipeline
from access_scan.rules.build_manifest import (BuildFacts, collect_build_facts,
                                              module_build_excluded)

_FIX = _REPO / "tests" / "fixtures"
_BUILD = _FIX / "build"


def _mk(root: Path, rel: str, text: str = "") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _pom(modules):
    mods = "".join(f"<module>{m}</module>" for m in modules)
    return (f"<project><modelVersion>4.0.0</modelVersion>"
            f"<groupId>g</groupId><artifactId>a</artifactId><version>1</version>"
            f"<packaging>pom</packaging><modules>{mods}</modules></project>")


# ---------------- Maven ----------------

def test_maven_modules_and_unlisted(tmp_path):
    _mk(tmp_path, "pom.xml", _pom(["app"]))
    _mk(tmp_path, "app/pom.xml", "<project/>")
    _mk(tmp_path, "orphan/pom.xml", "<project/>")
    facts = collect_build_facts(tmp_path)
    assert facts and facts.kind == "maven" and facts.modules == {"app"}
    app = tmp_path / "app/src/main/java/A.java"
    orphan = tmp_path / "orphan/src/main/java/B.java"
    assert not module_build_excluded(str(app), facts)
    assert module_build_excluded(str(orphan), facts)


def test_maven_profile_modules_uncertain(tmp_path):
    _mk(tmp_path, "pom.xml",
        "<project><modules><module>app</module></modules>"
        "<profiles><profile><modules><module>x</module></modules></profile></profiles></project>")
    assert collect_build_facts(tmp_path) is None


def test_maven_placeholder_uncertain(tmp_path):
    _mk(tmp_path, "pom.xml", "<project><modules><module>${mod}</module></modules></project>")
    assert collect_build_facts(tmp_path) is None


def test_maven_single_module_no_judgment(tmp_path):
    _mk(tmp_path, "pom.xml", "<project><groupId>g</groupId></project>")
    assert collect_build_facts(tmp_path) is None


# ---------------- Gradle ----------------

def test_gradle_include_and_unlisted(tmp_path):
    _mk(tmp_path, "settings.gradle", "rootProject.name='x'\ninclude ':app', ':lib'\n")
    _mk(tmp_path, "app/build.gradle", "plugins {}")
    _mk(tmp_path, "orphan/build.gradle", "plugins {}")
    facts = collect_build_facts(tmp_path)
    assert facts and facts.kind == "gradle" and facts.modules == {"app", "lib"}
    assert module_build_excluded(str(tmp_path / "orphan/src/B.java"), facts)
    assert not module_build_excluded(str(tmp_path / "app/src/A.java"), facts)


def test_gradle_dynamic_includes_rejected(tmp_path):
    _mk(tmp_path, "settings.gradle", "include ':app'\ninclude System.getenv('X')\n")
    assert collect_build_facts(tmp_path) is None
    _mk(tmp_path, "settings.gradle", "includeBuild('../other')\n")
    assert collect_build_facts(tmp_path) is None


def test_gradle_no_include_no_judgment(tmp_path):
    _mk(tmp_path, "settings.gradle", "rootProject.name='solo'\n")
    assert collect_build_facts(tmp_path) is None


def test_mixed_build_systems_no_judgment(tmp_path):
    _mk(tmp_path, "pom.xml", _pom(["app"]))
    _mk(tmp_path, "settings.gradle", "include ':app'\n")
    assert collect_build_facts(tmp_path) is None


def test_nested_module_under_listed_not_closed(tmp_path):
    _mk(tmp_path, "pom.xml", _pom(["app"]))
    _mk(tmp_path, "app/pom.xml", "<project/>")
    _mk(tmp_path, "app/sub/pom.xml", "<project/>")
    facts = collect_build_facts(tmp_path)
    assert not module_build_excluded(str(tmp_path / "app/sub/src/A.java"), facts), \
        "已列出模块的嵌套子构建无法归属 → 不关闭"


def test_module_requires_own_manifest(tmp_path):
    _mk(tmp_path, "pom.xml", _pom(["app"]))
    _mk(tmp_path, "plain/src/A.java")
    facts = collect_build_facts(tmp_path)
    assert not module_build_excluded(str(tmp_path / "plain/src/A.java"), facts), \
        "无自身构建清单的目录不判定"


def test_non_whole_project_skips(tmp_path):
    _mk(tmp_path, "pom.xml", _pom(["app"]))
    _mk(tmp_path, "orphan/pom.xml", "<project/>")
    facts = collect_build_facts(tmp_path)
    assert not module_build_excluded(str(tmp_path / "orphan/src/A.java"), facts, False)


# ---------------- 端到端 ----------------

def _cands(path: Path):
    cands, _ = cli.scan(path)
    return [c for c in cands if c.subtype == "A1"]


def _by_name(cands, suffix):
    return [c for c in cands if Path(c.endpoint.file).as_posix().endswith(suffix)][0]


def test_maven_fixture_hint():
    cands = _cands(_BUILD / "maven_unlisted")
    assert len(cands) == 2
    assert not _by_name(cands, "app/src/main/java/com/example/app/AppController.java"
                        ).reachability_hints.get("build")
    orphan = _by_name(cands, "orphan/src/main/java/com/example/orphan/OrphanController.java")
    assert "未包含模块" in orphan.reachability_hints.get("build", "")


def test_gradle_fixture_hint():
    cands = _cands(_BUILD / "gradle_unlisted")
    orphan = _by_name(cands, "orphan/src/main/java/com/example/orphan/OrphanController.java")
    assert "未包含模块" in orphan.reachability_hints.get("build", "")


def test_build_manifest_closes_without_llm_for_orphan():
    class Judge:
        available = True
        calls = 0

        def judge(self, pkg):
            type(self).calls += 1
            return {"is_vulnerable": True, "subtype": "A1", "confidence": 0.9,
                    "resource_privacy": "PRIVATE", "reasoning": "仅按 id 查询",
                    "evidence_lines": ["第 22 行：orderService.findById(id) 无归属过滤"],
                    "uncertain_reason": ""}

        def adversarial(self, pkg, verdict):
            return {"refuted": False, "reasoning": "维持漏洞成立"}

    cands, _ = cli.scan(_BUILD / "maven_unlisted")
    fs = VerdictPipeline(judge=Judge()).run(cands)
    orphan = [f for f in fs if f.candidate.endpoint.file.endswith("OrphanController.java")][0]
    app = [f for f in fs if f.candidate.endpoint.file.endswith("AppController.java")][0]
    assert orphan.verdict == "UNCERTAIN" and orphan.reachability_class == "build"
    assert orphan.disposition == "auto_close"
    assert app.verdict in ("LIKELY", "CONFIRMED"), "已声明模块继续走 LLM 判定"
