"""构建清单事实（Maven / Gradle 多模块）：模块未被聚合构建纳入 → 不参与编译。

判定：扫描根存在聚合清单（Maven 根 pom.xml 的 <modules> 或 Gradle settings 的
include），候选所在模块目录有自己的构建清单，但既不在聚合清单中，也不位于任何
已列出的模块之下 → 该模块不参与构建，路由不可达（确定性关闭）。

安全闸（任一成立即放弃关闭）：
- 非全量目录冷扫描；
- 根目录同时存在 Maven 与 Gradle 清单；
- 模块列表使用占位符 / profile 条件 / 动态 include（变量、file()、includeBuild 等）；
- Maven <parent><relativePath> 指向扫描根之外；
- 模块目录没有自己的构建清单；
- 模块位于某个已列出模块之下（嵌套子构建无法归属）。
"""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set

_SETTINGS = ("settings.gradle", "settings.gradle.kts")
_BUILDS = ("build.gradle", "build.gradle.kts")
_INCLUDE_RE = re.compile(r"^\s*include\s*(?:\((.*)\)|(.*))?\s*$", re.M)
_QUOTED_RE = re.compile(r"['\"]([^'\"]+)['\"]")
_DYNAMIC_INCLUDE_RE = re.compile(
    r"\$\{|\$[A-Za-z_]|file\s*\(|fileTree|providers|System\.getenv|rootProject|"
    r"\bif\s*\(", re.I)


@dataclass
class BuildFacts:
    kind: str                        # maven | gradle
    root: Path
    modules: Set[str] = field(default_factory=set)   # 归一化相对路径（posix）
    uncertain: bool = False


def _tag(el) -> str:
    return el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""


def _maven_modules(pom: Path) -> Optional[Set[str]]:
    """解析根 pom 的 <modules>；无 <modules> → None（单模块，不做构建排除）。"""
    try:
        tree = ET.parse(pom)
    except (ET.ParseError, OSError):
        return None
    root = tree.getroot()
    modules: Set[str] = set()
    uncertain = False
    for child in root:
        if _tag(child) == "modules":
            for m in child:
                if _tag(m) != "module":
                    continue
                text = (m.text or "").strip().replace("\\", "/").strip("/")
                if not text or "${" in text:
                    uncertain = True
                else:
                    modules.add(text)
        elif _tag(child) == "profiles":
            for profile in child:
                if any(_tag(x) == "modules" for x in profile):
                    uncertain = True  # profile 条件模块 → 无法静态确定
        elif _tag(child) == "parent":
            for p in child:
                if _tag(p) == "relativePath" and ".." in (p.text or ""):
                    uncertain = True  # 父构建在扫描根之外
    if uncertain:
        return None
    return modules or None


def _gradle_includes(settings: Path) -> Optional[Set[str]]:
    """解析 settings 的 include；无 include → None（单工程）。"""
    try:
        text = settings.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if re.search(r"\bincludeBuild\b", text):
        return None  # 组合构建 → 放弃判定
    modules: Set[str] = set()
    for m in _INCLUDE_RE.finditer(text):
        args = (m.group(1) or m.group(2) or "").strip()
        if not args:
            continue
        if _DYNAMIC_INCLUDE_RE.search(args):
            return None  # include 实参含变量/环境/文件 API → 无法静态确定
        for q in _QUOTED_RE.findall(args):
            mod = q.strip(":").replace(":", "/").strip("/")
            if mod:
                modules.add(mod)
    return modules or None


def collect_build_facts(root: Path, _files: Optional[Iterable[Path]] = None) -> Optional[BuildFacts]:
    """识别扫描根的聚合构建清单；无法确定 → None。"""
    if not root.is_dir():
        return None
    has_maven = (root / "pom.xml").is_file()
    has_gradle = any((root / n).is_file() for n in _SETTINGS)
    if has_maven and has_gradle:
        return None
    if has_maven:
        modules = _maven_modules(root / "pom.xml")
        return BuildFacts("maven", root, modules) if modules else None
    if has_gradle:
        settings = next(root / n for n in _SETTINGS if (root / n).is_file())
        modules = _gradle_includes(settings)
        return BuildFacts("gradle", root, modules) if modules else None
    return None


def _module_dir(file: str, facts: BuildFacts) -> Optional[Path]:
    """候选文件最近的模块目录（含 pom.xml 或 build.gradle），且必须位于扫描根之内。"""
    try:
        p = Path(file).resolve()
        rel = p.relative_to(facts.root.resolve())
    except (OSError, ValueError):
        return None
    cur = p.parent
    root = facts.root.resolve()
    while True:
        if cur == root:
            return None
        if any((cur / n).is_file() for n in ("pom.xml",) + _BUILDS):
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def _rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def module_of_file(file: str, facts: Optional[BuildFacts]) -> str:
    """候选文件所属构建模块（相对路径，posix）；无法归属 → ""（根模块/单模块工程）。"""
    if facts is None or not facts.modules:
        return ""
    mod = _module_dir(file, facts)
    if mod is None:
        return ""
    try:
        return _rel(mod, facts.root)
    except ValueError:
        return ""


def module_build_excluded(file: str, facts: Optional[BuildFacts],
                          whole_project: bool = True) -> Optional[str]:
    """模块未被聚合构建纳入 → 返回原因；无法确定 → None。"""
    if not whole_project or facts is None or facts.uncertain or not facts.modules:
        return None
    mod = _module_dir(file, facts)
    if mod is None:
        return None
    rel = _rel(mod, facts.root)
    listed = facts.modules
    # 位于已列出模块之下（嵌套子构建）→ 无法归属，放弃判定
    if any(rel == m or rel.startswith(m + "/") for m in listed):
        return None
    manifest = "聚合 pom.xml" if facts.kind == "maven" else "settings.gradle"
    return (f"构建清单（{manifest}）未包含模块 '{rel}'，该模块不参与构建"
            f"（已声明模块: {', '.join(sorted(listed))}）")
