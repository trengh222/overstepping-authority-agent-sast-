"""Java/Spring 注册可达事实（确定性层）。

判定：控制器类既不被任何 Spring 组件扫描根覆盖，也未被 @Import 显式引用
→ Spring 容器不会注册该 Bean，路由不可达，可确定性关闭。

安全闸（任一成立即放弃关闭，保持人工复核）：
- 非全量目录冷扫描；
- 未发现 @SpringBootApplication / @ComponentScan，或扫描根为空；
- 扫描声明含 basePackageClasses / includeFilters / useDefaultFilters=false 等
  无法静态确定的写法；
- 同一扫描范围内出现多个 @SpringBootApplication（多应用无法归属）；
- 仓库存在 XML <bean>/<context:component-scan> 配置；
- 存在 spring.factories / AutoConfiguration.imports（自动配置可能注册 Bean）；
- 候选位于 src/test 测试源集（不进入运行产物，但避免对测试代码做产品级判定）。
"""
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
_APP_ANNOT_RE = re.compile(r"@SpringBootApplication\b")
_SCAN_ANNOT_RE = re.compile(r"@ComponentScan\b")
_IMPORT_RE = re.compile(r"@Import\b")
_STRING_RE = re.compile(r"\"([\w.\-]+)\"")
_CLASS_LITERAL_RE = re.compile(r"\b([A-Z]\w*)\.class\b")
_DYNAMIC_IMPORT_RE = re.compile(r"ImportSelector|ImportBeanDefinitionRegistrar|\$\{")
_XML_BEAN_RE = re.compile(r"<bean\b|<context:component-scan\b", re.I)
_UNSAFE_SCAN_RE = re.compile(
    r"basePackageClasses|includeFilters|useDefaultFilters\s*=\s*false", re.I)


def _args_at(text: str, pos: int) -> str:
    """取注解名之后的平衡括号实参（容忍嵌套括号/数组）。"""
    i = text.find("(", pos)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[i + 1:j]
    return text[i + 1:]


def project_blockers(files: Iterable[Path]) -> Dict[str, bool]:
    """扫描仓库内的配置阻塞项：XML Bean 配置 / 自动配置注册文件。"""
    xml_beans = auto_config = False
    for p in files:
        name = p.name.lower()
        if name.endswith(".xml"):
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if _XML_BEAN_RE.search(text):
                xml_beans = True
        elif name == "spring.factories" or name.endswith("autoconfiguration.imports"):
            auto_config = True
        if xml_beans and auto_config:
            break
    return {"xml_beans": xml_beans, "auto_config": auto_config}


def collect_spring_facts(texts: Iterable[Tuple[str, str]],
                         blockers: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    """收集组件扫描根与 @Import 引用；任何动态/不确定写法置 uncertain。"""
    apps: List[str] = []
    roots: Set[str] = set()
    imports: Set[str] = set()
    has_scan_config = False
    uncertain = False
    for lang, text in texts:
        if lang != "java" or not text:
            continue
        pkg_m = _PACKAGE_RE.search(text)
        pkg = pkg_m.group(1) if pkg_m else ""
        for m in _APP_ANNOT_RE.finditer(text):
            has_scan_config = True
            apps.append(pkg)
            args = _args_at(text, m.end())
            vals = _STRING_RE.findall(args)
            if vals:
                roots.update(v for v in vals if v)
            elif pkg:
                roots.add(pkg)  # 无显式 scanBasePackages → 默认扫描启动类所在包
            if _UNSAFE_SCAN_RE.search(args):
                uncertain = True
        for m in _SCAN_ANNOT_RE.finditer(text):
            has_scan_config = True
            args = _args_at(text, m.end())
            roots.update(v for v in _STRING_RE.findall(args) if v)
            if _UNSAFE_SCAN_RE.search(args):
                uncertain = True
        for m in _IMPORT_RE.finditer(text):
            args = _args_at(text, m.end())
            imports.update(_STRING_RE.findall(args))
            imports.update(_CLASS_LITERAL_RE.findall(args))
            if _DYNAMIC_IMPORT_RE.search(args):
                uncertain = True
    blockers = blockers or {}
    return {
        "has_scan_config": has_scan_config,
        "roots": roots,
        "imports": imports,
        "multi_app": len(apps) > 1,
        "uncertain": uncertain or bool(blockers.get("xml_beans"))
                     or bool(blockers.get("auto_config")),
    }


def java_unregistered_reason(container: Optional[str], facts: Optional[Dict[str, Any]],
                             whole_project: bool, file: str = "") -> Optional[str]:
    """控制器 FQN 未被扫描根覆盖且未被 @Import 引用 → 返回原因；无法确定 → None。"""
    if not whole_project or not container or not facts:
        return None
    norm = "/" + (file or "").replace("\\", "/")
    if "/src/test/" in norm:
        return None
    if (not facts.get("has_scan_config") or facts.get("multi_app")
            or facts.get("uncertain")):
        return None
    roots = {r for r in (facts.get("roots") or set()) if r}
    if not roots:
        return None
    fqn = (container or "").strip()
    cls = fqn.rsplit(".", 1)[-1]
    pkg = fqn.rsplit(".", 1)[0] if "." in fqn else ""
    imports = facts.get("imports") or set()
    if cls in imports or fqn in imports:
        return None
    if any(pkg == r or pkg.startswith(r + ".") for r in roots):
        return None
    return (f"Spring 组件扫描根（{', '.join(sorted(roots))}）不覆盖包 '{pkg}'，"
            f"且类 {cls} 未被 @Import 引用")
