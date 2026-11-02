"""L1+L2 语言前端基类 + 注册表（方案 §6.1）。

各语言前端只做「tree-sitter AST → 统一 IR」的薄适配；
数据流、规则、LLM、报告层全部复用 IR。
"""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from ..dataflow.asts import WRITE_OP_PREFIXES, call_name, iter_calls
from ..ir import Endpoint, Resource


def _text(node: Any) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def has_write_op(node: Any, language: str) -> bool:
    """handler 内是否执行写/删/导出等敏感操作（跨语言通用，M4）。"""
    return any(
        (call_name(c) or "").lower().startswith(WRITE_OP_PREFIXES)
        for c in iter_calls(node, language)
    )


class Extractor(ABC):
    language: str = ""

    @abstractmethod
    def extract_endpoints(self, ast, file: str) -> List[Endpoint]:
        """从 AST 提取端点（路由 + 参数 + 鉴权 + 特权操作）。"""

    @abstractmethod
    def extract_resources(self, ast, file: str) -> List[Resource]:
        """从 AST 提取资源实体（ORM 模型/表名 + 归属字段）。"""


# 前端注册表：language -> Extractor 子类
FRONTENDS: Dict[str, Type[Extractor]] = {}


def register(language: str) -> Callable[[Type[Extractor]], Type[Extractor]]:
    def deco(cls: Type[Extractor]) -> Type[Extractor]:
        FRONTENDS[language] = cls
        return cls
    return deco


def get_frontend(language: str) -> Optional[Type[Extractor]]:
    return FRONTENDS.get(language)


@dataclass
class Guard:
    """垂直方向上的一处鉴权设备（语言中立：拦截器/过滤器/中间件/注册器）。"""
    kind: str                      # INTERCEPTOR | FILTER | MIDDLEWARE | CONFIGURER
    name: str                      # 类名/函数名/注册引用
    patterns: List[str]            # 覆盖的路径模式；空列表 = 全局 "**"
    has_auth_check: bool
    depends_on_client_input: bool  # 鉴权决策读取了客户端可控输入（参数/头/Cookie）
    line: int
    file: str = ""
    registered: bool = True        # INTERCEPTOR 需 addInterceptor 注册才生效；link_guards 统一校正
    module: str = ""               # 所属构建模块（Maven/Gradle 相对路径）；跨模块不共享覆盖


def link_guards(guards: List[Guard],
                chains: List[Tuple]) -> List[Guard]:
    """跨文件将注册链路绑定到守卫：
    - 引用命中可分析守卫名 → 追加其路径模式；
    - 引用外部/存量组件（无法分析逻辑）→ 合成 CONFIGURER 守卫，按"已覆盖"保守处理；
      合成守卫继承注册链所在模块（D1：跨模块不共享覆盖）；
    - 未被任何 addInterceptor 注册的 INTERCEPTOR 视为不生效（Spring 需显式注册），
      避免把「@Component 但未注册」的拦截器误当全局守卫而污染其他端点。

    chains 元素为 (ref, patterns) 或 (ref, patterns, module)。
    """
    out: List[Guard] = list(guards)
    registered_ids: set = set()
    for item in chains:
        ref, pats = item[0], item[1]
        module = item[2] if len(item) > 2 else ""
        matched = [g for g in out if re.search(rf"\b{re.escape(g.name)}\b", ref)]
        if matched:
            for g in matched:
                registered_ids.add(id(g))
                for p in pats:
                    if p not in g.patterns:
                        g.patterns.append(p)
        else:
            out.append(Guard(
                kind="CONFIGURER", name=ref.strip(), patterns=list(pats),
                has_auth_check=True, depends_on_client_input=False, line=-1,
                module=module,
            ))
    for g in out:
        if g.kind == "INTERCEPTOR" and id(g) not in registered_ids:
            g.registered = False
    return out


@dataclass
class EndpointCtx:
    """规则层所需的 handler 上下文（语言中立基类）。

    node：handler 节点（函数/方法/lambda…），由对应语言的污点追踪器消费。
    """
    file: str
    lines: List[str]
    language: str
    node: Any = None
    extras: Dict[str, Any] = field(default_factory=dict)