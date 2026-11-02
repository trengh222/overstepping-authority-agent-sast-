"""L3 符号执行「可触发」反例与 PoC（方案 §7.3 / M3.3）。

对 A1 候选的 handler 方法做有限路径符号执行（tree-sitter AST 解释器）：
- 资源 ID 参数设为符号变量 x，取值域为合法主键 [1, 2^31-1]；
- 语句遍历收集路径约束（整数线性/多项式比较、&&/||/! 组合），分支两路探索；
- 命中候选的 sink 调用即以当前约束求反例：优先用 Z3 SMT 求解（支持乘法等
  非线性约束），Z3 不可用时回退到内置区间推理（仅线性）；
- 不支持的结构（方法调用条件、循环、位运算等）标记该路径 unsound，
  不产出反例 → 保持 LIKELY（§7.3 降级语义，不强行 CONFIRMED）。
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..extractor import java  # noqa: F401  注册 Java 前端（供 CtxResolver 按需解析）
from ..ir import Endpoint, ParamSource
from .defuse import _go_is_source, _js_is_source

try:
    import z3
    _HAS_Z3 = True
    _SYM_X = z3.Int("x")          # 符号变量 x（资源 ID）
except ImportError:                # 未安装 z3 → 回退到内置区间推理
    z3 = None
    _HAS_Z3 = False
    _SYM_X = None

PK_LO, PK_HI = 1, 2 ** 31 - 1      # 合法主键域（x 为合法主键域，§7.3）
_MAX_PATHS = 64                     # 路径爆炸保护
_CMP_OPS = ("==", "!=", "<", "<=", ">", ">=")
_FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}
_NEGATE = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}


@dataclass
class _Cmp:
    op: str      # 比较操作符（== != < <= > >=）；"const"=常量布尔；"z3"=Z3 布尔表达式
    t: Any       # int（线性）/ bool（const）/ z3.BoolRef（z3）


@dataclass
class _State:
    cmps: List[_Cmp] = field(default_factory=list)
    tainted: Set[str] = field(default_factory=set)
    vars: Dict[str, Any] = field(default_factory=dict)   # name -> 符号值（Z3 表达式或元组）
    unsound: bool = False
    dead: bool = False


def _text(node: Any) -> str:
    if node is None:
        return ""
    if isinstance(node, str):
        return node
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _op_text(node: Any) -> str:
    op = node.child_by_field_name("operator")
    return _text(op).strip() if op is not None else ""


def _iter_calls(node: Any):
    if node.type == "method_invocation":
        yield node
    for ch in node.named_children:
        yield from _iter_calls(ch)


def _clone(s: _State) -> _State:
    return _State(cmps=list(s.cmps), tainted=set(s.tainted),
                  vars=dict(s.vars), unsound=s.unsound, dead=s.dead)


# ---------- 符号值：Z3 表达式（可用时）或 ("x", k)/(None, c) 元组 ----------

def _sv_symbol():
    """符号变量 x。"""
    return _SYM_X if _HAS_Z3 else ("x", 0)


def _sv_const(c: int):
    """整数常量。"""
    return z3.IntVal(c) if _HAS_Z3 else (None, c)


def _sv_is_symbolic(v) -> bool:
    """符号值是否含符号 x（非纯常量）。"""
    if v is None:
        return False
    if _HAS_Z3:
        return not z3.is_int_value(v)
    return isinstance(v, tuple) and v[0] == "x"


def _sv_const_val(v):
    """符号值若是纯常量，返回其整数；否则 None。"""
    if v is None:
        return None
    if _HAS_Z3:
        return v.as_long() if z3.is_int_value(v) else None
    if isinstance(v, tuple) and v[0] is None:
        return v[1]
    if isinstance(v, int):
        return v
    return None


def _sv_add_sub(op: str, a, b):
    """符号值二元 + -。"""
    if _HAS_Z3:
        return (a + b) if op == "+" else (a - b)
    if not (isinstance(a, tuple) and isinstance(b, tuple)):
        return None
    if op == "+":
        if a[0] is None and b[0] is None:
            return (None, a[1] + b[1])
        if a[0] == "x" and b[0] is None:
            return ("x", a[1] + b[1])
        if b[0] == "x" and a[0] is None:
            return ("x", b[1] + a[1])
        return None
    if a[0] is None and b[0] is None:
        return (None, a[1] - b[1])
    if a[0] == "x" and b[0] is None:
        return ("x", a[1] - b[1])
    return None


def _sv_mul(a, b):
    """符号值乘法（仅 Z3 支持；fallback 返回 None → unsound）。"""
    return (a * b) if _HAS_Z3 else None


def _sv_negate(v):
    if _HAS_Z3:
        return -v
    if isinstance(v, tuple):
        return (v[0], -v[1])
    return None


def _z3_rel(op: str, l, r):
    if op == "==":
        return l == r
    if op == "!=":
        return l != r
    if op == "<":
        return l < r
    if op == "<=":
        return l <= r
    if op == ">":
        return l > r
    return l >= r


# ---------- 符号表达式 → 符号值（线性/多项式） ----------

def _linear(node: Any, s: _State, param: str):
    if node is None:
        return None
    t = node.type
    if t == "decimal_integer_literal":
        try:
            return _sv_const(int(_text(node).replace("_", "")))
        except ValueError:
            return None
    if t == "hex_integer_literal":
        try:
            return _sv_const(int(_text(node).replace("0x", "", 1), 16))
        except ValueError:
            return None
    if t == "identifier":
        n = _text(node)
        if n == param or n in s.tainted:
            return _sv_symbol()
        return s.vars.get(n)
    if t == "unary_expression":
        op = _op_text(node)
        if op == "-":
            sub = _linear(node.child_by_field_name("operand"), s, param)
            return _sv_negate(sub) if sub is not None else None
        return None
    if t == "binary_expression":
        op = _op_text(node)
        a = _linear(node.child_by_field_name("left"), s, param)
        b = _linear(node.child_by_field_name("right"), s, param)
        if a is None or b is None:
            return None
        if op in ("+", "-"):
            return _sv_add_sub(op, a, b)
        if op == "*":
            return _sv_mul(a, b)
        return None
    return None


def _is_null(node: Any) -> bool:
    return node is not None and node.type == "null_literal"


# ---------- 比较 → x op t ----------

def _cmp(node: Any, s: _State, param: str) -> Optional[Tuple[str, Any]]:
    op = _op_text(node)
    if op not in _CMP_OPS:
        return None
    lhs_node = node.child_by_field_name("left")
    rhs_node = node.child_by_field_name("right")
    # x == null 恒假 / x != null 恒真（符号变量不可能为 null）
    if _is_null(lhs_node) or _is_null(rhs_node):
        return ("const", op == "!=")
    lhs = _linear(lhs_node, s, param)
    rhs = _linear(rhs_node, s, param)
    if lhs is None or rhs is None:
        return None
    if _HAS_Z3:
        return ("z3", _z3_rel(op, lhs, rhs))
    # fallback：元组比较
    if lhs[0] == "x" and rhs[0] is None:
        return (op, rhs[1] - lhs[1])
    if rhs[0] == "x" and lhs[0] is None:
        return (_FLIP[op], lhs[1] - rhs[1])
    if lhs[0] is None and rhs[0] is None:
        a, b = lhs[1], rhs[1]
        return ("const", {"==": a == b, "!=": a != b, "<": a < b,
                          "<=": a <= b, ">": a > b, ">=": a >= b}[op])
    return None


# ---------- 条件 → DNF：[(约束列表, 是否 unsound)] ----------

def _dnf(node: Any, s: _State, param: str, negate: bool = False) -> List[Tuple[List[_Cmp], bool]]:
    if node is None:
        return [([], True)]
    t = node.type
    if t == "parenthesized_expression":
        return _dnf(node.named_children[0] if node.named_children else None,
                    s, param, negate)
    if t == "boolean_literal":
        eff = ("true" in _text(node).lower()) != negate
        return [([], False)] if eff else []
    if t == "unary_expression":
        if _op_text(node) == "!":
            return _dnf(node.child_by_field_name("operand"), s, param, not negate)
        return [([], True)]
    if t != "binary_expression":
        return [([], True)]  # 方法调用等条件 → 不支持 → unsound
    op = _op_text(node)
    lhs = node.child_by_field_name("left")
    rhs = node.child_by_field_name("right")
    if op == "&&":
        a = _dnf(lhs, s, param, negate)
        b = _dnf(rhs, s, param, negate)
        return _and_dnf(a, b) if not negate else _or_dnf(a, b)
    if op == "||":
        a = _dnf(lhs, s, param, negate)
        b = _dnf(rhs, s, param, negate)
        return _or_dnf(a, b) if not negate else _and_dnf(a, b)
    if op in _CMP_OPS:
        c = _cmp(node, s, param)
        if c is None:
            return [([], True)]
        if c[0] == "const":
            eff = bool(c[1]) != negate
            return [([], False)] if eff else []
        if c[0] == "z3":
            b = c[1]
            if negate:
                b = z3.Not(b)
            return [([_Cmp("z3", b)], False)]
        opv, t = c
        if negate:
            opv = _NEGATE[opv]
        return [([_Cmp(opv, t)], False)]
    return [([], True)]


def _and_dnf(a, b):
    return [(ca + cb, ua or ub) for ca, ua in a for cb, ub in b]


def _or_dnf(a, b):
    return list(a) + list(b)


# ---------- 区间求解 ----------

def _solve(cmps: List[_Cmp]) -> Optional[int]:
    """求解约束合取：Z3 可用时用 SMT（含非线性），否则区间推理（仅线性）。"""
    if _HAS_Z3:
        return _solve_z3(cmps)
    return _solve_interval(cmps)


def _solve_z3(cmps: List[_Cmp]) -> Optional[int]:
    opt = z3.Optimize()
    for c in cmps:
        if c.op == "z3":
            opt.add(c.t)
        elif c.op in _CMP_OPS:
            opt.add(_z3_rel(c.op, _SYM_X, z3.IntVal(c.t)))
        # "const" 已在 _dnf 中消解，不会出现
    opt.add(_SYM_X >= PK_LO, _SYM_X <= PK_HI)
    # 偏好主键域中点，使反例取值风格与区间推理一致（可复现、非贴边界）
    mid = (PK_LO + PK_HI) // 2
    opt.minimize(z3.If(_SYM_X >= mid, _SYM_X - mid, mid - _SYM_X))
    if opt.check() == z3.sat:
        m = opt.model()
        v = m.eval(_SYM_X, model_completion=True)
        return v.as_long() if v is not None else None
    return None


def _solve_interval(cmps: List[_Cmp]) -> Optional[int]:
    lo, hi = PK_LO, PK_HI
    eq, nes = None, []
    for c in cmps:
        if c.op == "==":
            if eq is not None and eq != c.t:
                return None
            eq = c.t
        elif c.op == "!=":
            nes.append(c.t)
        elif c.op == "<":
            hi = min(hi, c.t - 1)
        elif c.op == "<=":
            hi = min(hi, c.t)
        elif c.op == ">":
            lo = max(lo, c.t + 1)
        elif c.op == ">=":
            lo = max(lo, c.t)
    if eq is not None:
        return eq if (eq not in nes and lo <= eq <= hi) else None
    # 选中点更像“他人资源 ID”
    return (lo + hi) // 2 if lo <= hi else None


# ---------- 语句执行 ----------

def _any_tainted_arg(args: Any, s: _State, param: str) -> bool:
    if args is None:
        return False
    return any(_sv_is_symbolic(_linear(a, s, param)) for a in args.named_children)


def _check_sink(node: Any, s: _State, param: str, sink_line: int, victories: List[_State]):
    if sink_line <= 0:
        return
    for call in _iter_calls(node):
        if call.start_point[0] + 1 != sink_line:
            continue
        if _any_tainted_arg(call.child_by_field_name("arguments"), s, param):
            victories.append(_clone(s))
            return


def _bind(name: str, value_node: Any, s: _State, param: str):
    lin = _linear(value_node, s, param)
    if lin is not None:
        s.vars[name] = lin
        return
    if value_node is not None and value_node.type == "method_invocation":
        # 未解释调用：参数带污点 → 结果视为符号（召回优先的近似）
        if _any_tainted_arg(value_node.child_by_field_name("arguments"), s, param):
            s.tainted.add(name)
            s.vars[name] = _sv_symbol()


def _bind_decl(node: Any, s: _State, param: str):
    for ch in node.named_children:
        if ch.type != "variable_declarator":
            continue
        name_node = ch.child_by_field_name("name")
        if name_node is None:
            continue
        _bind(_text(name_node), ch.child_by_field_name("value"), s, param)


def _bind_expr_stmt(node: Any, s: _State, param: str):
    first = node.named_children[0] if node.named_children else None
    if first is None:
        return
    if first.type == "assignment_expression":
        lhs = first.child_by_field_name("left")
        rhs = first.child_by_field_name("right")
        if lhs is not None and lhs.type == "identifier" and rhs is not None:
            _bind(_text(lhs), rhs, s, param)
    elif first.type == "method_invocation":
        # 独立调用（如 orderService.deleteUser(id)）：污点沿参数进入，无需绑定
        return


def _exec_if(node: Any, s: _State, param: str, sink_line: int,
             victories: List[_State]) -> List[_State]:
    cond = node.child_by_field_name("condition")
    then_b = node.child_by_field_name("consequence")
    else_b = node.child_by_field_name("alternative")
    out: List[_State] = []
    for cmps, unsound in _dnf(cond, s, param):
        ns = _clone(s)
        ns.unsound = ns.unsound or unsound
        ns.cmps.extend(cmps)
        if then_b is not None:
            out.extend(_exec_one(then_b, ns, param, sink_line, victories))
        else:
            out.append(ns)
    for cmps, unsound in _dnf(cond, s, param, negate=True):
        ns = _clone(s)
        ns.unsound = ns.unsound or unsound
        ns.cmps.extend(cmps)
        if else_b is not None:
            out.extend(_exec_one(else_b, ns, param, sink_line, victories))
        else:
            out.append(ns)
    return out


def _exec_one(node: Any, s: _State, param: str, sink_line: int,
              victories: List[_State]) -> List[_State]:
    t = node.type
    # sink 检测只对叶子语句做：复合节点（block/if/循环）的子语句会携带各自
    # 的路径约束被逐个访问，提前扫描子树会以错误（无约束）状态记录 sink。
    if t in ("local_variable_declaration", "expression_statement", "return_statement"):
        _check_sink(node, s, param, sink_line, victories)
    if t == "block":
        return _exec_nodes(node, s, param, sink_line, victories)
    if t == "local_variable_declaration":
        _bind_decl(node, s, param)
        return [s]
    if t == "expression_statement":
        _bind_expr_stmt(node, s, param)
        return [s]
    if t == "return_statement":
        s.dead = True
        return []
    if t == "if_statement":
        return _exec_if(node, s, param, sink_line, victories)
    # while/for/switch/try/lambda 等：标记 unsound，仍扫一遍体内保持召回
    s.unsound = True
    return _exec_nodes(node, s, param, sink_line, victories)


def _exec_nodes(node: Any, s: _State, param: str, sink_line: int,
                victories: List[_State]) -> List[_State]:
    states = [s]
    for stmt in node.named_children:
        if not states:
            break
        nxt: List[_State] = []
        for st in states:
            if st.dead:
                continue
            nxt.extend(_exec_one(stmt, st, param, sink_line, victories))
        states = nxt[:_MAX_PATHS]
    return states


# ---------- 对外 API ----------

def build_poc(endpoint: Endpoint, value: int, param_name: str) -> str:
    # 路径占位符（{id} / {id:\d+}）替换为反例值
    path = re.sub(r"\{" + re.escape(param_name) + r"(?::[^}]*)?\}", str(value), endpoint.path)
    # D7：query 参数补齐（?userId=...），否则 PoC 只有路径参数
    for p in endpoint.params:
        if p.name == param_name and p.source == ParamSource.QUERY:
            path += ("&" if "?" in path else "?") + f"{param_name}={value}"
            break
    return (f"{endpoint.method} {path}\n"
            f'curl -H "Cookie: SESSION=<attacker>" "http://<host>{path}"')


def _mk_result(status: str, counterexample: Optional[int] = None,
               poc: Optional[str] = None) -> Dict[str, Any]:
    """符号执行三态结果：sat（可触发）/ unsat（确定性不可触发）/ unsound（未知）。"""
    return {"status": status, "counterexample": counterexample, "poc": poc}


def _conclude(victories: List[_State], endpoint: Endpoint,
              param_name: str) -> Dict[str, Any]:
    """由「到达 sink 的路径状态」推出可触发性三态（数据可达）。

    仅对 unsound=False 的健全路径判定：
    - 任一健全路径约束合取可满足（sat）→ 产出反例/PoC；
    - 有健全路径但约束合取不可满足（unsat）→ 确定性证明不可触发；
    - 无健全路径（循环/未解释条件等 unsound，或根本没命中 sink）→ 未知，不降级。
    """
    sound = [v for v in victories if not v.unsound]
    for v in sound:
        val = _solve(v.cmps)
        if val is not None:
            return _mk_result("sat", val, build_poc(endpoint, val, param_name))
    if sound:
        return _mk_result("unsat")
    return _mk_result("unsound")


def symbolic_reachability(method_node: Any, param_name: str, sink_line: int,
                          endpoint: Endpoint, lang: str = "java") -> Dict[str, Any]:
    """符号执行可触发性三态判定（数据可达维度）。

    sat（存在触发路径，含反例/PoC）/ unsat（确定性不可触发）/ unsound（结构不支持，未知）。
    lang 指定 handler 语言（java/javascript/go）。
    """
    if lang == "java":
        return _symbolic_java(method_node, param_name, sink_line, endpoint)
    return _symbolic_generic(method_node, param_name, sink_line, endpoint, lang)


def symbolic_counterexample(method_node: Any, param_name: str, sink_line: int,
                            endpoint: Endpoint, lang: str = "java") -> Optional[Dict[str, Any]]:
    """向后兼容包装：仅 sat 时返回 {counterexample, poc}，unsat/unsound 均返回 None。

    需要区分 unsat（确定性不可达）与 unsound（未知）时请用 symbolic_reachability。
    """
    r = symbolic_reachability(method_node, param_name, sink_line, endpoint, lang)
    if r.get("status") == "sat":
        return {"counterexample": r["counterexample"], "poc": r["poc"]}
    return None


def _symbolic_java(method_node: Any, param_name: str, sink_line: int,
                   endpoint: Endpoint) -> Dict[str, Any]:
    """Java handler 的有限路径符号执行（原 M3.3 实现）。"""
    body = method_node.child_by_field_name("body")
    if body is None:
        return _mk_result("unsound")
    victories: List[_State] = []
    states: List[_State] = [_State(tainted={param_name})]
    for stmt in body.named_children:
        if not states:
            break
        nxt: List[_State] = []
        for s in states:
            nxt.extend(_exec_one(stmt, s, param_name, sink_line, victories))
        states = nxt[:_MAX_PATHS]
    return _conclude(victories, endpoint, param_name)


# ---------- 通用符号执行（JS / Go，M4 完善） ----------

# 各非 Java 语言的 AST 节点类型集合（差异集中在字面量/标识符/表达式/块命名）。
_OTHER_SPECS = {
    "javascript": {
        "call": ("call_expression",),
        "ident": ("identifier",),
        "int": ("number",),
        "paren": ("parenthesized_expression",),
        "null": ("null",),
        "block": ("statement_block",),
        "unary": ("unary_expression",),
        "binary": ("binary_expression",),
        "if_body": "consequence", "else": "alternative",
        "ret": "return_statement", "if": "if_statement",
    },
    "go": {
        "call": ("call_expression",),
        "ident": ("identifier",),
        "int": ("int_literal",),
        "paren": ("parenthesized_expression",),
        "null": ("nil",),
        "block": ("block", "statement_list"),
        "unary": ("unary_expression",),
        "binary": ("binary_expression",),
        "if_body": "consequence", "else": "alternative",
        "ret": "return_statement", "if": "if_statement",
    },
}


def _g_norm_op(op: str) -> str:
    op = op.strip().lower()
    return {"and": "&&", "or": "||", "not": "!"}.get(op, op)


def _g_binop(node: Any) -> Tuple[str, Any, Any]:
    """提取二元/比较/逻辑操作：(归一化 op, lhs, rhs)。"""
    op = _text(node.child_by_field_name("operator") or "").strip()
    lhs = node.child_by_field_name("left")
    rhs = node.child_by_field_name("right")
    return _g_norm_op(op), lhs, rhs


def _g_unary(node: Any) -> Tuple[str, Any]:
    op = _text(node.child_by_field_name("operator") or "").strip()
    operand = node.child_by_field_name("operand")
    if operand is None:
        operand = node.named_children[0] if node.named_children else None
    if not op:
        m = re.match(r"^(not|!|-)", _text(node).strip())
        op = m.group(1) if m else ""
    return _g_norm_op(op), operand


def _g_var_name(node: Any) -> str:
    return _text(node)


def _g_linear(node: Any, s: _State, param: str, spec: dict, lang: str):
    if node is None:
        return None
    t = node.type
    if t in spec["int"]:
        txt = _text(node).replace("_", "").replace("'", "")
        try:
            return _sv_const(int(txt, 0))
        except ValueError:
            return None
    if t in spec["ident"]:
        n = _g_var_name(node)
        if n == param or n in s.tainted:
            return _sv_symbol()
        return s.vars.get(n)
    if lang == "javascript" and _js_is_source(node, param):
        return _sv_symbol()
    if lang == "go" and _go_is_source(node, param):
        return _sv_symbol()
    if t in spec["unary"]:
        op, operand = _g_unary(node)
        if op == "-":
            sub = _g_linear(operand, s, param, spec, lang)
            return _sv_negate(sub) if sub is not None else None
        return None
    if t in spec["binary"]:
        op, lhs, rhs = _g_binop(node)
        a = _g_linear(lhs, s, param, spec, lang)
        b = _g_linear(rhs, s, param, spec, lang)
        if a is None or b is None:
            return None
        if op in ("+", "-"):
            return _sv_add_sub(op, a, b)
        if op == "*":
            return _sv_mul(a, b)
        return None
    return None


def _g_is_null(node: Any, spec: dict) -> bool:
    return node is not None and node.type in spec["null"]


def _g_cmp(node: Any, s: _State, param: str, spec: dict, lang: str):
    op, lhs, rhs = _g_binop(node)
    if op not in _CMP_OPS:
        return None
    if _g_is_null(lhs, spec) or _g_is_null(rhs, spec):
        return ("const", op == "!=")
    a = _g_linear(lhs, s, param, spec, lang)
    b = _g_linear(rhs, s, param, spec, lang)
    if a is None or b is None:
        return None
    if _HAS_Z3:
        return ("z3", _z3_rel(op, a, b))
    if a[0] == "x" and b[0] is None:
        return (op, b[1] - a[1])
    if b[0] == "x" and a[0] is None:
        return (_FLIP[op], a[1] - b[1])
    if a[0] is None and b[0] is None:
        return ("const", {"==": a[1] == b[1], "!=": a[1] != b[1], "<": a[1] < b[1],
                          "<=": a[1] <= b[1], ">": a[1] > b[1], ">=": a[1] >= b[1]}[op])
    return None


def _g_dnf(node: Any, s: _State, param: str, negate: bool, spec: dict,
           lang: str) -> List[Tuple[List[_Cmp], bool]]:
    if node is None:
        return [([], True)]
    t = node.type
    if t in spec["paren"]:
        return _g_dnf(node.named_children[0] if node.named_children else None,
                      s, param, negate, spec, lang)
    if _text(node).strip().lower() in ("true", "false"):
        eff = (_text(node).strip().lower() == "true") != negate
        return [([], False)] if eff else []
    if t in spec["unary"]:
        op, operand = _g_unary(node)
        if op == "!":
            return _g_dnf(operand, s, param, not negate, spec, lang)
        return [([], True)]
    if t in spec["binary"]:
        op, lhs, rhs = _g_binop(node)
        if op == "&&":
            a = _g_dnf(lhs, s, param, negate, spec, lang)
            b = _g_dnf(rhs, s, param, negate, spec, lang)
            return _and_dnf(a, b) if not negate else _or_dnf(a, b)
        if op == "||":
            a = _g_dnf(lhs, s, param, negate, spec, lang)
            b = _g_dnf(rhs, s, param, negate, spec, lang)
            return _or_dnf(a, b) if not negate else _and_dnf(a, b)
        if op in _CMP_OPS:
            c = _g_cmp(node, s, param, spec, lang)
            if c is None:
                return [([], True)]
            if c[0] == "const":
                eff = bool(c[1]) != negate
                return [([], False)] if eff else []
            if c[0] == "z3":
                b = c[1]
                if negate:
                    b = z3.Not(b)
                return [([_Cmp("z3", b)], False)]
            opv, tt = c
            if negate:
                opv = _NEGATE[opv]
            return [([_Cmp(opv, tt)], False)]
    return [([], True)]


def _g_iter_calls(node: Any, spec: dict):
    if node.type in spec["call"]:
        yield node
    for ch in node.named_children:
        yield from _g_iter_calls(ch, spec)


def _g_contains_symbol(node: Any, s: _State, param: str, spec: dict, lang: str) -> bool:
    """表达式是否携带符号 x（递归处理对象字面量/成员访问/调用等复合结构）。"""
    if node is None:
        return False
    lin = _g_linear(node, s, param, spec, lang)
    if lin is not None:
        return _sv_is_symbolic(lin)
    return any(_g_contains_symbol(ch, s, param, spec, lang) for ch in node.named_children)


def _g_any_tainted_arg(args: Any, s: _State, param: str, spec: dict, lang: str) -> bool:
    if args is None:
        return False
    return any(_g_contains_symbol(a, s, param, spec, lang) for a in args.named_children)


def _g_check_sink(node: Any, s: _State, param: str, sink_line: int,
                  victories: List[_State], spec: dict, lang: str):
    if sink_line <= 0:
        return
    for call in _g_iter_calls(node, spec):
        if call.start_point[0] + 1 != sink_line:
            continue
        if _g_any_tainted_arg(call.child_by_field_name("arguments"), s, param, spec, lang):
            victories.append(_clone(s))
            return


def _g_left_names(left: Any) -> List[str]:
    if left is None:
        return []
    names: List[str] = []
    for ch in left.named_children:
        if ch.type == "identifier":
            names.append(_text(ch))
        else:
            names.extend(_g_left_names(ch))
    return names


def _g_bind(name: str, value_node: Any, s: _State, param: str, spec: dict, lang: str):
    lin = _g_linear(value_node, s, param, spec, lang)
    if lin is not None:
        s.vars[name] = lin
        return
    if value_node is not None and value_node.type in spec["call"]:
        if _g_any_tainted_arg(value_node.child_by_field_name("arguments"), s, param, spec, lang):
            s.tainted.add(name)
            s.vars[name] = _sv_symbol()


def _g_bind_expr(node: Any, s: _State, param: str, spec: dict, lang: str):
    if node is None:
        return
    t = node.type
    if t in ("assignment", "assignment_expression"):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and left.type in spec["ident"]:
            _g_bind(_g_var_name(left), right, s, param, spec, lang)
    elif t == "assignment_statement":  # Go 赋值语句
        right = node.child_by_field_name("right")
        lin = _g_linear(right, s, param, spec, lang)
        for name in _g_left_names(node.child_by_field_name("left")):
            if lin is not None:
                s.vars[name] = lin
            elif right is not None and right.type in spec["call"] and \
                    _g_any_tainted_arg(right.child_by_field_name("arguments"), s, param, spec, lang):
                s.tainted.add(name)
                s.vars[name] = _sv_symbol()
    else:
        for ch in node.named_children:
            _g_bind_expr(ch, s, param, spec, lang)


def _g_bind_stmt(stmt: Any, s: _State, param: str, spec: dict, lang: str):
    """处理声明/赋值语句：把符号/常量绑定到变量。"""
    t = stmt.type
    if lang == "go" and t == "short_var_declaration":
        right = stmt.child_by_field_name("right")
        lin = _g_linear(right, s, param, spec, lang)
        for name in _g_left_names(stmt.child_by_field_name("left")):
            if lin is not None:
                s.vars[name] = lin
            elif right is not None and right.type in spec["call"] and \
                    _g_any_tainted_arg(right.child_by_field_name("arguments"), s, param, spec, lang):
                s.tainted.add(name)
                s.vars[name] = _sv_symbol()
    elif lang == "go" and t == "var_declaration":
        for spec_node in stmt.named_children:
            if spec_node.type == "var_spec":
                name_node = spec_node.child_by_field_name("name")
                if name_node is not None:
                    _g_bind(_text(name_node), spec_node.child_by_field_name("value"),
                            s, param, spec, lang)
    elif lang == "javascript" and t in ("lexical_declaration", "variable_declaration"):
        for decl in stmt.named_children:
            if decl.type == "variable_declarator":
                name_node = decl.child_by_field_name("name")
                if name_node is not None:
                    _g_bind(_text(name_node), decl.child_by_field_name("value"),
                            s, param, spec, lang)
    else:
        _g_bind_expr(stmt, s, param, spec, lang)


def _g_exec_if(node: Any, s: _State, param: str, sink_line: int,
               victories: List[_State], spec: dict, lang: str) -> List[_State]:
    cond = node.child_by_field_name("condition")
    then_b = node.child_by_field_name(spec["if_body"])
    else_b = node.child_by_field_name(spec["else"])
    out: List[_State] = []
    for cmps, unsound in _g_dnf(cond, s, param, False, spec, lang):
        ns = _clone(s)
        ns.unsound = ns.unsound or unsound
        ns.cmps.extend(cmps)
        if then_b is not None:
            out.extend(_g_exec_one(then_b, ns, param, sink_line, victories, spec, lang))
        else:
            out.append(ns)
    for cmps, unsound in _g_dnf(cond, s, param, True, spec, lang):
        ns = _clone(s)
        ns.unsound = ns.unsound or unsound
        ns.cmps.extend(cmps)
        if else_b is not None:
            # elseif/elif 链：递归当 if（保留其 condition 约束，而非落入 unsound 兜底）
            if else_b.type in ("else_if_clause", "elif_clause"):
                out.extend(_g_exec_if(else_b, ns, param, sink_line, victories, spec, lang))
            else:
                out.extend(_g_exec_one(else_b, ns, param, sink_line, victories, spec, lang))
        else:
            out.append(ns)
    return out


def _g_exec_one(node: Any, s: _State, param: str, sink_line: int,
                victories: List[_State], spec: dict, lang: str) -> List[_State]:
    t = node.type
    if t in spec["block"]:
        return _g_exec_nodes(node, s, param, sink_line, victories, spec, lang)
    if t == spec["if"]:
        return _g_exec_if(node, s, param, sink_line, victories, spec, lang)
    if t == spec["ret"]:
        _g_check_sink(node, s, param, sink_line, victories, spec, lang)
        s.dead = True
        return []
    # 循环/switch/try/else/elseif/match 等复合语句：有 body 子块 → 标记 unsound，仍扫 body 保持召回
    body = node.child_by_field_name("body")
    if body is not None and body.type in spec["block"]:
        s.unsound = True
        return _g_exec_nodes(body, s, param, sink_line, victories, spec, lang)
    # 叶子语句（声明/赋值/表达式）：sink 检测 + 绑定
    _g_check_sink(node, s, param, sink_line, victories, spec, lang)
    _g_bind_stmt(node, s, param, spec, lang)
    return [s]


def _g_exec_nodes(node: Any, s: _State, param: str, sink_line: int,
                  victories: List[_State], spec: dict, lang: str) -> List[_State]:
    states = [s]
    for stmt in node.named_children:
        if not states:
            break
        nxt: List[_State] = []
        for st in states:
            if st.dead:
                continue
            nxt.extend(_g_exec_one(stmt, st, param, sink_line, victories, spec, lang))
        states = nxt[:_MAX_PATHS]
    return states


def _symbolic_generic(method_node: Any, param_name: str, sink_line: int,
                      endpoint: Endpoint, lang: str) -> Dict[str, Any]:
    spec = _OTHER_SPECS[lang]
    body = method_node.child_by_field_name("body")
    if body is None:
        return _mk_result("unsound")
    victories: List[_State] = []
    # JS/Go 的污点源是客户端读取表达式（req.params.X / c.Param("X")），赋值时污染
    initial_tainted: Set[str] = set()
    states: List[_State] = [_State(tainted=initial_tainted)]
    if body.type in spec["block"]:
        for stmt in body.named_children:
            if not states:
                break
            nxt: List[_State] = []
            for s in states:
                nxt.extend(_g_exec_one(stmt, s, param_name, sink_line, victories, spec, lang))
            states = nxt[:_MAX_PATHS]
    else:
        # 表达式体（JS 箭头函数简写体 `(req,res) => svc.findById(...)` 等）：body 即表达式
        for s in states:
            _g_exec_one(body, s, param_name, sink_line, victories, spec, lang)
    return _conclude(victories, endpoint, param_name)


_SUFFIX_LANG = {
    ".java": "java", ".js": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go",
}


class CtxResolver:
    """按文件后缀解析 handler 上下文（多语言，带缓存）。

    增量扫描下未解析的文件也支持按需重解析；resolve 返回 (EndpointCtx, lang)。
    """

    def __init__(self):
        self._cache: Dict[str, Tuple[Dict[str, Any], str]] = {}
        self._exts: Dict[str, Any] = {}

    def resolve(self, file: str, handler: str):
        if file not in self._cache:
            lang = _SUFFIX_LANG.get(Path(file).suffix.lower(), "java")
            ext = self._exts.get(lang)
            if ext is None:
                from ..extractor.base import FRONTENDS
                ext = FRONTENDS[lang]()
                self._exts[lang] = ext
            src = Path(file).read_bytes()
            ast = ext.parse(src)
            self._cache[file] = (ext.endpoint_contexts(ast, file, src), lang)
        ctxs, lang = self._cache[file]
        return ctxs.get(handler), lang

    def get(self, file: str) -> Dict[str, Any]:
        """兼容旧接口：返回 {handler: ctx}（Java 默认）。"""
        return self.resolve(file, "")[0]