"""L3 def-use 链（方案 §6.2）：变量的定义点 → 使用点。

基于 CFG（cfg.py）的**精确数据流**：
- `reaching_definitions(cfg)`：标准 reaching definitions 求解（gen/kill + worklist），
  精确给出每个块入口/出口的「变量可能来自哪些定义点」——支持 kill（变量被重新
  定义后，旧定义不再到达）。
- `analyze_taint(cfg, sources)`：以 reaching definitions 的 kill 语义做前向 may-taint
  传播（变量重定义为干净值时移除旧污点），并在块内顺序处理时收集「实参携带污点」
  的调用点，供 taint 层做 sink 判定与跨过程追踪。

两者均只实现 Java；其余语言沿用 taint.py 的文本级启发式。
"""
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .cfg import CFG, build_cfg, build_go_cfg, build_js_cfg


def _text(node: Any) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


# ---------- 表达式：作为「值」被引用的标识符 ----------

def _value_idents(node: Any) -> Iterable[str]:
    """表达式里作为值引用的标识符：跳过方法名与字段名。

    findById(id) → {"id"}；order.userId → {"order"}（字段随接收者污染，over-approx）。
    """
    if node is None:
        return
    if node.type == "identifier":
        yield _text(node)
    elif node.type == "method_invocation":
        # 接收者也是值引用：`request.getDocId()` 的污点来自 request 本身，
        # 只看实参会把「请求/会话对象派生取值」漏掉（@RequestBody DTO 拆包依赖此路径）。
        o = node.child_by_field_name("object")
        if o is not None:
            yield from _value_idents(o)
        a = node.child_by_field_name("arguments")
        if a is not None:
            yield from _value_idents(a)
    elif node.type == "field_access":
        o = node.child_by_field_name("object")
        if o is not None:
            yield from _value_idents(o)
    else:
        for ch in node.named_children:
            yield from _value_idents(ch)


def _contains_tainted(node: Any, tainted: Set[str]) -> bool:
    return any(i in tainted for i in _value_idents(node))


def _expr_tainted(node: Any, tainted: Set[str], calls: List[Tuple[Any, List[int]]]) -> bool:
    """返回表达式是否携带污点；副作用收集「实参被污染」的方法调用（含赋值 kill）。"""
    if node is None:
        return False
    t = node.type
    if t == "identifier":
        return _text(node) in tainted
    if t in ("method_invocation", "object_creation_expression"):
        # 链式调用 a().b() / x.findById(id).orElse(v)：递归处理接收者，防吞内层。
        # 对象构造 new FileInputStream(path) 无接收者，但其实参污点要收集为调用。
        obj = node.child_by_field_name("object") if t == "method_invocation" else None
        obj_tainted = _expr_tainted(obj, tainted, calls) if obj is not None else False
        args = node.child_by_field_name("arguments")
        tainted_idxs: List[int] = []
        if args is not None:
            for i, arg in enumerate(args.named_children):
                if _contains_tainted(arg, tainted):
                    tainted_idxs.append(i)
        if tainted_idxs:
            calls.append((node, tainted_idxs))
        if t == "object_creation_expression":
            return obj_tainted or bool(tainted_idxs)
        # D6：setter 把污点写进对象（actionQuery.setUserId(userId) → actionQuery 污点）
        mname_node = node.child_by_field_name("name")
        mname = _text(mname_node) if mname_node else ""
        if obj is not None and obj.type == "identifier" and tainted_idxs \
                and mname.startswith("set"):
            tainted.add(_text(obj))
        return obj_tainted or bool(tainted_idxs)
    if t == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        rt = _expr_tainted(right, tainted, calls)
        if left is not None and left.type == "identifier":
            tainted.discard(_text(left))  # kill：先移除旧污点，再按新值决定是否加回
            if rt:
                tainted.add(_text(left))
        elif left is not None and left.type == "field_access" and rt:
            obj = left.child_by_field_name("object")
            if obj is not None and obj.type == "identifier":
                tainted.add(_text(obj))  # D6：query.userId = userId → query 污点
        return rt
    if t == "field_access":
        o = node.child_by_field_name("object")
        return _expr_tainted(o, tainted, calls) if o is not None else False
    any_t = False
    for ch in node.named_children:
        if _expr_tainted(ch, tainted, calls):
            any_t = True
    return any_t


# ---------- 定义点收集 ----------

def _assignment_lefts(node: Any) -> List[str]:
    if node is None:
        return []
    if node.type == "assignment_expression":
        out: List[str] = []
        left = node.child_by_field_name("left")
        if left is not None and left.type == "identifier":
            out.append(_text(left))
        out.extend(_assignment_lefts(node.child_by_field_name("right")))
        return out
    out = []
    for ch in node.named_children:
        out.extend(_assignment_lefts(ch))
    return out


def _stmt_def_vars(stmt: Any) -> List[str]:
    out: List[str] = []
    if stmt.type == "local_variable_declaration":
        for decl in stmt.named_children:
            if decl.type == "variable_declarator":
                n = decl.child_by_field_name("name")
                if n is not None:
                    out.append(_text(n))
    elif stmt.type == "resource_specification":
        for res in stmt.named_children:
            if res.type != "resource":
                continue
            kids = res.named_children
            if len(kids) >= 2 and kids[-2].type == "identifier":
                out.append(_text(kids[-2]))
    else:
        for ch in stmt.named_children:
            out.extend(_assignment_lefts(ch))
    return out


def _collect_defs(cfg: CFG) -> Tuple[List[Tuple[str, int]], Dict[int, List[Tuple[str, int]]]]:
    """收集所有定义点：(变量名, 所属块 id) + 每块的定义列表 [(var, def_id)]。"""
    defs: List[Tuple[str, int]] = []
    block_defs: Dict[int, List[Tuple[str, int]]] = {b.id: [] for b in cfg.blocks}
    for b in cfg.blocks:
        for stmt in b.stmts:
            for var in _stmt_def_vars(stmt):
                did = len(defs)
                defs.append((var, b.id))
                block_defs[b.id].append((var, did))
    return defs, block_defs


# ---------- 精确到达定义（reaching definitions） ----------

def reaching_definitions(cfg: CFG):
    """标准 reaching definitions 数据流。

    返回 (ins, out, defs)：
      - ins/out: {block_id: set[def_id]}，块入口/出口处可能到达的定义点；
      - defs: [(var, block_id)]，def_id → 定义点。
    """
    defs, block_defs = _collect_defs(cfg)
    var_defs: Dict[str, Set[int]] = {}
    for i, (v, _b) in enumerate(defs):
        var_defs.setdefault(v, set()).add(i)

    gen: Dict[int, Set[int]] = {}
    kill: Dict[int, Set[int]] = {}
    for b in cfg.blocks:
        last: Dict[str, int] = {}
        killed: Set[int] = set()
        for v, did in block_defs[b.id]:
            last[v] = did
            killed |= var_defs.get(v, set())
        gen[b.id] = set(last.values())
        kill[b.id] = killed

    pred = cfg.predecessors()
    ins: Dict[int, Optional[Set[int]]] = {b.id: None for b in cfg.blocks}  # None=未计算
    out: Dict[int, Set[int]] = {b.id: set() for b in cfg.blocks}
    worklist = [b.id for b in cfg.blocks]
    while worklist:
        bid = worklist.pop()
        new_in: Set[int] = set()
        for p in pred[bid]:
            new_in |= out[p]
        if ins[bid] is not None and new_in == ins[bid]:
            continue
        ins[bid] = new_in
        out[bid] = gen[bid] | (new_in - kill[bid])
        for s in cfg.blocks[bid].succs:
            worklist.append(s)
    return {k: (v or set()) for k, v in ins.items()}, out, defs


# ---------- 精确污点传播（带 kill，等价于按到达定义消旧） ----------

def _transfer_out(b, in_set: Set[str]) -> Set[str]:
    t = set(in_set)
    _process_stmts(b.stmts, t, [])  # 传播阶段丢弃调用，仅第二遍收集
    return t


def _process_stmts(stmts, t: Set[str], calls):
    for stmt in stmts:
        _process_stmt(stmt, t, calls)


def _process_stmt(stmt, t: Set[str], calls):
    if stmt.type == "local_variable_declaration":
        for decl in stmt.named_children:
            if decl.type == "variable_declarator":
                name_node = decl.child_by_field_name("name")
                if name_node is not None:
                    name = _text(name_node)
                    v = _expr_tainted(decl.child_by_field_name("value"), t, calls)
                    t.discard(name)  # kill
                    if v:
                        t.add(name)
    elif stmt.type == "expression_statement":
        for ch in stmt.named_children:
            _expr_tainted(ch, t, calls)
    elif stmt.type == "resource_specification":
        # try-with-resources 的 resource 声明：Type name = value（value 里可能有构造调用）
        for res in stmt.named_children:
            if res.type != "resource":
                _expr_tainted(res, t, calls)
                continue
            kids = res.named_children
            value = kids[-1] if kids else None
            name = kids[-2] if len(kids) >= 2 else None
            v = _expr_tainted(value, t, calls)
            if name is not None and name.type == "identifier":
                n = _text(name)
                t.discard(n)  # kill
                if v:
                    t.add(n)
    else:
        for ch in stmt.named_children:
            _expr_tainted(ch, t, calls)


def _collect_terminator_calls(term, tainted: Set[str], calls):
    """终结语句（return/if/while 条件）表达式里的调用，如 `return service.find(id)`。"""
    t = set(tainted)
    for ch in term.named_children:
        if ch.type == "block":
            continue  # 循环体/if 体已在 CFG 展开
        _expr_tainted(ch, t, calls)


def _analyze_taint(cfg: CFG, sources: Set[str], transfer_fn, collect_fn):
    """前向 may-taint 数据流骨架（worklist 迭代到不动点，含 kill）。

    transfer_fn(block, in_set) -> out_set；collect_fn(block, in_set, calls) 收集被污染调用。
    返回 (ins, calls)。
    """
    pred = cfg.predecessors()
    ins: Dict[int, Optional[Set[str]]] = {b.id: None for b in cfg.blocks}  # None=未计算
    out: Dict[int, Set[str]] = {b.id: set() for b in cfg.blocks}
    worklist = [cfg.entry]
    while worklist:
        bid = worklist.pop()
        new_in = set(sources) if bid == cfg.entry else set()
        for p in pred[bid]:
            new_in |= out[p]
        if ins[bid] is not None and new_in == ins[bid]:
            continue
        ins[bid] = new_in
        out[bid] = transfer_fn(cfg.blocks[bid], new_in)
        for s in cfg.blocks[bid].succs:
            worklist.append(s)

    calls: List[Tuple[Any, List[int]]] = []
    for b in cfg.blocks:
        collect_fn(b, set(ins[b.id] or set()), calls)
    return {k: (v or set()) for k, v in ins.items()}, calls


def _java_collect(b, t: Set[str], calls):
    _process_stmts(b.stmts, t, calls)
    if b.terminator is not None:
        _collect_terminator_calls(b.terminator, t, calls)


def analyze_taint(cfg: CFG, sources: Set[str]):
    """Java 方法体的前向 may-taint 数据流（带 kill，见 _analyze_taint）。"""
    return _analyze_taint(cfg, sources, _transfer_out, _java_collect)


class JavaFlow:
    """Java 方法体的精确污点传播分析器（基于 CFG）。

    输入：方法节点 + 污点源变量名集合（如 {"id"}）。
    产出：
      - calls: [(调用节点, 被污染实参位置列表)]；
      - tainted: 方法体出口处仍携带污点的变量集合（无后继块的入口污点并集）。
    """

    def __init__(self, method_node: Any, sources: Set[str]):
        self.method_node = method_node
        self.sources = set(sources)
        self.calls: List[Tuple[Any, List[int]]] = []
        self.tainted: Set[str] = set()

    def analyze(self) -> "JavaFlow":
        cfg = build_cfg(self.method_node)
        ins, calls = analyze_taint(cfg, self.sources)
        self.calls = calls
        self.tainted = set()
        for b in cfg.blocks:
            if not b.succs:
                self.tainted |= ins[b.id]
        return self


# ---------- JavaScript（Express/Prisma）def-use ----------
_JS_REQ_SOURCES = {"params", "query", "body"}


def _js_is_source(node: Any, param_name: str) -> bool:
    """node 是否 req.params.<param> / req.query.<param> / req.body.<param>。"""
    if node is None or node.type != "member_expression":
        return False
    prop = node.child_by_field_name("property")
    if prop is None or _text(prop) != param_name:
        return False
    obj = node.child_by_field_name("object")
    if obj is None or obj.type != "member_expression":
        return False
    src = obj.child_by_field_name("property")
    if src is None or _text(src) not in _JS_REQ_SOURCES:
        return False
    base = obj.child_by_field_name("object")
    return base is not None and _text(base) == "req"


def _js_value_idents(node: Any) -> Iterable[str]:
    if node is None:
        return
    t = node.type
    if t in ("identifier", "shorthand_property_identifier"):
        yield _text(node)
    elif t == "call_expression":
        args = node.child_by_field_name("arguments")
        if args is not None:
            yield from _js_value_idents(args)
    elif t == "member_expression":
        obj = node.child_by_field_name("object")
        if obj is not None:
            yield from _js_value_idents(obj)
    elif t == "subscript_expression":
        obj = node.child_by_field_name("object")
        if obj is not None:
            yield from _js_value_idents(obj)
    elif t == "object":
        for ch in node.named_children:
            if ch.type == "pair":
                yield from _js_value_idents(ch)
            elif ch.type == "shorthand_property_identifier":
                yield _text(ch)
    elif t == "pair":
        value = node.child_by_field_name("value")
        if value is not None:
            yield from _js_value_idents(value)
        else:
            # shorthand { id }：key 即变量引用
            key = node.child_by_field_name("key")
            if key is not None:
                yield _text(key)
    elif t in ("await_expression", "parenthesized_expression"):
        yield from _js_value_idents(node.named_children[0] if node.named_children else None)
    else:
        for ch in node.named_children:
            yield from _js_value_idents(ch)


def _js_contains_source(node: Any, param_name: str) -> bool:
    """node 的任意 descendant 是否 req.params/query/body.<param>（含对象字面量深层嵌套）。"""
    if node is None:
        return False
    if _js_is_source(node, param_name):
        return True
    return any(_js_contains_source(ch, param_name) for ch in node.named_children)


def _js_contains_tainted(node: Any, tainted: Set[str], param_name: str) -> bool:
    return _js_contains_source(node, param_name) or any(
        i in tainted for i in _js_value_idents(node))


def _js_expr_tainted(node: Any, tainted: Set[str], calls, param_name: str) -> bool:
    if node is None:
        return False
    t = node.type
    if t == "identifier":
        return _text(node) in tainted
    if t == "member_expression":
        if _js_is_source(node, param_name):
            return True
        obj = node.child_by_field_name("object")
        return _js_expr_tainted(obj, tainted, calls, param_name) if obj is not None else False
    if t == "call_expression":
        fn = node.child_by_field_name("function")
        fn_t = _js_expr_tainted(fn, tainted, calls, param_name) if fn is not None else False
        args = node.child_by_field_name("arguments")
        tainted_idxs: List[int] = []
        if args is not None:
            for i, arg in enumerate(args.named_children):
                if _js_contains_tainted(arg, tainted, param_name):
                    tainted_idxs.append(i)
        if tainted_idxs:
            calls.append((node, tainted_idxs))
        return fn_t or bool(tainted_idxs)
    if t == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        rt = _js_expr_tainted(right, tainted, calls, param_name)
        if left is not None and left.type == "identifier":
            tainted.discard(_text(left))
            if rt:
                tainted.add(_text(left))
        return rt
    if t == "subscript_expression":
        obj = node.child_by_field_name("object")
        return _js_expr_tainted(obj, tainted, calls, param_name) if obj is not None else False
    if t in ("await_expression", "parenthesized_expression"):
        return _js_expr_tainted(node.named_children[0] if node.named_children else None,
                                tainted, calls, param_name)
    if t == "object":
        any_t = False
        for ch in node.named_children:
            if ch.type == "pair" and _js_expr_tainted(ch.child_by_field_name("value"),
                                                      tainted, calls, param_name):
                any_t = True
        return any_t
    if t == "pair":
        return _js_expr_tainted(node.child_by_field_name("value"), tainted, calls, param_name)
    any_t = False
    for ch in node.named_children:
        if _js_expr_tainted(ch, tainted, calls, param_name):
            any_t = True
    return any_t


def _js_process_stmt(stmt, t: Set[str], calls, param_name: str):
    if stmt.type in ("lexical_declaration", "variable_declaration"):
        for decl in stmt.named_children:
            if decl.type == "variable_declarator":
                name_node = decl.child_by_field_name("name")
                if name_node is not None:
                    name = _text(name_node)
                    v = _js_expr_tainted(decl.child_by_field_name("value"), t, calls, param_name)
                    t.discard(name)
                    if v:
                        t.add(name)
    else:
        for ch in stmt.named_children:
            _js_expr_tainted(ch, t, calls, param_name)


def _js_transfer_out(b, in_set: Set[str], param_name: str) -> Set[str]:
    t = set(in_set)
    for stmt in b.stmts:
        _js_process_stmt(stmt, t, [], param_name)
    return t


def _js_collect(b, t: Set[str], calls, param_name: str):
    for stmt in b.stmts:
        _js_process_stmt(stmt, t, calls, param_name)
    if b.terminator is not None:
        tt = set(t)
        for ch in b.terminator.named_children:
            if ch.type in ("statement_block", "block", "compound_statement"):
                continue
            _js_expr_tainted(ch, tt, calls, param_name)


class JsFlow:
    """JavaScript 方法体（Express handler）的跨语句污点传播。

    污点源为 req.params/query/body.<param> 读取表达式；追踪赋值别名
    （const uid = req.params.id → uid）流入 sink 调用（findUnique/findById…）。
    """

    def __init__(self, method_node: Any, param_name: str,
                 sources: Optional[Set[str]] = None):
        self.method_node = method_node
        self.param_name = param_name
        self.sources = sources  # None=handler 模式(req.params.<param>)；set=跨过程模式(变量名源)
        self.calls: List[Tuple[Any, List[int]]] = []

    def analyze(self) -> "JsFlow":
        cfg = build_js_cfg(self.method_node)
        pn = self.param_name
        init = self.sources if self.sources is not None else set()
        _ins, calls = _analyze_taint(
            cfg, init,
            lambda b, s: _js_transfer_out(b, s, pn),
            lambda b, s, c: _js_collect(b, s, c, pn))
        self.calls = calls
        return self


# ---------- Go（Gin + database/sql/GORM）def-use ----------

def _go_is_source(node: Any, param_name: str) -> bool:
    """node 是否 c.Param/Query/QueryParam/DefaultQuery/PostForm/FormValue("param")。"""
    if node is None or node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "selector_expression":
        return False
    field = fn.child_by_field_name("field")
    if field is None or _text(field) not in (
            "Param", "Query", "QueryParam", "DefaultQuery",
            "PostForm", "FormValue", "DefaultPostForm"):
        return False
    args = node.child_by_field_name("arguments")
    if args is None:
        return False
    for a in args.named_children:
        if _text(a).strip('"\'`') == param_name:
            return True
    return False


def _go_value_idents(node: Any) -> Iterable[str]:
    if node is None:
        return
    t = node.type
    if t == "identifier":
        yield _text(node)
    elif t == "call_expression":
        args = node.child_by_field_name("arguments")
        if args is not None:
            yield from _go_value_idents(args)
    elif t == "selector_expression":
        op = node.child_by_field_name("operand")
        if op is not None:
            yield from _go_value_idents(op)
    elif t == "unary_expression":
        op = node.child_by_field_name("operand")
        if op is not None:
            yield from _go_value_idents(op)
    elif t == "parenthesized_expression":
        yield from _go_value_idents(node.named_children[0] if node.named_children else None)
    else:
        for ch in node.named_children:
            yield from _go_value_idents(ch)


def _go_contains_tainted(node: Any, tainted: Set[str], param_name: str) -> bool:
    if _go_is_source(node, param_name):
        return True
    return any(i in tainted for i in _go_value_idents(node))


def _go_expr_tainted(node: Any, tainted: Set[str], calls, param_name: str) -> bool:
    if node is None:
        return False
    t = node.type
    if t == "identifier":
        return _text(node) in tainted
    if t == "call_expression":
        if _go_is_source(node, param_name):
            return True
        fn = node.child_by_field_name("function")
        fn_t = _go_expr_tainted(fn, tainted, calls, param_name) if fn is not None else False
        args = node.child_by_field_name("arguments")
        tainted_idxs: List[int] = []
        if args is not None:
            for i, arg in enumerate(args.named_children):
                if _go_contains_tainted(arg, tainted, param_name):
                    tainted_idxs.append(i)
        if tainted_idxs:
            calls.append((node, tainted_idxs))
        return fn_t or bool(tainted_idxs)
    if t == "selector_expression":
        op = node.child_by_field_name("operand")
        return _go_expr_tainted(op, tainted, calls, param_name) if op is not None else False
    if t == "unary_expression":
        op = node.child_by_field_name("operand")
        return _go_expr_tainted(op, tainted, calls, param_name) if op is not None else False
    if t == "parenthesized_expression":
        return _go_expr_tainted(node.named_children[0] if node.named_children else None,
                                tainted, calls, param_name)
    any_t = False
    for ch in node.named_children:
        if _go_expr_tainted(ch, tainted, calls, param_name):
            any_t = True
    return any_t


def _go_left_names(left: Any) -> List[str]:
    if left is None:
        return []
    names: List[str] = []
    for ch in left.named_children:
        if ch.type == "identifier":
            names.append(_text(ch))
        else:
            names.extend(_go_left_names(ch))
    return names


def _go_process_stmt(stmt, t: Set[str], calls, param_name: str):
    typ = stmt.type
    if typ in ("short_var_declaration", "assignment_statement"):
        right = stmt.child_by_field_name("right")
        rt = _go_expr_tainted(right, t, calls, param_name)
        for name in _go_left_names(stmt.child_by_field_name("left")):
            t.discard(name)
            if rt:
                t.add(name)
    elif typ == "var_declaration":
        for spec in stmt.named_children:
            if spec.type == "var_spec":
                name_node = spec.child_by_field_name("name")
                if name_node is not None:
                    name = _text(name_node)
                    value_node = spec.child_by_field_name("value")
                    if value_node is None:
                        # `var req request.GetById`：纯声明不覆盖入口污点
                        # （DTO 参数场景下入口污点正是这个变量）
                        continue
                    v = _go_expr_tainted(value_node, t, calls, param_name)
                    t.discard(name)
                    if v:
                        t.add(name)
    else:
        for ch in stmt.named_children:
            _go_expr_tainted(ch, t, calls, param_name)


def _go_transfer_out(b, in_set: Set[str], param_name: str) -> Set[str]:
    t = set(in_set)
    for stmt in b.stmts:
        _go_process_stmt(stmt, t, [], param_name)
    return t


def _go_collect(b, t: Set[str], calls, param_name: str):
    for stmt in b.stmts:
        _go_process_stmt(stmt, t, calls, param_name)
    if b.terminator is not None:
        tt = set(t)
        for ch in b.terminator.named_children:
            if ch.type in ("block", "statement_list"):
                continue
            _go_expr_tainted(ch, tt, calls, param_name)


class GoFlow:
    """Go 方法体（Gin handler）的跨语句污点传播。

    污点源为 c.Param/c.Query/c.PostForm("param") 读取；追踪短变量声明/赋值别名
    （id := c.Param("id") → id）流入 sink 调用（db.QueryRow/Query…）。
    """

    def __init__(self, method_node: Any, param_name: str,
                 sources: Optional[Set[str]] = None):
        self.method_node = method_node
        self.param_name = param_name
        self.sources = sources  # None=handler 模式(c.Param/Query("param"))；set=跨过程模式(变量名源)
        self.calls: List[Tuple[Any, List[int]]] = []

    def analyze(self) -> "GoFlow":
        cfg = build_go_cfg(self.method_node)
        pn = self.param_name
        init = self.sources if self.sources is not None else set()
        _ins, calls = _analyze_taint(
            cfg, init,
            lambda b, s: _go_transfer_out(b, s, pn),
            lambda b, s, c: _go_collect(b, s, c, pn))
        self.calls = calls
        return self
