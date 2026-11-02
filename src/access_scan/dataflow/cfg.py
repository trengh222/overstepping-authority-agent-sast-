"""L3 控制流图（方案 §6.2）：以函数为单位构建基本块 + 边。

结构化 CFG 构建器：把 Java 方法体分解为基本块，处理顺序语句、if/else、
while/do/for/enhanced-for、return、嵌套 block、try（body 展开 + catch/finally
并行分支）、switch（case 组顺序近似 fallthrough）、break/continue（经
loop_stack 帧栈真实跳转：break→循环/switch 出口，continue→循环头）。
不追求语言完备，但保证块与边正确、可做精确到达定义。
"""
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple


def _text(node: Any) -> str:
    t = node.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


@dataclass
class BasicBlock:
    id: int
    stmts: List[Any] = field(default_factory=list)   # 顺序语句
    terminator: Optional[Any] = None                  # 控制流终结语句（if/while/return…）
    succs: List[int] = field(default_factory=list)


@dataclass
class CFG:
    blocks: List[BasicBlock]
    entry: int

    def __iter__(self):
        return iter(self.blocks)

    def __len__(self):
        return len(self.blocks)

    def __getitem__(self, i):
        return self.blocks[i]

    def predecessors(self) -> dict:
        pred = {b.id: [] for b in self.blocks}
        for b in self.blocks:
            for s in b.succs:
                if s < len(self.blocks):
                    pred[s].append(b.id)
        return pred


_SEQ_STMT_TYPES = {
    "local_variable_declaration", "expression_statement", "throw_statement",
    "assert_statement", "yield_statement",
}


class _Builder:
    def __init__(self):
        self.blocks: List[BasicBlock] = []
        # 循环/switch 帧栈：(break_target, continue_target)；continue_target=None 表示 switch 帧
        self.loop_stack: List[Tuple[int, Optional[int]]] = []

    def new_block(self) -> int:
        self.blocks.append(BasicBlock(len(self.blocks)))
        return len(self.blocks) - 1

    def append(self, bid: int, stmt: Any):
        self.blocks[bid].stmts.append(stmt)

    # 返回「该语句之后可继续填充的块入口」列表
    def build_block(self, block_node: Any, entries: List[int]) -> List[int]:
        cur = list(entries)
        for stmt in block_node.named_children:
            nxt: List[int] = []
            for e in cur:
                nxt.extend(self.build_stmt(stmt, e))
            cur = nxt
            if not cur:
                break
        return cur

    def build_stmt(self, stmt: Any, entry: int) -> List[int]:
        t = stmt.type
        if t in _SEQ_STMT_TYPES:
            self.append(entry, stmt)
            return [entry]
        if t == "if_statement":
            return self._if(stmt, entry)
        if t == "while_statement":
            return self._loop(stmt, entry)
        if t == "do_statement":
            return self._do(stmt, entry)
        if t in ("for_statement", "enhanced_for_statement"):
            return self._loop(stmt, entry)
        if t == "return_statement":
            self.blocks[entry].terminator = stmt
            return []
        if t == "break_statement":
            self.blocks[entry].terminator = stmt
            if self.loop_stack:                      # break→最内层循环/switch 出口
                self.blocks[entry].succs = [self.loop_stack[-1][0]]
            return []
        if t == "continue_statement":
            self.blocks[entry].terminator = stmt
            tgt = self._continue_target()            # continue→最内层可 continue 的循环头
            if tgt is not None:
                self.blocks[entry].succs = [tgt]
            return []
        if t == "block":
            return self.build_block(stmt, [entry])
        if t == "switch_statement" or t == "switch_expression":
            return self._switch(stmt, entry)
        if t in ("try_statement", "try_with_resources_statement"):
            return self._try(stmt, entry)
        # labeled 等：按顺序语句展开（简化）
        self.append(entry, stmt)
        return [entry]

    def _if(self, stmt, entry):
        then_b = self.new_block()
        merge = self.new_block()
        self.blocks[entry].terminator = stmt
        self.blocks[entry].succs = [then_b, merge]  # 无 else 时假分支直连 merge
        then_body = stmt.child_by_field_name("consequence")
        then_succs = self.build_block(then_body, [then_b]) if then_body is not None else [then_b]
        alt = stmt.child_by_field_name("alternative")
        if alt is not None:
            else_b = self.new_block()
            self.blocks[entry].succs = [then_b, else_b]
            self._link(self.build_block(alt, [else_b]), merge) 
        self._link(then_succs, merge)
        return [merge]

    def _loop(self, stmt, entry):
        # 循环头必须是独立块：entry 含「循环之前的语句」（只执行一次），
        # 回边应指向 header 而非 entry，否则每次迭代会重放循环前语句。
        header = self.new_block()
        body_b = self.new_block()
        merge = self.new_block()
        self.blocks[entry].succs = [header]      # 循环前语句 → 循环头
        self.blocks[header].terminator = stmt     # 循环头承载 while/for 条件
        self.blocks[header].succs = [body_b, merge]
        body = stmt.child_by_field_name("body")
        self.loop_stack.append((merge, header))    # break→merge，continue→header
        try:
            body_succs = self.build_block(body, [body_b]) if body is not None else [body_b]
        finally:
            self.loop_stack.pop()
        self._link(body_succs, header)            # 回边到循环头
        return [merge]

    def _do(self, stmt, entry):
        # do-while：body 先执行一次，条件在 body 之后。独立条件块使
        # continue 落到条件处（而非重放 body 头），循环前语句只执行一次。
        body_b = self.new_block()
        cond_b = self.new_block()
        merge = self.new_block()
        self.blocks[entry].succs = [body_b]
        self.blocks[cond_b].terminator = stmt
        self.blocks[cond_b].succs = [body_b, merge]   # 条件真回 body，假出 merge
        body = stmt.child_by_field_name("body")
        self.loop_stack.append((merge, cond_b))       # break→merge，continue→条件
        try:
            body_succs = self.build_block(body, [body_b]) if body is not None else [body_b]
        finally:
            self.loop_stack.pop()
        self._link(body_succs, cond_b)
        return [merge]

    def _continue_target(self) -> Optional[int]:
        """continue 目标是最近可 continue 的帧；switch 帧（continue_target=None）穿透。"""
        for _bt, ct in reversed(self.loop_stack):
            if ct is not None:
                return ct
        return None

    def _switch(self, stmt, entry):
        """switch：case 组按并行分支建模（组内顺序近似），break 跳 merge。

        分派块刻意不设 terminator：defuse 的终结语句收集器只跳过 block 子节点，
        若把 switch 节点挂在 terminator 上会二次收集 case 体内的调用。
        """
        body = stmt.child_by_field_name("body")
        if body is None:
            for ch in reversed(list(stmt.named_children)):
                if ch.type == "switch_block":
                    body = ch
                    break
        groups = [g for g in (body.named_children if body is not None else [])
                  if g.type == "switch_block_statement_group"]
        if not groups:
            self.append(entry, stmt)   # 无 case 组：退化为顺序语句展开
            return [entry]
        merge = self.new_block()
        case_b = self.new_block()
        self.blocks[entry].succs = [case_b, merge]   # 无匹配 case 直连 merge
        self.loop_stack.append((merge, None))        # switch 帧：break→merge
        try:
            outs: List[int] = []
            for g in groups:             # 各 case 独立从分派块出发，break 只断本组链
                cur = [case_b]
                for s in (c for c in g.named_children if c.type != "switch_label"):
                    nxt = []
                    for e in cur:
                        nxt.extend(self.build_stmt(s, e))
                    cur = nxt
                    if not cur:
                        break
                outs.extend(cur)
            self._link(outs, merge)   # 各 case 出口汇入 merge
        finally:
            self.loop_stack.pop()
        return [merge]

    def _try(self, stmt, entry):
        """try：展开 body；catch/finally 作并行分支（近似：try 任意点可抛）。

        并行分支保证 catch 内定义对到达定义可见；分派块不设 terminator
        （同 _switch），避免终结语句收集器二次收集 catch 体内调用。
        """
        body = stmt.child_by_field_name("body")
        if body is None:
            self.append(entry, stmt)
            return [entry]
        merge = self.new_block()
        tb = self.new_block()
        self.blocks[entry].succs = [tb]
        # try-with-resources：`try (FileInputStream in = new FileInputStream(x))`
        # 的 resource 声明是 try 体之前求值的真实语句，必须进入块内参与污点传播
        resources = stmt.child_by_field_name("resources")
        if resources is not None:
            self.append(tb, resources)
        outs = self.build_block(body, [tb])
        fin = next((c for c in stmt.named_children if c.type == "finally_clause"), None)
        for c in (c for c in stmt.named_children if c.type == "catch_clause"):
            cb = self.new_block()
            self.blocks[entry].succs.append(cb)   # 近似：try 任意点可抛 → 任意 catch 可达
            cbody = c.child_by_field_name("body")
            outs.extend(self.build_block(cbody, [cb]) if cbody is not None else [cb])
        if fin is not None:
            fin_b = self.new_block()
            self._link(outs, fin_b)
            fbody = fin.child_by_field_name("body")
            outs = self.build_block(fbody, [fin_b]) if fbody is not None else [fin_b]
        self._link(outs, merge)
        return [merge]

    def _link(self, blocks: List[int], target: int):
        for b in blocks:
            if self.blocks[b].terminator is None:
                self.blocks[b].succs = [target]


def build_cfg(method_node: Any) -> CFG:
    b = _Builder()
    entry = b.new_block()
    body = method_node.child_by_field_name("body")
    if body is not None:
        b.build_block(body, [entry])
    return CFG(b.blocks, entry)


# ---------- 通用结构化 CFG 构建器（JS / Go，M4 真数据流） ----------

class _GenericBuilder:
    """参数化的结构化 CFG 构建器：顺序语句/块/循环类型、if-body 字段按语言配置。

    各语言差异仅在于 tree-sitter 节点命名：
    - JS：block=statement_block，if body=consequence；
    - Go：block=block（内含 statement_list），if body=consequence。
    """

    def __init__(self, seq_types, block_types, loop_types, switch_types=(), case_types=()):
        self.blocks: List[BasicBlock] = []
        self.seq_types = seq_types
        self.block_types = block_types
        self.loop_types = loop_types
        self.switch_types = switch_types
        self.case_types = case_types
        # 循环/switch 帧栈：(break_target, continue_target)；continue_target=None 表示 switch 帧
        self.loop_stack: List[Tuple[int, Optional[int]]] = []

    def new_block(self) -> int:
        self.blocks.append(BasicBlock(len(self.blocks)))
        return len(self.blocks) - 1

    def append(self, bid: int, stmt: Any):
        self.blocks[bid].stmts.append(stmt)

    def build_block(self, block_node: Any, entries: List[int]) -> List[int]:
        cur = list(entries)
        for stmt in block_node.named_children:
            nxt: List[int] = []
            for e in cur:
                nxt.extend(self.build_stmt(stmt, e))
            cur = nxt
            if not cur:
                break
        return cur

    def build_stmt(self, stmt: Any, entry: int) -> List[int]:
        t = stmt.type
        if t in self.seq_types:
            self.append(entry, stmt)
            return [entry]
        if t == "return_statement":
            self.blocks[entry].terminator = stmt
            return []
        if t == "break_statement":
            self.blocks[entry].terminator = stmt
            if self.loop_stack:
                self.blocks[entry].succs = [self.loop_stack[-1][0]]
            return []
        if t == "continue_statement":
            self.blocks[entry].terminator = stmt
            tgt = self._continue_target()
            if tgt is not None:
                self.blocks[entry].succs = [tgt]
            return []
        if t == "if_statement":
            return self._if(stmt, entry)
        if t == "do_statement":
            return self._do(stmt, entry)
        if t in self.loop_types:
            return self._loop(stmt, entry)
        if t in self.block_types:
            return self.build_block(stmt, [entry])
        if t == "try_statement":
            return self._try(stmt, entry)
        if t in self.switch_types:
            return self._switch(stmt, entry)
        # 其它复合语句：按顺序语句展开（简化）
        self.append(entry, stmt)
        return [entry]

    def _if(self, stmt, entry):
        then_b = self.new_block()
        merge = self.new_block()
        self.blocks[entry].terminator = stmt
        self.blocks[entry].succs = [then_b, merge]
        body = stmt.child_by_field_name("consequence") or stmt.child_by_field_name("body")
        then_succs = self.build_block(body, [then_b]) if body is not None else [then_b]
        alt = stmt.child_by_field_name("alternative")
        if alt is not None:
            else_b = self.new_block()
            self.blocks[entry].succs = [then_b, else_b]
            self._link(self._alternative(alt, else_b), merge)
        self._link(then_succs, merge)
        return [merge]

    def _alternative(self, alt, entry):
        if alt.type in self.block_types:
            return self.build_block(alt, [entry])
        body = alt.child_by_field_name("body") or alt.child_by_field_name("consequence")
        if body is not None:
            return self.build_block(body, [entry])
        return [entry]

    def _loop(self, stmt, entry):
        header = self.new_block()
        body_b = self.new_block()
        merge = self.new_block()
        self.blocks[entry].succs = [header]
        self.blocks[header].terminator = stmt
        self.blocks[header].succs = [body_b, merge]
        body = stmt.child_by_field_name("body")
        self.loop_stack.append((merge, header))    # break→merge，continue→header
        try:
            body_succs = self.build_block(body, [body_b]) if body is not None else [body_b]
        finally:
            self.loop_stack.pop()
        self._link(body_succs, header)
        return [merge]

    def _do(self, stmt, entry):
        # do-while：body 先执行一次，条件在 body 后；独立条件块使 continue 落到条件处。
        body_b = self.new_block()
        cond_b = self.new_block()
        merge = self.new_block()
        self.blocks[entry].succs = [body_b]
        self.blocks[cond_b].terminator = stmt
        self.blocks[cond_b].succs = [body_b, merge]
        body = stmt.child_by_field_name("body")
        self.loop_stack.append((merge, cond_b))    # break→merge，continue→条件
        try:
            body_succs = self.build_block(body, [body_b]) if body is not None else [body_b]
        finally:
            self.loop_stack.pop()
        self._link(body_succs, cond_b)
        return [merge]

    def _continue_target(self) -> Optional[int]:
        for _bt, ct in reversed(self.loop_stack):
            if ct is not None:
                return ct
        return None

    def _clause_body(self, clause):
        b = clause.child_by_field_name("body")
        if b is not None:
            return b
        for ch in clause.named_children:
            if ch.type in self.block_types:
                return ch
        return None

    _CTRL_STMT_TYPES = ("if_statement", "return_statement", "break_statement",
                        "continue_statement", "try_statement", "switch_statement",
                        "throw_statement", "do_statement")

    def _stmt_like(self):
        return (set(self.seq_types) | set(self.block_types)
                | set(self.loop_types) | set(_GenericBuilder._CTRL_STMT_TYPES))

    def _case_nodes(self, node):
        if node.type in self.case_types:
            yield node
            return
        for ch in node.named_children:
            yield from self._case_nodes(ch)

    def _collect_case_groups(self, stmt) -> List[List[Any]]:
        """按 case 分组提取各 case 体语句（组内顺序，组间并行近似）。"""
        body = stmt.child_by_field_name("body")
        root = body if body is not None else stmt
        stmt_like = self._stmt_like()
        groups: List[List[Any]] = []
        for case in self._case_nodes(root):
            g: List[Any] = []
            for ch in case.named_children:
                if ch.type in stmt_like:
                    g.append(ch)
                elif ch.type in self.block_types:
                    g.extend(sub for sub in ch.named_children
                             if sub.type in stmt_like)
            if g:
                groups.append(g)
        return groups

    def _switch(self, stmt, entry):
        """switch：case 分支并行建模（各 case 从分派块独立出发），break 跳 merge。

        分派块不设 terminator：defuse 终结语句收集器不认识 switch 体类型，
        挂 terminator 会二次收集 case 体内调用。
        """
        groups = self._collect_case_groups(stmt)
        if not groups:
            self.append(entry, stmt)   # 提取不到 case 体：退化为顺序语句展开
            return [entry]
        merge = self.new_block()
        case_b = self.new_block()
        self.blocks[entry].succs = [case_b, merge]
        self.loop_stack.append((merge, None))   # switch 帧：break→merge
        try:
            outs: List[int] = []
            for g in groups:
                cur = [case_b]
                for s in g:
                    nxt = []
                    for e in cur:
                        nxt.extend(self.build_stmt(s, e))
                    cur = nxt
                    if not cur:
                        break
                outs.extend(cur)
            self._link(outs, merge)
        finally:
            self.loop_stack.pop()
        return [merge]

    def _try(self, stmt, entry):
        """try：展开 body；catch/finally 作并行分支（近似 may 路径）。

        分派块不设 terminator：避免终结语句收集器二次收集 catch 体内调用。
        Go 无 try/catch，此分支仅对 JS 生效。
        """
        body = stmt.child_by_field_name("body")
        if body is None:
            self.append(entry, stmt)
            return [entry]
        merge = self.new_block()
        tb = self.new_block()
        self.blocks[entry].succs = [tb]
        outs = self.build_block(body, [tb])
        fin = next((c for c in stmt.named_children if c.type == "finally_clause"), None)
        for c in (c for c in stmt.named_children if c.type == "catch_clause"):
            cb = self.new_block()
            self.blocks[entry].succs.append(cb)
            cbody = self._clause_body(c)
            outs.extend(self.build_block(cbody, [cb]) if cbody is not None else [cb])
        if fin is not None:
            fin_b = self.new_block()
            self._link(outs, fin_b)
            fbody = self._clause_body(fin)
            outs = self.build_block(fbody, [fin_b]) if fbody is not None else [fin_b]
        self._link(outs, merge)
        return [merge]

    def _link(self, blocks: List[int], target: int):
        for b in blocks:
            if self.blocks[b].terminator is None:
                self.blocks[b].succs = [target]


_JS_SEQ_TYPES = ("expression_statement", "lexical_declaration", "variable_declaration",
                 "throw_statement", "empty_statement")
_GO_SEQ_TYPES = ("expression_statement", "short_var_declaration", "var_declaration",
                 "assignment_statement", "inc_statement", "dec_statement",
                 "send_statement", "go_statement", "defer_statement", "empty_statement")


_JS_SWITCH = (("switch_statement",), ("switch_case", "switch_default"))
_GO_SWITCH = (("expression_switch_statement", "type_switch_statement"),
              ("expression_case", "default_case", "type_case"))


def build_js_cfg(method_node: Any) -> CFG:
    b = _GenericBuilder(_JS_SEQ_TYPES, ("statement_block",),
                        ("while_statement", "for_statement", "for_in_statement"),
                        *_JS_SWITCH)
    return _run_generic(b, method_node)


def build_go_cfg(method_node: Any) -> CFG:
    b = _GenericBuilder(_GO_SEQ_TYPES, ("block", "statement_list"),
                        ("for_statement",), *_GO_SWITCH)
    return _run_generic(b, method_node)


def _run_generic(b: _GenericBuilder, method_node: Any) -> CFG:
    entry = b.new_block()
    body = method_node.child_by_field_name("body")
    if body is not None:
        b.build_block(body, [entry])
    return CFG(b.blocks, entry)