"""cfg.py 结构化 CFG 单元测试：break/continue/try/switch/do 优化（正/负样本）。

运行：python -m pytest tests/test_cfg.py -q
覆盖：break 跳循环出口、continue 跳循环头、break 后死代码不建块（负样本）、
try body 展开 + catch 并行分支、switch case 建模 + switch 内 break、
JS do-while 独立条件块。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from tree_sitter import Language, Parser
import tree_sitter_java
import tree_sitter_javascript

from access_scan.dataflow.cfg import build_cfg, build_js_cfg

_JAVA_LANG = Language(tree_sitter_java.language())
_JS_LANG = Language(tree_sitter_javascript.language())


def _parse(lang, src: str):
    return Parser(lang).parse(src.encode("utf-8")).root_node


def _find(root, ttype):
    if root.type == ttype:
        return root
    for ch in root.named_children:
        r = _find(ch, ttype)
        if r is not None:
            return r
    return None


def _text_of(stmt) -> str:
    t = stmt.text
    return t.decode("utf-8", errors="replace") if isinstance(t, bytes) else str(t)


def _blocks_with(cfg, substr):
    return [b for b in cfg.blocks
            if any(substr in _text_of(s) for s in b.stmts)]


def _term_blocks(cfg, ttype):
    return [b for b in cfg.blocks
            if b.terminator is not None and b.terminator.type == ttype]


def _java_cfg(body: str):
    src = f"class T {{ void m(long id) {{ {body} }} }}"
    node = _find(_parse(_JAVA_LANG, src), "method_declaration")
    return build_cfg(node)


def _js_cfg(body: str):
    src = f"function m(req) {{ {body} }}"
    node = _find(_parse(_JS_LANG, src), "function_declaration")
    return build_js_cfg(node)


# ---------- Java ----------

def test_java_break_targets_loop_exit():
    cfg = _java_cfg("for (int i = 0; i < 3; i++) { if (id > 1) { break; } use(id); } after(id);")
    header = _term_blocks(cfg, "for_statement")[0]
    merge = cfg.blocks[header.succs[1]]
    b = _term_blocks(cfg, "break_statement")[0]
    assert b.succs == [merge.id], "break 应跳循环出口 merge"
    assert _blocks_with(cfg, "use(id)"), "循环体内的 use 应可达"
    assert _blocks_with(cfg, "after(id)"), "循环后的 after 应可达"


def test_java_continue_targets_header():
    cfg = _java_cfg("for (int i = 0; i < 3; i++) { if (id > 1) { continue; } use(id); }")
    header = _term_blocks(cfg, "for_statement")[0]
    c = _term_blocks(cfg, "continue_statement")[0]
    assert c.succs == [header.id], "continue 应跳循环头"
    assert _blocks_with(cfg, "use(id)"), "非 continue 路径上 use 应可达"


def test_java_dead_code_after_break_excluded():
    """负样本：break 之后的语句不可达，不得建成块。"""
    cfg = _java_cfg("for (int i = 0; i < 3; i++) { if (id > 1) { break; deadAfter(id); } }")
    assert not _blocks_with(cfg, "deadAfter"), "break 后死代码不应入任何块"
    assert _term_blocks(cfg, "break_statement")


def test_java_switch_modeled():
    cfg = _java_cfg("switch ((int) id) { case 1: a(id); break; case 2: b(id); } after(id);")
    disp = cfg.blocks[cfg.entry]
    assert disp.terminator is None, "switch 分派块不挂 terminator（避免二次收集）"
    assert len(disp.succs) == 2, "分派块：case 路径 + 无匹配直连 merge"
    assert _blocks_with(cfg, "a(id)") and _blocks_with(cfg, "b(id)")
    merge = _blocks_with(cfg, "after(id)")[0]
    for b in _term_blocks(cfg, "break_statement"):
        assert b.succs == [merge.id], "switch 内 break 应跳 switch merge"


def test_java_try_expanded_catch_parallel():
    cfg = _java_cfg("try { h(id); } catch (Exception e) { g(id); } after(id);")
    disp = cfg.blocks[cfg.entry]
    assert disp.terminator is None and len(disp.succs) == 2, "try 分派：body + catch 并行分支"
    tb, cb = _blocks_with(cfg, "h(id)")[0], _blocks_with(cfg, "g(id)")[0]
    assert tb.id != cb.id, "try body 与 catch body 应为不同块"
    merge = _blocks_with(cfg, "after(id)")[0]
    assert tb.succs == [merge.id] and cb.succs == [merge.id], "两分支汇入 merge"


# ---------- JavaScript ----------

def test_js_do_while_cond_block():
    cfg = _js_cfg("let i = 0; do { const id = req.params.id; db.f(id); } while (i < 2); after(req);")
    cond = _term_blocks(cfg, "do_statement")[0]
    body = _blocks_with(cfg, "db.f(id)")[0]
    merge = _blocks_with(cfg, "after(req)")[0]
    assert cond.succs == [body.id, merge.id], "do 条件块：真回 body，假出 merge"
    assert cfg.blocks[cfg.entry].succs == [body.id], "entry 无条件先入 body"


def test_js_switch_with_break():
    cfg = _js_cfg('switch (req.params.id) { case "1": a(req.params.id); break; default: b(req.params.id); } after(req);')
    assert _blocks_with(cfg, "a(req.params.id)") and _blocks_with(cfg, "b(req.params.id)")
    merge = _blocks_with(cfg, "after(req)")[0]
    for b in _term_blocks(cfg, "break_statement"):
        assert b.succs == [merge.id]


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()
