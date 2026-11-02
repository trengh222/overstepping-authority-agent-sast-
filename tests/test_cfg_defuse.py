"""CFG + 精确到达定义 验证。运行：python tests/test_cfg_defuse.py

覆盖：CFG 基本结构（if 分支）、reaching definitions 的 kill 语义、
污点传播的 kill（重定义为干净值后不再 taint）、分支汇合的 may-taint。
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from access_scan.extractor.java import JavaExtractor
from access_scan.dataflow.cfg import build_cfg
from access_scan.dataflow.defuse import JavaFlow, reaching_definitions

_ext = JavaExtractor()


def _method(src: str, fqname: str):
    ctxs = _ext.endpoint_contexts(_ext.parse(src.encode()), "Demo.java", src.encode())
    return ctxs[fqname].node


def test_cfg_if_branches():
    node = _method("""
class Demo {
    void m(boolean flag) { if (flag) { a(); } else { b(); } }
}
""", "Demo.m")
    cfg = build_cfg(node)
    # entry(if) → then/else → merge，应 ≥4 块
    assert len(cfg.blocks) >= 4, len(cfg.blocks)
    entry = cfg[cfg.entry]
    assert entry.terminator is not None and entry.terminator.type == "if_statement"
    assert len(entry.succs) == 2


def test_reaching_defs_kill():
    node = _method("""
class Demo {
    void m(Long id) { Long o = id; o = 100L; sink(o); }
}
""", "Demo.m")
    cfg = build_cfg(node)
    ins, out, defs = reaching_definitions(cfg)
    # defs: 0 = "o = id"（污点源），1 = "o = 100L"（常量）
    assert [v for v, _ in defs] == ["o", "o"], defs
    # 唯一基本块的出口，o 的到达定义应只剩 def1（def0 被 kill）
    entry = cfg.entry
    assert out[entry] == {1}, f"kill 未生效: {out[entry]}"


def test_taint_kill_no_report():
    node = _method("""
class Demo {
    void m(Long id) { Long o = id; o = 100L; sink(o); }
}
""", "Demo.m")
    flow = JavaFlow(node, {"id"}).analyze()
    assert flow.calls == [], f"重定义为干净值后不应再 taint: {flow.calls}"


def test_taint_branch_merge_may_report():
    node = _method("""
class Demo {
    void m(Long id, boolean flag) {
        Long o;
        if (flag) { o = id; } else { o = 100L; }
        sink(o);
    }
}
""", "Demo.m")
    flow = JavaFlow(node, {"id"}).analyze()
    assert len(flow.calls) == 1, f"then 分支污染路径应保留（may-taint）: {flow.calls}"


def test_loop_backedge_does_not_replay_preloop_stmt():
    # 回边若指回「循环前语句所在块」，会每次迭代重放 x=1 并 kill 循环内定义。
    node = _method("""
class Demo {
    void m(boolean cond) {
        int x = 1;
        while (cond) { x = 2; use(x); }
    }
}
""", "Demo.m")
    cfg = build_cfg(node)
    ins, out, defs = reaching_definitions(cfg)
    # def0 = x=1（循环前），def1 = x=2（循环内）
    assert [v for v, _ in defs] == ["x", "x"], defs
    header = next(b for b in cfg.blocks
                  if b.terminator is not None and b.terminator.type == "while_statement")
    # 循环头入口应同时到达 def0（首轮迭代）与 def1（后续迭代），缺一即回边重放 bug
    assert ins[header.id] == {0, 1}, f"循环头 IN 应含两个 x 定义: {ins[header.id]}"


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\n{len(tests)} tests passed.")


if __name__ == "__main__":
    _main()