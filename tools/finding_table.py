"""把 access-scan 的 findings.json 渲染成可读表格（测试留档用）。

用法: python tools/finding_table.py runs/<run>/static/findings.json [> out.txt]
"""
import json
import sys


def main(path: str) -> None:
    data = json.load(open(path, encoding="utf-8"))
    items = data.get("findings") if isinstance(data, dict) else data
    items = items or []
    print(f"# findings={len(items)}  source={path}")
    if isinstance(data, dict):
        print("stats:", json.dumps(data.get("stats") or {}, ensure_ascii=False))
        llm = data.get("llm")
        if isinstance(llm, dict):
            llm = {k: v for k, v in llm.items() if k not in ("raw", "samples")}
        print("llm:", json.dumps(llm, ensure_ascii=False)[:600])
        print("cache_hits:", data.get("cache_hits"))
    print()
    header = ("#", "sub", "verdict", "method", "path", "handler", "file:line",
              "auth", "own", "priv", "flags", "counterex")
    widths = (3, 3, 9, 7, 46, 34, 40, 5, 5, 5, 30, 10)
    print(" ".join(h.ljust(w) for h, w in zip(header, widths)))
    for i, f in enumerate(items, 1):
        c = f.get("candidate") or {}
        ep = c.get("endpoint") or {}
        acc = c.get("access") or {}
        ev = f.get("evidence") or {}
        file = ep.get("file") or ""
        src = f"{file.split(chr(92))[-1]}:{ep.get('line_start')}-{ep.get('line_end')}"
        flags = ",".join(x.get("name", "") for x in (c.get("flag_refs") or []))
        row = (
            str(i),
            str(c.get("subtype") or ""),
            str(f.get("verdict") or ""),
            str(ep.get("method") or ""),
            str(ep.get("path") or "")[:widths[4]],
            str(ep.get("handler") or "")[:widths[5]],
            src[:widths[6]],
            str((ep.get("auth") or {}).get("present")),
            str(acc.get("ownership_predicate")),
            str(ep.get("privilege_op")),
            flags[:widths[10]],
            str(ev.get("counterexample") or ""),
        )
        print(" ".join(v.ljust(w) for v, w in zip(row, widths)))

    # 证据字段明细（每条的 rule_id / taint_flow / sink）
    print("\n## evidence detail")
    for i, f in enumerate(items, 1):
        c = f.get("candidate") or {}
        ep = c.get("endpoint") or {}
        acc = c.get("access") or {}
        ev = f.get("evidence") or {}
        print(f"\n[{i}] {ep.get('method')} {ep.get('path')}  ({f.get('verdict')}/{c.get('subtype')})")
        print(f"    rule_id={c.get('rule_id')} conf={f.get('confidence')} disp={f.get('disposition')}")
        print(f"    auth={json.dumps(ep.get('auth'), ensure_ascii=False)}")
        print(f"    entity={acc.get('entity')} id_param={acc.get('identifier_param')} own={acc.get('ownership_predicate')}")
        print(f"    flow={acc.get('flow')}")
        print(f"    sink={acc.get('sink_snippet')}")
        print(f"    reach={c.get('reachability_hints')} flags={c.get('flag_refs')}")
        print(f"    evidence_keys={sorted(ev.keys())}")
        if ev.get("reachability_reason"):
            print(f"    reachability_reason={ev.get('reachability_reason')}")
        if ev.get("gate_verification"):
            print(f"    gate_verification={ev.get('gate_verification')}")
        if f.get("poc"):
            print(f"    poc={f.get('poc')!r}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "findings.json")
