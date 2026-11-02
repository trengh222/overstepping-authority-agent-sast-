"""诊断单个 Java 控制器：端点提取 + 规则 A/B/C 候选生成明细（测试留档用）。

用法: python tools/diag_java.py <file.java> [more.java ...]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from access_scan.dataflow.taint import trace_to_sinks
from access_scan.extractor.java import JavaExtractor
from access_scan.rules.idor import is_resource_identifier, recall_idor
from access_scan.rules.massign import recall_massign
from access_scan.rules.vertical import recall_vertical


def main(files):
    ext = JavaExtractor()
    for f in files:
        p = Path(f)
        print(f"\n===== {p.name} =====")
        src = p.read_bytes()
        ast = ext.parse(src)
        eps = ext.extract_endpoints(ast, str(p))
        ctxs = ext.endpoint_contexts(ast, str(p), src)
        print(f"endpoints={len(eps)} contexts={len(ctxs)}")
        for ep in eps:
            tags = []
            if ep.privilege_op:
                tags.append("PRIV")
            if ep.auth.present:
                tags.append(f"AUTH:{ep.auth.mechanism.value}/{ep.auth.role_or_perm}")
            params = [(x.name, x.source.value, x.type) for x in ep.params]
            print(f"\n  {ep.method:<6} {ep.path:<52} {ep.handler:<28} {' '.join(tags)}")
            print(f"         params={params}")
            ctx = ctxs.get(ep.handler)
            if ctx is None:
                print("         NO_CONTEXT")
                continue
            for x in ep.params:
                if is_resource_identifier(x.name, x.type):
                    accs = trace_to_sinks(ctx.node, x.name, ctx, {})
                    if not accs:
                        print(f"         id-param {x.name}: 无污点到 sink")
                    for a in accs:
                        print(f"         id-param {x.name}: sink_line={a.sink_line} entity={a.entity!r} "
                              f"own={a.ownership_predicate} flow={a.flow}")
            a1 = recall_idor(ep, ctx, {})
            a3 = recall_vertical(ep, ctx, [])
            a4 = recall_massign(ep, ctx)
            print(f"         -> A1={len(a1)} A3/B={len(a3)}({','.join(c.subtype for c in a3)}) C={len(a4)}")


if __name__ == "__main__":
    main(sys.argv[1:])
