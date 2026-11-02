"""easylive 静态召回漏斗统计：端点/参数/守卫/各规则候选数（测试留档用）。

用法: python tools/pipeline_stats.py "<项目根>"
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from access_scan.config import load_rules
from access_scan.extractor.base import link_guards
from access_scan.extractor.java import JavaExtractor
from access_scan.rules.filter import apply_filters
from access_scan.rules.idor import is_resource_identifier, recall_idor
from access_scan.rules.massign import recall_massign
from access_scan.rules.vertical import recall_vertical


def main(root: str) -> None:
    rootp = Path(root)
    ext = JavaExtractor()
    guards, chains, units = [], [], []
    for f in sorted(rootp.rglob("*.java")):
        src = f.read_bytes()
        ast = ext.parse(src)
        g, c = ext.extract_guards(ast, str(f))
        guards += g
        chains += c
        eps = ext.extract_endpoints(ast, str(f))
        ctxs = ext.endpoint_contexts(ast, str(f), src)
        units.append((f, eps, ctxs))

    guards = link_guards(guards, chains)
    method_index = {}
    for _f, _e, ctxs in units:
        method_index.update(ctxs)

    eps_all = [ep for _f, eps, _c in units for ep in eps]
    print(f"files={len(units)} endpoints={len(eps_all)} methods_indexed={len(method_index)}")
    print("guards:", [(g.name, g.registered, g.has_auth_check, g.patterns) for g in guards])
    print("endpoints without context:", sum(1 for ep in eps_all if ep.handler not in method_index))
    print("privilege_op=True:", sum(1 for ep in eps_all if ep.privilege_op))
    print("auth.present=True:", sum(1 for ep in eps_all if ep.auth.present))
    print("endpoints with id-like param:",
          sum(1 for ep in eps_all if any(is_resource_identifier(p.name, p.type) for p in ep.params)))
    print("param sources:", dict(Counter(p.source.value for ep in eps_all for p in ep.params)))

    cands = []
    per_ep = {}
    for ep in eps_all:
        ctx = method_index.get(ep.handler)
        if ctx is None:
            continue
        cs = (recall_idor(ep, ctx, method_index)
              + recall_vertical(ep, ctx, guards)
              + recall_massign(ep, ctx))
        per_ep[ep.id] = cs
        cands += cs
    print("raw candidates:", len(cands), dict(Counter(c.subtype for c in cands)))
    print("candidates by rule:", dict(Counter(c.rule_id for c in cands)))
    print("endpoints with >=1 candidate:", sum(1 for v in per_ep.values() if v), "/", len(eps_all))

    kept, gate = apply_filters(cands, load_rules(), [])
    print("after L4 filter: kept=", len(kept), "gateway_downgrade=", len(gate))
    print("kept by subtype:", dict(Counter(c.subtype for c in kept)))
    print("\nA2/A3/A4 候选（垂直/未授权/失效访问控制）:")
    for c in cands:
        if c.subtype in ("A2", "A3", "A4"):
            print(f"  {c.subtype} {c.rule_id} {c.endpoint.method} {c.endpoint.path}"
                  f"  priv={c.endpoint.privilege_op} auth={c.endpoint.auth.present}")


if __name__ == "__main__":
    main(sys.argv[1])
