"""access_scan：多语言白盒越权检测（IDOR/垂直越权/未授权/失效访问控制）。

流水线：源码 → AST → IR → 候选(Candidate) → verdict(Finding) → SARIF/Markdown/JSON。
L1–L4 确定性静态分析，L5 LLM 语义判定可插拔（方案 §1/§2）。
"""

__version__ = "0.1.0"