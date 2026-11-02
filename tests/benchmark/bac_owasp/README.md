# 越权（Broken Access Control）基准集 · OWASP Benchmark 口径

一套**独立于仓库既有 fixtures/ground_truth** 的越权检测基准：每个用例目录 = 一个最小但
真实的 Web 应用片段，配套人工标注（`fragments/*.csv`），计分沿用
[OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) 的官方口径：

```
TPR = TP / (TP + FN)      # 真实越权被报出
FPR = FP / (FP + TN)      # 安全用例被误报
Score = TPR - FPR         # 官方 ranking 指标，[-1, 1]
```

> 说明：OWASP Benchmark 本体（BenchmarkJava，2740 个 servlet 用例）只覆盖注入/加密类
> 缺陷，**不含任何访问控制用例**（用越权扫描器去跑它只会得到 0 TP 与一批 FP，
> 不构成有效基线）。本目录因此在 **方法论** 上对齐它（用例标签 + expected-results CSV +
> TPR/FPR/Score + 按类别分解 + 逐用例隔离扫描），而**用例内容**是按越权类型新写的。

## 目录

```
tests/benchmark/bac_owasp/
├─ corpus/<lang>/<case_id>/...      # 104 个人工用例（java/js/go）+ 36 个生成用例
├─ fragments/<lang>.csv             # 标注分片（run_suite 合并）
├─ fragments/gen.csv                # 生成器产出的标注
├─ legacy_corpus/                   # 已移出套件的历史语料（python/php，不参与跑分）
├─ gen_cases.py                     # 模板 × 资源域批量生成（标签由构造保证）
├─ run_suite.py                     # 逐用例隔离扫描，落 per_case.json/csv + run.log
├─ score.py                         # 计分：score.md / score.json
└─ analyze.py                       # 语料模式对照 + FN/FP 逐例明细（复核用）
```

> 语言范围：**Java / JavaScript / Go**。Python、PHP 的检测前端已从项目中移除
> （2026-10-30），对应语料与标注移到 `legacy_corpus/` 仅作历史留存，`run_suite.py`
> 按 `corpus/<lang>/` 子目录枚举用例，因此不会再把它们计进 TPR/FPR。

## 标注格式

`fragments/*.csv` 表头：

```
case_id,category,language,real_vulnerability,endpoint_path,source_file,note
```

- `category`：`A1-IDOR` / `A2-Vertical` / `A3-Unauth` / `A4-ClientAuth` / `B6-FieldExposure`
- `real_vulnerability`：`1` = 真实越权（应报出），`0` = 安全实现（不应报出）
- 每个用例目录只放 **1 个目标端点**（正例必须是真实可越权的链路）

## 运行

```powershell
cd tests/benchmark/bac_owasp
$env:PYTHONPATH = "$PWD\..\..\..\src"
python gen_cases.py --clean               # 重生成 36 个 gen-* 用例与 fragments/gen.csv
python run_suite.py --out ..\..\..\runs\bac_owasp_<ts> --corpus-mode   # 逐例隔离 + 整目录对照
python score.py   --run ..\..\..\runs\bac_owasp_<ts>                   # OWASP 口径计分
python analyze.py --run ..\..\..\runs\bac_owasp_<ts>                   # 翻转明细 + FN/FP 根因附件
```

### 最近一次全量结果（140 例 = java/js/go，确定性层）

`runs/bac_owasp_java_go_js/score.md`：**TPR 86.2% · FPR 32.1% · Score +0.541 · 精确率 81.5%**
（java 100.0%/3.6%，js 63.6%/42.9%，go 81.0%/90.9%；authored 82.6%/14.3%，generated 100%/66.7%）。
按类别：A1 93.6%/42.9%、A2 92.9%/16.7%、A3 83.3%/16.7%、A4 66.7%/0%、B6 50.0%/0%。

同一套语料在语言收敛前的 210 例结果（含 python/php）为 `runs/bac_owasp_full3/`：
**TPR 69.2% · FPR 31.2% · Score +0.380 · 精确率 78.3%**；其中 java 100%/3.6%、go 81.0%/90.9%、
js 63.6%/42.9% —— 与收敛后逐语言数字完全一致，说明删除 Python/PHP 前端没有改变
Java/Go/JS 的检测行为（只是把两种零召回语言移出计分）。

主要缺口：Go/JS 的「当前用户」变量追踪（`c.Get("uid")`、`req.session.userId` 未视为归属来源）
导致 `gen-{go,js}-a1-neg-*` 12 个负例误报；JS 的 A3/A4/B6 缺特性（NestJS 装饰器路由未抽取、
无 JS 字段事实）；B6 仅 Java 可测（A4/B6 的 FN 全在 js/go）。根因与修复优先级见
`runs/bac_owasp_full1/REPORT.md` 与 `runs/bac_owasp_java_go_js/NOTES.md`。

`run_suite.py` 默认逐用例隔离扫描：负例常靠目录内的全局守卫/拦截器表达安全语义，
整目录一次扫描会让守卫跨用例泄漏（见 `runs/easylive_*/SUMMARY.md` 的 D1），污染标签。
`--corpus-mode` 额外跑一次整目录扫描作为对照，用于量化该泄漏。

## 评测口径

- 检测 = 该用例扫描结果里存在 `LIKELY`/`CONFIRMED` 的 finding（`UNCERTAIN` 不算报出）。
- 静态召回 + L4 + 判定层全流程（`cli.run`），不启用 LLM 与对抗复核，保证可复现。
- 计分器按 `category` / `language` / `origin`（authored vs generated）分解，并输出
  FN/FP 清单，供人工复核标注本身。
