# access-scan：越权漏洞白盒检测

面向 Java/Spring（以及 Python、Node/TS、Go、PHP）Web 工程的越权检测工具。静态分析负责产出带证据链的候选，LLM 参与最终判定，但结论必须能被静态证据回验。

> 仅用于自有代码或已获授权的代码审计。请勿用于未授权的目标。

## 检测范围

| 类型 | 说明 |
|---|---|
| A1 IDOR | 客户端可控的资源标识（id / 业务键 / 文件路径）流入 DB 或文件读取 sink，且没有绑定当前用户 |
| A2 垂直越权 | 特权操作（删除 / 审批 / 退款 / 授权等）只做了弱鉴权 |
| A3 未授权访问 | 敏感端点没有鉴权注解，也没有被全局守卫覆盖 |
| A4 失效访问控制 | 客户端可直接写入 `role` / `admin` 等敏感字段（Mass Assignment） |

语言前端：Java/Spring、Python（Flask/FastAPI/Django）、Node/Express（JS/TS）、Go（Gin 等）、PHP（Laravel 等）。各语言都按「解析 → 统一 IR → CFG + 到达定义污点追踪」处理，不是文本正则匹配。

## 处理流程

1. **摄取**：遍历源码文件，按后缀分派语言前端。
2. **结构提取**：路由、参数来源（PATH/QUERY/BODY）、鉴权注解、守卫（拦截器/过滤器/中间件）、实体与归属字段。
3. **数据流**：Java 用 CFG + 精确到达定义做前向 may-taint，跨语句传播别名与 setter 写入；跨方法解析支持接口→实现类、继承链上的父类方法体、`this` 同类调用，追踪深度上限 12。
4. **过滤**：排除前缀、公开资源（所有权模型声明 `PUBLIC`）的读访问、网关保护降级。
5. **LLM 判定**：证据包（污点链、sink 源码、跨过程方法切片、守卫与归属信息）交给模型；多采样投票 + 一轮对抗复核 + 缓存。
6. **报告**：text / JSON / Markdown / SARIF。

### 证据回验（LLM 结论不是最终结论）

- 模型判「非漏洞」时，必须指明拦截门（全局守卫 / 鉴权注解 / 归属校验），程序回到源码核验：门确实存在、名称与注解对得上、不依赖客户端输入、路径覆盖成立。核验不过就翻回疑似。
- 模型判「漏洞」时，引用的行号必须落在 handler 或方法体内，并能在 sink 文本中找到对应标识，证据不足不升级。
- A4 与低置信度负结论不自动关闭，只降级。

### 可达性事实

从构建清单（Maven `<modules>` / Gradle `include`）、Spring 扫描根与 `@Import`、配置键、数据流事实推导可达性：

- 由**构建/注册**这类确定性事实确认不可达的，才自动关闭；
- **配置、权限**这类运行时假设，只降级并附工单说明；
- 什么都证明不了的，保持疑似，交人工。

## 安装

```bash
pip install -e .
# 可选：LLM 判定与符号执行
pip install anthropic z3-solver
```

## 使用

```bash
# 纯静态（不调用模型）
python -m access_scan.cli /path/to/project --no-llm --format markdown -o report.md

# 启用 LLM 判定（默认 3 次采样投票）
python -m access_scan.cli /path/to/project --format json -o findings.json

# 增量扫描（复用未变更文件的基线）
python -m access_scan.cli /path/to/project --state .access_scan_state.db --no-llm

# 人工打标回写所有权模型（fp=资源公开 / confirm=资源私有）
python -m access_scan.cli tag --findings findings.json --key /api/order/ --decision confirm
```

常用参数：`--limit N`（只判定前 N 条）、`--llm-timeout`、`--llm-retries`、`--llm-max-seconds`（单轮预算）、`--llm-parallel`（采样并发）、`--no-adversarial`、`--no-symbolic`。

## LLM 配置

优先读取环境变量，其次 `config/llm.yaml`：

```bash
export ANTHROPIC_AUTH_TOKEN=...          # 也支持 ANTHROPIC_API_KEY
export ACCESS_SCAN_LLM_MODEL=deepseek-v4-pro
export ACCESS_SCAN_LLM_BASE_URL=https://your-gateway.example.com
```

仓库内提供了 [config/llm.example.yaml](config/llm.example.yaml) 模板。真实的 `config/llm.yaml` 已在 `.gitignore` 中，请勿提交。

## 配置目录

| 文件 | 作用 |
|---|---|
| `config/ownership.yaml` | 资源所有权模型：实体 → 归属字段 / 隐私级别（`PRIVATE` / `PUBLIC` / `UNKNOWN`） |
| `config/rules.yaml` | 排除前缀、网关保护前缀 |
| `config/feature_flags.yaml` | 配置开关声明，供可达性剪枝 |
| `config/projects/<name>/ownership.yaml` | 单项目的公开资源声明（按需创建，不入库） |

公开资源只豁免「读」：同一实体的按 id 删除/修改仍会报越权。

## 目录结构

```
src/access_scan/
├── extractor/        # L1+L2 语言前端：java / python / node / go / php
├── dataflow/         # L3 CFG、到达定义、污点追踪、继承链、符号执行
├── rules/            # L4 A1–A4 规则、可达性事实、过滤
├── llm/              # L5 证据包、提示词、判定与回验
├── report/           # L6 text / json / markdown / sarif
└── cli.py
tests/                # 单测 + fixtures
tests/benchmark/      # 自建基准（ground_truth.yaml）与靶场 gap 记录
tools/                # 基线比对、统计与诊断脚本
```

## 评测

| 数据集 | 结果 |
|---|---|
| 自建基准（57 条正样本，多语言） | 静态层全部命中，无误报 |
| Spring Boot 项目（162 个 Java 文件，人工标注 34 个端点） | 精确率 100%、召回 83.3%（3 条漏报中 2 条复核后认为服务层已有归属校验，标注存疑） |
| 性能（266k 行，冷启动全量扫描） | 约 31 秒 |

样本规模有限，上述数字只代表当前样本集上的表现，不代表泛化能力。

## 已知限制

- 继承链只覆盖 Java；守卫的间接继承（父类才实现 `HandlerInterceptor`）尚未识别。
- 公开/私有资源的语义依赖 `config/ownership.yaml` 声明，未声明时按 `UNKNOWN` 保守处理。
- PHP 仅支持框架路由，原生 `$_GET` 入口无法提取端点；WebGoat 这类「构造函数模拟 DB」的写法不在 sink 定义内。
- LLM 输出存在非确定性，同一代码多次运行可能出现个别条目在 LIKELY 与 UNCERTAIN 之间漂移。

## 测试

```bash
python -m pytest tests -q          # 279 条
python tests/benchmark/run_benchmark.py
```
