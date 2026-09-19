# java-ai-code-reviewer

面向 Java 的 **AI 代码质量与风险审查工具**。
把「复述门」式的审查方法论做成可执行管道：**确定性规则引擎 + LLM / 启发式上下文审查**，并提供 GitHub Action，在 PR 上按风险等级给出位置和修复建议。

不需要 JDK。Python 3.10+ 即可运行。没有模型密钥时，两阶段管道仍然完整可跑。

## 为什么是混合架构

参考了三套成熟思路：

| 项目 | 借鉴 |
| --- | --- |
| [alibaba/open-code-review](https://github.com/alibaba/open-code-review) | 文件选择、行号、规则匹配必须由确定性代码保证，模型只做动态判断 |
| [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) | 静态优先、LLM 可选；JSON / Markdown / SARIF；风险分 |
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | PR 自动触发、评论、产物上传 |

纯模型审查会漏文件、飘行号；纯规则又看不懂鉴权、账本和异常路径。
所以本工具把 NPE、资源泄漏、线程安全、事务边界、SQL 注入做成可回归的规则，把「需要读懂上下文」的问题留给第二阶段。

## 功能

- **Java 专项规则**：空指针、流/连接未关闭、线程安全、事务边界、SQL 注入（含 MyBatis `${}`）
- **第二阶段**：配置了 OpenAI / Anthropic 兼容接口就走 LLM；否则自动用本地启发式（硬编码密钥、弱随机数、缺鉴权、路径穿越、空 catch、SSRF）
- **输出**：终端分级、JSON、Markdown、SARIF
- **GitHub Action**：PR 评论 + artifact + `--fail-on` 门禁
- **零密钥可演示**：`examples/vulnerable-shop` 是故意写坏的样例

## 快速开始

```bash
git clone https://github.com/zhudun/java-ai-code-reviewer.git
cd java-ai-code-reviewer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

# 扫描故意写坏的示例（无需 API Key）
jacr scan examples/vulnerable-shop --fail-on NONE
```

审查当前仓库的 git 变更：

```bash
jacr review . --base origin/main --format markdown --output review-report.md
```

启用真实 LLM（OpenAI 兼容）：

```bash
export OPENAI_API_KEY=sk-...
# 可选：自建网关
# export OPENAI_BASE_URL=https://your-gateway/v1
jacr scan path/to/java-project
```

Anthropic：

```bash
export ANTHROPIC_API_KEY=sk-ant-...
jacr scan path/to/java-project --config configs/default.yaml
```

把 `configs/default.yaml` 里的 `llm.provider` 改成 `anthropic`，`llm.model` 改成你的模型名。

## CLI

```text
jacr scan   [PATH]   扫描目录或文件
jacr review [REPO]   审查 git diff，没有 diff 则全量扫描
jacr github-comment REPORT.json   在 PR 下评论（Action 使用）
jacr version
```

常用参数：

| 参数 | 含义 |
| --- | --- |
| `--format terminal\|json\|markdown\|sarif` | 输出格式 |
| `--output FILE` | 写入文件 |
| `--fail-on HIGH` | 达到该等级返回退出码 1 |
| `--no-llm` | 只要确定性规则 |
| `--config configs/default.yaml` | 开关规则、排除目录 |
| `--base` / `--head` | `review` 的 git 范围 |

退出码：有达到 `--fail-on` 的发现时为 `1`，否则 `0`。

## GitHub Action

```yaml
name: Java AI Review
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: zhudun/java-ai-code-reviewer@v0.1.0
        with:
          fail-on: HIGH
          comment-pr: "true"
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

完整模板见 `examples/github-action/security.yml`。
没有 `OPENAI_API_KEY` 时 Action 仍会跑规则 + 启发式，并评论 PR。

## 报告长什么样

```text
▸ CRITICAL
  java.sql-injection  PaymentDao.java:15  SQL 注入风险
    SQL 字符串与变量拼接，攻击者可注入任意子句。
    修复: 改为参数绑定：WHERE name = ? + PreparedStatement.setString。

▸ HIGH
  java.npe  UserService.java:17  空指针 / NPE 风险
    直接调用 optional.get()，未确认 Optional 有值。
    修复: 先 isPresent()/ifPresent()，或改用 orElseThrow()。
```

每条发现都带：**规则 ID、风险等级、文件、行号、代码片段、修复建议、CWE**。

## 项目结构

```text
java_reviewer/          核心包
  analyze/              Java / XML / git 解析
  rules/                确定性规则
  llm/                  LLM 客户端与启发式回退
  reporters/            终端 / JSON / Markdown / SARIF
examples/vulnerable-shop/
action.yml              可复用 GitHub Action
configs/default.yaml
docs/ARCHITECTURE.md
docs/RULES.md
```

## 开发

```bash
python -m pip install -e ".[dev]"
pytest
```

规则语义与误报边界见 [docs/RULES.md](docs/RULES.md)，管道设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 许可

Apache-2.0
