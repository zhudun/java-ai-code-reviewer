# 架构

`java-ai-code-reviewer` 把「复述门」里的审查方法论做成可执行管道：
**能用代码判定的问题，绝不交给模型；需要理解上下文的问题，再交给第二阶段。**

设计参考：

- [alibaba/open-code-review](https://github.com/alibaba/open-code-review)：确定性工程 × LLM Agent
- [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector)：静态扫描 + 可选 LLM，多种报告格式
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)：PR 自动触发、评论、产物上传

## 管道

```
输入（目录 / 文件 / git diff）
        │
        ▼
  文件发现与过滤（include/exclude、扩展名）
        │
        ▼
  Java / MyBatis 轻量解析（去注释、抽类/方法/字段/注解）
        │
        ├──────────────┐
        ▼              ▼
 阶段 1 确定性规则   阶段 2 上下文审查
 NPE / 资源泄漏      有 API Key → LLM
 线程安全 / 事务     无 Key → 本地启发式
 SQL 注入            输出必须能落到真实行号
        │              │
        └──────┬───────┘
               ▼
     去重、风险评分、分级输出
     terminal / JSON / Markdown / SARIF
               ▼
     CLI 退出码 或 GitHub PR 评论
```

## 为什么要混合

纯 LLM 审查常见三个失败模式：漏看文件、行号漂移、提示词稍变结果就不稳。
纯静态规则又看不懂「这个接口有没有鉴权」「这个异常会不会让账不平」。

因此：

1. **文件选择、行号、规则匹配**由确定性代码保证。
2. **LLM 只做上下文判断**，并且必须引用已存在的行；对不上的结果会被丢掉。
3. **没有密钥也能跑完整个管道**：第二阶段退化为本地启发式（硬编码密钥、弱随机数、空 catch、缺鉴权、路径穿越、SSRF）。

## 模块

| 模块 | 职责 |
| --- | --- |
| `analyze/` | 源码清洗、类/方法/字段抽取、git diff、文件发现 |
| `rules/` | 五类 Java 专项规则，可单独开关 |
| `llm/` | OpenAI / Anthropic 兼容客户端 + 启发式回退 + 行号锚定 |
| `reporters/` | 终端、JSON、Markdown、SARIF |
| `pipeline.py` | 编排两阶段、去重、打分 |
| `cli.py` | `jacr scan` / `jacr review` / `jacr github-comment` |
| `action.yml` | PR 自动审查 |

## 风险分

| 等级 | 权重 |
| --- | ---: |
| CRITICAL | 25 |
| HIGH | 12 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 0 |

风险分截断在 100。`--fail-on HIGH` 表示存在 HIGH 或 CRITICAL 时以退出码 1 失败。
