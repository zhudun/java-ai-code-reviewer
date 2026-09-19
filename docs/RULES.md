# 规则说明

规则 ID 使用 `java.<family>` 或 `llm.<topic>`。
可用 `configs/default.yaml` 按 family 关闭。

## 阶段 1：确定性规则

### `java.npe` — 空指针 / NPE

会报：

- `Optional.get()` 且未见 `isPresent` / `ifPresent`
- `orElse(null)` 把空值重新引入调用链
- `findById(...).xxx()` / `map.get(...).xxx()` 链式解引用
- 变量在左侧的 `.equals`（左侧可能为 null）
- 包装类型自动拆箱
- 赋值为 `null` 后继续解引用

不报：已有 `!= null` / `Objects.requireNonNull` / `Objects.equals` 保护的用法。

建议：`"admin".equals(name)`、`orElseThrow()`、`Optional` 链式处理。

### `java.resource-leak` — 资源未关闭

覆盖常见 `AutoCloseable`：文件流、Socket、Scanner、JDBC Connection / Statement / ResultSet。

会报：`new FileInputStream` 等未进入 try-with-resources，且方法内没有 `close()`。
`DriverManager.getConnection` 未关闭视为 CRITICAL。

不报：`try (Resource r = ...) { ... }` 或明确 `close()`。

### `java.thread-safety` — 线程安全

会报：

- 字段级 `SimpleDateFormat` / 静态 `Calendar`
- Spring 单例（`@Service` / `@Controller` / `@Component` 等）里的 `HashMap` / `ArrayList`
- 非 `volatile` 的双重检查锁定
- 共享 Map 的无锁 check-then-act、共享计数器 `++`

不报：方法局部变量、`ConcurrentHashMap`、`List.of` 等不可变初始化、已 `synchronized` 的方法。

### `java.transaction` — 事务边界

会报：

- `@Transactional` 标在 private / package 方法上（Spring 代理不生效）
- 同类 `this.txMethod()` 自调用
- 事务方法里 catch Exception 且不抛出
- `readOnly = true` 却有 save/update/delete
- Controller 上开事务
- `@Service` 写库方法完全没有事务

### `java.sql-injection` — SQL 注入

会报：

- `"SELECT ... '" + user + "'"` / `String.format` 拼 SQL
- `createNativeQuery` / `jdbcTemplate` 传入拼接串
- `Statement` + 动态 SQL
- MyBatis XML 中的 `${}`

不报：`#{}`、`PreparedStatement` 占位符。

## 阶段 2：上下文审查

有 `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` 时走模型；否则走本地启发式。

启发式主题：

| ID | 含义 |
| --- | --- |
| `llm.hardcoded-secret` | 硬编码口令 / 密钥 |
| `llm.weak-random` | 安全场景使用 `new Random()` |
| `llm.insecure-deserialize` | Fastjson / XMLDecoder |
| `llm.path-traversal` | 请求参数进 `new File` |
| `llm.empty-catch` | 空 catch |
| `llm.missing-authz` | Controller 映射缺少授权注解 |
| `llm.ssrf` | 外部 URL 直接请求 |

LLM 输出必须带行号；行号超出文件范围的条目会被丢弃。
