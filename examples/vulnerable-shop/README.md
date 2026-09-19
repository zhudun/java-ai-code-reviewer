# vulnerable-shop

一组**故意写坏**的 Java 片段，用来演示 `jacr scan` 的五类确定性规则和第二阶段启发式。

不要把这里的代码当业务模板。

```bash
jacr scan examples/vulnerable-shop --fail-on NONE
```

| 文件 | 预期命中 |
| --- | --- |
| `UserService.java` | NPE、HashMap 线程安全、private `@Transactional`、吞异常、自调用 |
| `OrderController.java` | Controller 事务、硬编码密钥、弱随机数、路径穿越、缺鉴权 |
| `PaymentDao.java` | JDBC 未关闭、SQL 拼接 |
| `ReportExporter.java` | 流未关闭（`safeRead` 是对照，不应报） |
| `CacheHolder.java` | 非 volatile 双重检查锁定、SimpleDateFormat |
| `UserMapper.xml` | MyBatis `${}` |
