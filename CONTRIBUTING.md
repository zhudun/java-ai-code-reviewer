# 参与贡献

## 开发

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

新增确定性规则：

1. 在 `java_reviewer/rules/` 实现 `Rule` 子类。
2. 在 `default_rules()` 注册。
3. 在 `tests/test_rules.py` 加正例和反例。
4. 在 `docs/RULES.md` 写清会报 / 不报。

规则优先追求**高精确率**。上下文不够时不要报。

## 提交前

- `pytest` 必须通过
- 用 `examples/vulnerable-shop` 跑一遍 `jacr scan`，确认五类规则都还能打中
