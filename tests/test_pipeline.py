from pathlib import Path

from java_reviewer.config import ReviewConfig
from java_reviewer.models import Severity
from java_reviewer.pipeline import ReviewPipeline
from java_reviewer.reporters.markdown import render_markdown
from java_reviewer.reporters.sarif import render_sarif


def test_example_shop_has_all_families(example_root: Path):
    config = ReviewConfig()
    config.llm.enabled = True
    report = ReviewPipeline(config).scan(example_root)
    families = {item.rule_id.split(".")[0] + "." + item.rule_id.split(".")[1] for item in report.findings}
    # rule ids are java.npe / java.resource-leak / llm.*
    rule_ids = {item.rule_id for item in report.findings}
    assert any(rid.startswith("java.npe") for rid in rule_ids)
    assert any(rid.startswith("java.resource-leak") for rid in rule_ids)
    assert any(rid.startswith("java.thread-safety") for rid in rule_ids)
    assert any(rid.startswith("java.transaction") for rid in rule_ids)
    assert any(rid.startswith("java.sql-injection") for rid in rule_ids)
    assert any(item.source.value in {"heuristic", "llm"} for item in report.findings)
    assert report.risk_score > 0
    assert report.highest_severity() in {Severity.CRITICAL, Severity.HIGH}
    markdown = render_markdown(report)
    assert "SQL" in markdown or "注入" in markdown
    sarif = render_sarif(report)
    assert "java-ai-code-reviewer" in sarif
    _ = families


def test_clean_file_has_no_rule_hits(tmp_path: Path):
    src = tmp_path / "Clean.java"
    src.write_text(
        """
        import java.io.BufferedReader;
        import java.io.FileReader;
        class Clean {
          String read(String path) throws Exception {
            try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
              return reader.readLine();
            }
          }
        }
        """,
        encoding="utf-8",
    )
    config = ReviewConfig()
    config.llm.enabled = False
    report = ReviewPipeline(config).scan(tmp_path, [src])
    assert report.findings == []
