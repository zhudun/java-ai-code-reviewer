from pathlib import Path

from typer.testing import CliRunner

from java_reviewer.cli import app

runner = CliRunner()


def test_cli_scan_example(example_root: Path):
    result = runner.invoke(
        app,
        ["scan", str(example_root), "--no-llm", "--fail-on", "NONE", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert "java.npe" in result.output
    assert "java.sql-injection" in result.output


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_render_and_gate(example_root: Path, tmp_path: Path):
    report = tmp_path / "report.json"
    scanned = runner.invoke(
        app,
        ["scan", str(example_root), "--no-llm", "--fail-on", "NONE", "--format", "json", "-o", str(report)],
    )
    assert scanned.exit_code == 0, scanned.output
    rendered = runner.invoke(app, ["render", str(report), "--format", "markdown"])
    assert rendered.exit_code == 0
    assert "Java AI" in rendered.output
    blocked = runner.invoke(app, ["gate", str(report), "--fail-on", "HIGH"])
    assert blocked.exit_code == 1
    opened = runner.invoke(app, ["gate", str(report), "--fail-on", "NONE"])
    assert opened.exit_code == 0
