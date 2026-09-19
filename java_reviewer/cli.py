from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from java_reviewer import __version__
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Severity
from java_reviewer.pipeline import ReviewPipeline
from java_reviewer.reporters import render_json, render_markdown, render_sarif, render_terminal

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Java AI 代码质量与风险审查工具（确定性规则 + LLM/启发式）。",
)
console = Console()


@app.callback()
def _root() -> None:
    """java-ai-code-reviewer"""


@app.command()
def version() -> None:
    """打印版本号。"""
    typer.echo(__version__)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="要扫描的目录或文件"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML 配置文件"),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|markdown|sarif"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="把报告写入文件"),
    no_llm: bool = typer.Option(False, "--no-llm", help="关闭第二阶段上下文审查"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="达到该等级时以退出码 1 失败"),
    lang: Optional[str] = typer.Option(None, "--lang", help="zh 或 en"),
) -> None:
    """扫描目录或单个文件（不依赖 git）。"""
    review_config = _load_config(config, no_llm, fail_on, lang)
    pipeline = ReviewPipeline(review_config)
    root, files = _resolve_targets(path)
    report = pipeline.scan(root, files)
    _emit(report, fmt, output)
    raise typer.Exit(_exit_code(report, review_config.fail_on))


@app.command()
def review(
    path: Path = typer.Argument(Path("."), help="仓库根目录"),
    base: Optional[str] = typer.Option(None, "--base", help="git 基准引用，如 origin/main"),
    head: Optional[str] = typer.Option(None, "--head", help="git 目标引用，默认 HEAD"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    fmt: str = typer.Option("terminal", "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    no_llm: bool = typer.Option(False, "--no-llm"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on"),
    lang: Optional[str] = typer.Option(None, "--lang"),
) -> None:
    """审查 git 变更；找不到 diff 时回退为全量扫描。"""
    review_config = _load_config(config, no_llm, fail_on, lang)
    pipeline = ReviewPipeline(review_config)
    report = pipeline.review_diff(path, base, head)
    _emit(report, fmt, output)
    raise typer.Exit(_exit_code(report, review_config.fail_on))


@app.command()
def render(
    report_file: Path = typer.Argument(..., help="JSON 报告路径"),
    fmt: str = typer.Option("markdown", "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """把 JSON 报告渲染成其他格式。"""
    from java_reviewer.models import ReviewReport

    report = ReviewReport.model_validate_json(report_file.read_text(encoding="utf-8"))
    _emit(report, fmt, output)


@app.command()
def gate(
    report_file: Path = typer.Argument(..., help="JSON 报告路径"),
    fail_on: str = typer.Option("HIGH", "--fail-on"),
) -> None:
    """根据已有 JSON 报告执行严重级别门禁。"""
    from java_reviewer.models import ReviewReport

    report = ReviewReport.model_validate_json(report_file.read_text(encoding="utf-8"))
    raise typer.Exit(_exit_code(report, fail_on))


@app.command("github-comment")
def github_comment(
    report_file: Path = typer.Argument(..., help="scan --format json 产出的报告"),
    title: str = typer.Option("Java AI Code Review", "--title"),
) -> None:
    """根据 JSON 报告向当前 PR 发表评论（GitHub Action 使用）。"""
    from java_reviewer.github_pr import post_review_comment

    data = json.loads(report_file.read_text(encoding="utf-8"))
    from java_reviewer.models import ReviewReport

    report = ReviewReport.model_validate(data)
    url = post_review_comment(report, title=title)
    if url:
        console.print(f"已评论 PR: {url}")
    else:
        console.print("未检测到 GitHub PR 环境，已跳过评论。")


def _load_config(
    path: Path | None,
    no_llm: bool,
    fail_on: str | None,
    lang: str | None,
) -> ReviewConfig:
    config = ReviewConfig.load(path) if path else ReviewConfig()
    if no_llm:
        config.llm.enabled = False
    if fail_on:
        config.fail_on = fail_on.upper()
    if lang:
        config.language = lang
    return config


def _resolve_targets(path: Path) -> tuple[Path, list[Path] | None]:
    path = path.resolve()
    if path.is_file():
        return path.parent, [path]
    return path, None


def _emit(report, fmt: str, output: Path | None) -> None:
    fmt = fmt.lower()
    if fmt == "json":
        text = render_json(report)
    elif fmt in {"md", "markdown"}:
        text = render_markdown(report)
    elif fmt == "sarif":
        text = render_sarif(report)
    else:
        render_terminal(report, console)
        text = render_markdown(report)
        if output is None:
            return
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"报告已写入 {output}")
    elif fmt != "terminal":
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _exit_code(report, fail_on: str) -> int:
    if fail_on in {"", "NONE", "OFF"}:
        return 0
    try:
        threshold = Severity(fail_on.upper())
    except ValueError:
        threshold = Severity.HIGH
    return 1 if any(item.severity.rank >= threshold.rank for item in report.findings) else 0


def main() -> None:
    # Allow `python -m java_reviewer` style
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    app()


if __name__ == "__main__":
    main()
