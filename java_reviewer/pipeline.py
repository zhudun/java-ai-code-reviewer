from __future__ import annotations

from pathlib import Path

from java_reviewer.analyze.discover import discover_files
from java_reviewer.analyze.gitdiff import changed_files
from java_reviewer.config import ReviewConfig
from java_reviewer.llm.reviewer import ContextualReviewer
from java_reviewer.models import Finding, ReviewReport
from java_reviewer.rules.engine import RuleEngine
from java_reviewer.scoring import build_report


class ReviewPipeline:
    def __init__(self, config: ReviewConfig | None = None) -> None:
        self.config = config or ReviewConfig()
        self.engine = RuleEngine()
        self.contextual = ContextualReviewer(self.config)

    def scan(self, root: Path, files: list[Path] | None = None) -> ReviewReport:
        root = root.resolve()
        targets = files if files is not None else discover_files(root, self.config)
        return self._run(
            targets,
            scan_mode="rules+llm" if self.contextual.llm_used else "rules+heuristic",
            root=root,
        )

    def review_diff(self, root: Path, base: str | None, head: str | None = None) -> ReviewReport:
        targets = changed_files(root, base, head)
        if not targets:
            targets = discover_files(root, self.config)
        mode = "diff+llm" if self.contextual.llm_used else "diff+heuristic"
        return self._run(targets, scan_mode=mode, root=root.resolve())

    def _run(self, targets: list[Path], scan_mode: str, root: Path | None = None) -> ReviewReport:
        findings: list[Finding] = []
        rule_hits: list[Finding] = []
        for path in targets:
            hits = self.engine.analyze_file(path, self.config)
            rule_hits.extend(hits)
            findings.extend(hits)

        if self.config.llm.enabled:
            selected = _select_for_llm(targets, rule_hits, self.config.llm.max_files)
            for path in selected:
                related = [item for item in rule_hits if Path(item.file).resolve() == path.resolve()]
                findings.extend(self.contextual.review_file(path, related))

        findings = _relocate(_dedupe(findings), root)
        return build_report(
            findings,
            scanned_files=len(targets),
            llm_used=self.contextual.llm_used,
            scan_mode=scan_mode,
        )


def _relocate(findings: list[Finding], root: Path | None) -> list[Finding]:
    if root is None:
        return findings
    root = root.resolve()
    for item in findings:
        try:
            item.file = str(Path(item.file).resolve().relative_to(root))
        except ValueError:
            item.file = str(Path(item.file))
    return findings


def _select_for_llm(targets: list[Path], hits: list[Finding], limit: int) -> list[Path]:
    scored: dict[Path, int] = {path: 0 for path in targets}
    for item in hits:
        path = Path(item.file)
        if path in scored:
            scored[path] += item.severity.rank
    ranked = sorted(scored.items(), key=lambda pair: (-pair[1], str(pair[0])))
    if not ranked:
        return targets[:limit]
    # always include files with hits, then fill with remaining java files
    chosen = [path for path, score in ranked if score > 0][:limit]
    if len(chosen) < limit:
        for path, _ in ranked:
            if path not in chosen and path.suffix == ".java":
                chosen.append(path)
            if len(chosen) >= limit:
                break
    return chosen


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for item in findings:
        key = item.fingerprint()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
