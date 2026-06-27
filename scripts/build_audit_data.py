#!/usr/bin/env python3
"""Generate the static audit-results JSON used by BenchjackAuditPage."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import timezone, datetime
from pathlib import Path
from typing import Iterable


VULN_ORDER = [f"V{i}" for i in range(1, 9)]
DEFAULT_REPO_URL = "https://github.com/volkthienpreecha/benchjack"


@dataclass(frozen=True)
class SourceInfo:
    root: Path
    repo_url: str
    commit: str | None
    branch: str


def _run_git(root: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value or None


def _normalize_repo_url(value: str | None) -> str:
    if not value:
        return DEFAULT_REPO_URL
    value = value.strip()
    if value.endswith(".git"):
        value = value[:-4]
    if value.startswith("git@github.com:"):
        return "https://github.com/" + value.removeprefix("git@github.com:")
    return value


def source_info(source_root: Path) -> SourceInfo:
    return SourceInfo(
        root=source_root,
        repo_url=_normalize_repo_url(_run_git(source_root, ["config", "--get", "remote.origin.url"])),
        commit=_run_git(source_root, ["rev-parse", "HEAD"]),
        branch=_run_git(source_root, ["branch", "--show-current"]) or "main",
    )


def strip_markdown(value: str) -> str:
    value = value.strip()
    value = re.sub(r"<(https?://[^>]+)>", r"\1", value)
    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", value)
    value = value.replace("`", "")
    value = value.replace("**", "")
    value = value.replace("~", "")
    value = normalize_public_text(value)
    return value.strip()


def normalize_public_text(value: str) -> str:
    """Normalize source prose into the page's ASCII terminal style."""
    replacements = {
        "\u2014": " - ",
        "\u2013": "-",
        "\u2192": "->",
        "\u00d7": "x",
        "\u2248": "~=",
        "\u00a0": " ",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    return re.sub(r"\s{2,}", " ", value)


def first_markdown_url(value: str) -> str | None:
    for pattern in (r"<(https?://[^>]+)>", r"\[[^\]]+\]\((https?://[^)]+)\)", r"(https?://\S+)"):
        match = re.search(pattern, value)
        if match:
            return match.group(1).rstrip(").,")
    return None


def section(markdown: str, heading: str) -> str:
    pattern = rf"^##\s+{re.escape(heading)}\s*$"
    match = re.search(pattern, markdown, flags=re.MULTILINE)
    if not match:
        return ""
    start = match.end()
    next_heading = re.search(r"^##\s+", markdown[start:], flags=re.MULTILINE)
    end = start + next_heading.start() if next_heading else len(markdown)
    return markdown[start:end].strip()


def metadata(markdown: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in markdown.splitlines():
        match = re.match(r"^-\s+\*\*([^:]+):\*\*\s*(.+)$", line)
        if match:
            out[match.group(1).strip().lower()] = match.group(2).strip()
    return out


def parse_table(markdown: str) -> list[dict[str, str]]:
    rows = []
    lines = [line.strip() for line in markdown.splitlines() if line.strip().startswith("|")]
    if len(lines) < 2:
        return rows
    headers = [strip_markdown(col).lower() for col in lines[0].strip("|").split("|")]
    for line in lines[2:]:
        values = [col.strip() for col in line.strip("|").split("|")]
        if len(values) != len(headers):
            continue
        rows.append({headers[i]: values[i].strip() for i in range(len(headers))})
    return rows


def normalize_severity(value: str) -> str:
    text = strip_markdown(value).lower()
    if text in {"critical", "high", "medium", "low"}:
        return text
    return "na"


def parse_findings(markdown: str) -> dict[str, dict[str, str]]:
    findings = {vuln: {"id": vuln, "name": "", "prevalence": "", "severity": "na"} for vuln in VULN_ORDER}
    for row in parse_table(section(markdown, "Findings")):
        vuln = strip_markdown(row.get("class", "")).upper()
        if vuln not in findings:
            continue
        findings[vuln] = {
            "id": vuln,
            "name": strip_markdown(row.get("name", "")),
            "prevalence": strip_markdown(row.get("prevalence", row.get("notes", ""))),
            "severity": normalize_severity(row.get("severity", "")),
        }
    return findings


def parse_task_count(markdown: str, findings: dict[str, dict[str, str]]) -> int | None:
    for item in findings.values():
        match = re.search(r"\ball\s+(\d+)\s+tasks\b", item.get("prevalence", ""), flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    summary = section(markdown, "Summary")
    match = re.search(r"\b(?:is|covers|covering)\s+(\d+)\b[^.\n]{0,80}\btasks\b", summary, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    match = re.search(r"\b(\d+)\b[^.\n]{0,80}\btasks\b", markdown, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def parse_reproduction(markdown: str) -> str:
    text = section(markdown, "Reproduction")
    match = re.search(r"```(?:bash|sh|shell)?\s*(.*?)```", text, flags=re.DOTALL)
    if match:
        lines = [line.strip() for line in match.group(1).strip().splitlines()]
        lines = [line for line in lines if line and not line.startswith("#")]
        return "\n".join(lines)
    return ""


def parse_disclosure(markdown: str) -> list[str]:
    text = section(markdown, "Disclosure")
    return [strip_markdown(line.removeprefix("-").strip()) for line in text.splitlines() if line.strip().startswith("-")]


def referenced_relative_paths(markdown: str) -> set[str]:
    refs: set[str] = set()
    for url in re.findall(r"\[[^\]]+\]\(([^)]+)\)", markdown):
        if re.match(r"^[a-z]+://", url) or url.startswith("#"):
            continue
        refs.add(url.strip())
    return refs


def artifact_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".md":
        return "markdown"
    if suffix in {".json", ".jsonl"}:
        return "data"
    if suffix in {".py", ".sh", ".js", ".ts"}:
        return "code"
    return "artifact"


def artifact_label(path: Path) -> str:
    if path.name == "README.md":
        return "audit summary"
    if path.name == "recon.md":
        return "recon report"
    if path.name == "vuln_scan.md":
        return "vulnerability scan"
    if path.name == "poc.md":
        return "PoC notes"
    return path.as_posix()


def collect_artifacts(audit_dir: Path, source: SourceInfo) -> tuple[list[dict], list[str]]:
    artifacts = []
    for path in sorted(p for p in audit_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(audit_dir).as_posix()
        repo_rel = f"audits/{audit_dir.name}/{rel}"
        artifacts.append({
            "path": rel,
            "label": artifact_label(Path(rel)),
            "kind": artifact_kind(path),
            "size_bytes": path.stat().st_size,
            "url": f"{source.repo_url}/blob/{source.branch}/{repo_rel}",
        })

    readme = audit_dir / "README.md"
    refs = referenced_relative_paths(readme.read_text(encoding="utf-8")) if readme.exists() else set()
    missing = sorted(ref for ref in refs if not (audit_dir / ref).exists())
    return artifacts, missing


def parse_audit(audit_dir: Path, source: SourceInfo) -> dict | None:
    readme = audit_dir / "README.md"
    if not readme.exists():
        return None
    markdown = readme.read_text(encoding="utf-8")
    meta = metadata(markdown)
    findings = parse_findings(markdown)
    artifacts, missing = collect_artifacts(audit_dir, source)
    upstream_commit = meta.get("upstream commit", "")

    return {
        "id": re.sub(r"[^a-z0-9]+", "-", audit_dir.name.lower()).strip("-"),
        "name": audit_dir.name,
        "upstream_repo": first_markdown_url(meta.get("upstream repo", "")),
        "upstream_commit": strip_markdown(upstream_commit),
        "upstream_commit_url": first_markdown_url(upstream_commit),
        "audited_on": strip_markdown(meta.get("audited on", "")),
        "backend": strip_markdown(meta.get("backend", "")),
        "mode": strip_markdown(meta.get("mode", "")),
        "auditor": strip_markdown(meta.get("auditor", "")),
        "summary": strip_markdown(section(markdown, "Summary")),
        "task_count": parse_task_count(markdown, findings),
        "exploit_score": None,
        "exploit_score_label": "not aggregated",
        "findings": findings,
        "reproduction": parse_reproduction(markdown),
        "disclosure": parse_disclosure(markdown),
        "artifacts": artifacts,
        "missing_artifact_references": missing,
        "source_path": f"audits/{audit_dir.name}/README.md",
        "source_url": f"{source.repo_url}/blob/{source.branch}/audits/{audit_dir.name}/README.md",
    }


def severity_counts(records: Iterable[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "na": 0}
    for record in records:
        for finding in record["findings"].values():
            counts[finding["severity"]] += 1
    return counts


def build_snapshot(source_root: Path) -> dict:
    source = source_info(source_root)
    audits_root = source.root / "audits"
    records = []
    if audits_root.exists():
        for audit_dir in sorted(path for path in audits_root.iterdir() if path.is_dir()):
            record = parse_audit(audit_dir, source)
            if record:
                records.append(record)

    task_total = sum(record["task_count"] or 0 for record in records)
    return {
        "generated_at": datetime.now(timezone.utc).date().isoformat(),
        "source": {
            "repo_url": source.repo_url,
            "commit": source.commit,
            "branch": source.branch,
            "path": str(audits_root),
        },
        "summary": {
            "record_count": len(records),
            "task_count": task_total,
            "exploit_score_range": None,
            "severity_counts": severity_counts(records),
        },
        "records": records,
    }


def main_with_args(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Path to the BenchJack repo")
    parser.add_argument("--out", type=Path, default=Path("data/audits.json"), help="Output JSON path")
    args = parser.parse_args(argv)

    snapshot = build_snapshot(args.source.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    return main_with_args()


if __name__ == "__main__":
    raise SystemExit(main())
