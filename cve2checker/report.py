"""Run manifest and human-readable report generation."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_run_report(
    output_dir: str | os.PathLike[str],
    *,
    cve_id: str,
    status: str,
    stages: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    metadata: Mapping[str, Any] | None = None,
    summary: Mapping[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Write ``manifest.json`` and ``report.md`` for a run."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    artifact_manifest: dict[str, Any] = {}
    for name, value in artifacts.items():
        path = Path(value)
        entry: dict[str, Any] = {
            "path": str(path),
            "exists": path.is_file(),
        }
        if path.is_file():
            entry["sha256"] = sha256_file(path)
            entry["bytes"] = path.stat().st_size
        artifact_manifest[name] = entry

    manifest = {
        "cve_id": cve_id,
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": dict(metadata or {}),
        "summary": dict(summary or {}),
        "stages": dict(stages),
        "artifacts": artifact_manifest,
    }
    manifest_path = output / "manifest.json"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    report_path = output / "report.md"
    report_path.write_text(
        _render_report(manifest), encoding="utf-8", newline="\n"
    )
    return manifest_path, report_path


def _render_report(manifest: Mapping[str, Any]) -> str:
    metadata = manifest.get("metadata", {})
    summary = manifest.get("summary", {})
    lines = [
        f"# CVE2Query report: {manifest.get('cve_id', '')}",
        "",
        f"- Status: `{manifest.get('status', '')}`",
        f"- Generated: {manifest.get('generated_at', '')}",
    ]
    for key in ("repo", "vulnerable_commit", "fix_commit", "model", "codeql_version"):
        if metadata.get(key):
            lines.append(f"- {key}: `{metadata[key]}`")
    lines.extend(["", "## Stages", ""])
    for name, stage in manifest.get("stages", {}).items():
        if isinstance(stage, Mapping):
            lines.append(f"- `{name}`: {stage.get('status', 'unknown')}")
        else:
            lines.append(f"- `{name}`: {stage}")
    if summary:
        lines.extend(["", "## Summary", ""])
        for key, value in summary.items():
            lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Artifacts", ""])
    for name, artifact in manifest.get("artifacts", {}).items():
        if not isinstance(artifact, Mapping):
            continue
        if artifact.get("exists"):
            lines.append(f"- {name}: `{artifact['path']}`")
        else:
            lines.append(f"- {name}: missing (`{artifact.get('path', '')}`)")
    lines.append("")
    return "\n".join(lines)
