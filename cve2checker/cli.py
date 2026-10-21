"""Command-line interface for the CVE-to-CodeQL MVP foundation."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .codeql import (
    CodeQLError,
    analyze_query,
    compile_query,
    create_cpp_database,
    ensure_query_pack,
    install_pack,
    verify_pack,
)
from .cve import (
    CVEError,
    build_vulnerability_spec,
    fetch_record,
    parse_record,
    validate_cve_id,
)
from .agents import AgentError, run_feasibility, run_root_cause, write_json_artifact
from .diff import changed_ranges, parse_unified_diff
from .env import load_dotenv, project_env_paths, set_env_value
from .evidence import EvidenceError, build_evidence
from .git_tools import GitError, add_worktree
from .llm import LLMError, build_llm_client, llm_from_env
from .lsp import CodeQLLanguageServer, LSPError
from .rag import RagError, RagIndex
from .rag_index import index_directory
from .report import write_run_report
from .synthesis import SynthesisError, ToolBox, run_synthesis
from .validator import ValidationError, validate_query


def _default_codeql_path() -> str:
    configured = os.environ.get("CODEQL_PATH")
    if configured:
        return configured
    project_root = Path(__file__).resolve().parent.parent
    for candidate in (
        project_root / ".tools" / "codeql" / "codeql.cmd",
        project_root / ".tools" / "codeql" / "codeql.exe",
        project_root / ".tools" / "codeql" / "codeql",
    ):
        if candidate.is_file():
            return str(candidate)
    return "codeql"


def _pinned_codeql_version() -> str:
    project_root = Path(__file__).resolve().parent.parent
    path = project_root / ".codeql-version"
    try:
        version = path.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    return version or "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve2checker",
        description="Prepare evidence-gated CVE specs and run CodeQL analysis.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser(
        "add",
        help="fetch a CVE record and create an initial vulnerability IR",
        description=(
            "Fetch a CVE v5 record and create an evidence-gated vulnerability spec. "
            "This does not generate a CVE-specific query."
        ),
    )
    add_parser.add_argument("cve_id", metavar="CVE-ID", help="identifier such as CVE-2021-3156")
    add_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        metavar="DIR",
        help="root directory for per-CVE artifacts (default: ./artifacts)",
    )
    add_parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache/cve2checker"),
        metavar="DIR",
        help="directory for raw CVE JSON cache (default: ./.cache/cve2checker)",
    )
    add_parser.add_argument(
        "--refresh",
        action="store_true",
        help="fetch from the API even when a cached record exists",
    )
    add_parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing vulnerability spec",
    )

    database_parser = subparsers.add_parser(
        "database", help="create a CodeQL source database"
    )
    database_subparsers = database_parser.add_subparsers(
        dest="database_command", required=True
    )
    create_parser = database_subparsers.add_parser(
        "create", help="create a C/C++ CodeQL database"
    )
    create_parser.add_argument("--source-root", type=Path, required=True)
    create_parser.add_argument("--database", type=Path, required=True)
    create_parser.add_argument(
        "--build-command",
        help="custom traced build command; omit to use CodeQL autobuild",
    )
    create_parser.add_argument(
        "--build-mode",
        choices=("autobuild", "none"),
        help="CodeQL build mode; omit for autobuild",
    )
    create_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")

    query_parser = subparsers.add_parser("query", help="compile and analyze CodeQL queries")
    query_subparsers = query_parser.add_subparsers(dest="query_command", required=True)
    compile_parser = query_subparsers.add_parser("compile", help="compile one .ql query")
    compile_parser.add_argument("query", type=Path)
    compile_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")

    analyze_parser = query_subparsers.add_parser(
        "analyze", help="run a query and write SARIF 2.1.0 results"
    )
    analyze_parser.add_argument("--query", type=Path, required=True)
    analyze_parser.add_argument("--database", type=Path, required=True)
    analyze_parser.add_argument("--output", type=Path, required=True, metavar="SARIF")
    analyze_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")

    pack_parser = subparsers.add_parser("pack", help="manage the local CodeQL query pack")
    pack_subparsers = pack_parser.add_subparsers(dest="pack_command", required=True)
    for command, help_text in (
        ("install", "resolve pack dependencies and write/update the lock file"),
        ("ci", "verify pack dependencies against the lock file"),
    ):
        command_parser = pack_subparsers.add_parser(command, help=help_text)
        command_parser.add_argument(
            "--pack-root", type=Path, default=Path("codeql-pack"), metavar="DIR"
        )
        command_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")

    config_parser = subparsers.add_parser(
        "config", help="inspect or update local LLM configuration"
    )
    config_subparsers = config_parser.add_subparsers(
        dest="config_command", required=True
    )
    config_subparsers.add_parser(
        "set-key", help="securely store the OpenCode Go API key in .env"
    )
    config_subparsers.add_parser(
        "show", help="show the configured endpoint/model and whether a key is present"
    )

    rag_parser = subparsers.add_parser("rag", help="index and query the local RAG store")
    rag_subparsers = rag_parser.add_subparsers(dest="rag_command", required=True)
    rag_index_parser = rag_subparsers.add_parser(
        "index", help="index CodeQL docs, libraries, or examples"
    )
    rag_index_parser.add_argument("--db", type=Path, required=True)
    rag_index_parser.add_argument("--collection", required=True)
    rag_index_parser.add_argument(
        "--source", type=Path, action="append", required=True, metavar="DIR"
    )
    rag_index_parser.add_argument(
        "--extensions",
        nargs="+",
        default=None,
        help="file extensions to include (default: .ql .qll .md .txt .yml .yaml)",
    )
    rag_index_parser.add_argument("--chunk-lines", type=int, default=200)
    rag_index_parser.add_argument("--max-file-bytes", type=int, default=500_000)

    rag_search_parser = rag_subparsers.add_parser(
        "search", help="search an indexed collection"
    )
    rag_search_parser.add_argument("query")
    rag_search_parser.add_argument("--db", type=Path, required=True)
    rag_search_parser.add_argument("--collection", required=True)
    rag_search_parser.add_argument("--limit", type=int, default=5)

    evidence_parser = subparsers.add_parser(
        "evidence", help="discover the repository, fix commit, diff, and source context"
    )
    evidence_parser.add_argument("--cve-id", required=True)
    evidence_parser.add_argument("--cve-file", type=Path)
    evidence_parser.add_argument("--cache-dir", type=Path, default=Path(".cache/cve2checker"))
    evidence_parser.add_argument("--refresh", action="store_true")
    evidence_parser.add_argument("--repo-path", type=Path)
    evidence_parser.add_argument("--fix-commit")
    evidence_parser.add_argument(
        "--github-token", default=os.environ.get("GITHUB_TOKEN")
    )
    evidence_parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    evidence_parser.add_argument("--context-lines", type=int, default=8)

    validate_parser = subparsers.add_parser(
        "validate", help="compile and score a query against vulnerable and fixed databases"
    )
    validate_parser.add_argument("--query", type=Path, required=True)
    validate_parser.add_argument("--vuln-db", type=Path, required=True)
    validate_parser.add_argument("--fixed-db", type=Path, required=True)
    validate_parser.add_argument("--diff", type=Path, required=True)
    validate_parser.add_argument("--output-dir", type=Path, required=True)
    validate_parser.add_argument("--iteration", type=int, default=1)
    validate_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")
    validate_parser.add_argument(
        "--strict-fixed",
        action="store_true",
        help="reject any alert on the fixed database, even outside the patch",
    )
    validate_parser.add_argument("--json", action="store_true", help="print full feedback JSON")

    lsp_parser = subparsers.add_parser("lsp", help="use the CodeQL language server")
    lsp_subparsers = lsp_parser.add_subparsers(dest="lsp_command", required=True)
    lsp_diagnostics_parser = lsp_subparsers.add_parser(
        "diagnostics", help="compile a query through the language server"
    )
    lsp_diagnostics_parser.add_argument("--query", type=Path, required=True)
    lsp_diagnostics_parser.add_argument(
        "--pack-root", type=Path, default=Path("codeql-pack")
    )
    lsp_diagnostics_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")

    generate_parser = subparsers.add_parser(
        "generate", help="run the complete CVE-to-validated-query pipeline"
    )
    generate_parser.add_argument("--cve-id", required=True)
    generate_parser.add_argument("--cve-file", type=Path)
    generate_parser.add_argument("--repo-path", type=Path)
    generate_parser.add_argument("--fix-commit")
    generate_parser.add_argument("--vuln-commit")
    generate_parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    generate_parser.add_argument(
        "--cache-dir", type=Path, default=Path(".cache/cve2checker")
    )
    generate_parser.add_argument("--refresh", action="store_true")
    build_group = generate_parser.add_mutually_exclusive_group()
    build_group.add_argument(
        "--build-mode", choices=("autobuild", "none"), default="none"
    )
    build_group.add_argument("--build-command")
    generate_parser.add_argument("--context-lines", type=int, default=12)
    generate_parser.add_argument("--rag-db", type=Path)
    generate_parser.add_argument(
        "--codeql-path", default=_default_codeql_path(), metavar="PATH"
    )
    generate_parser.add_argument(
        "--codeql-version", default=_pinned_codeql_version()
    )
    generate_parser.add_argument("--max-iterations", type=int, default=10)
    generate_parser.add_argument("--max-tool-calls", type=int, default=50)
    generate_parser.add_argument("--max-attempts", type=int, default=2)
    generate_parser.add_argument("--strict-fixed", action="store_true")
    generate_parser.add_argument("--no-lsp", action="store_true")
    generate_parser.add_argument("--resume", action="store_true")
    generate_parser.add_argument("--llm-base-url")
    generate_parser.add_argument("--llm-model")
    generate_parser.add_argument("--llm-api-key")

    analyze_parser = subparsers.add_parser(
        "analyze", help="run the feasibility and root-cause agents"
    )
    analyze_parser.add_argument("--cve-file", type=Path, required=True)
    analyze_parser.add_argument("--source-json", type=Path, required=True)
    analyze_parser.add_argument("--output-dir", type=Path)
    analyze_parser.add_argument("--build-log", type=Path)
    analyze_parser.add_argument("--codeql-version", default="2.27.2")
    analyze_parser.add_argument("--max-attempts", type=int, default=2)
    analyze_parser.add_argument("--llm-base-url")
    analyze_parser.add_argument("--llm-model")
    analyze_parser.add_argument("--llm-api-key")

    synthesize_parser = subparsers.add_parser(
        "synthesize", help="run the iterative query synthesis and validation loop"
    )
    synthesize_parser.add_argument("--cve-file", type=Path, required=True)
    synthesize_parser.add_argument("--ir", type=Path, required=True)
    synthesize_parser.add_argument("--repo", type=Path, required=True)
    synthesize_parser.add_argument("--vuln-commit", required=True)
    synthesize_parser.add_argument("--fix-commit", required=True)
    synthesize_parser.add_argument("--diff", type=Path, required=True)
    synthesize_parser.add_argument("--vuln-db", type=Path, required=True)
    synthesize_parser.add_argument("--fixed-db", type=Path, required=True)
    synthesize_parser.add_argument("--output-dir", type=Path, required=True)
    synthesize_parser.add_argument("--rag-db", type=Path)
    synthesize_parser.add_argument("--pack-root", type=Path, default=Path("codeql-pack"))
    synthesize_parser.add_argument("--codeql-path", default=_default_codeql_path(), metavar="PATH")
    synthesize_parser.add_argument("--codeql-version", default="2.27.2")
    synthesize_parser.add_argument("--max-iterations", type=int, default=10)
    synthesize_parser.add_argument("--max-tool-calls", type=int, default=50)
    synthesize_parser.add_argument(
        "--strict-fixed",
        action="store_true",
        help="reject any alert on the fixed database, even outside the patch",
    )
    synthesize_parser.add_argument("--llm-base-url")
    synthesize_parser.add_argument("--llm-model")
    synthesize_parser.add_argument("--llm-api-key")
    synthesize_parser.add_argument("--no-lsp", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "add":
            return _add_cve(args)
        if args.command == "database":
            return _create_database(args)
        if args.command == "query":
            return _run_query_command(args)
        if args.command == "pack":
            return _run_pack_command(args)
        if args.command == "config":
            return _run_config_command(args)
        if args.command == "rag":
            return _run_rag_command(args)
        if args.command == "evidence":
            return _run_evidence(args)
        if args.command == "validate":
            return _run_validate(args)
        if args.command == "lsp":
            return _run_lsp_command(args)
        if args.command == "generate":
            return _run_generate(args)
        if args.command == "analyze":
            return _run_analyze(args)
        if args.command == "synthesize":
            return _run_synthesize(args)
        parser.error(f"unsupported command: {args.command}")
    except (
        CVEError,
        CodeQLError,
        RagError,
        EvidenceError,
        GitError,
        AgentError,
        LSPError,
        LLMError,
        SynthesisError,
        ValidationError,
    ) as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2

    return 0


def _add_cve(args: argparse.Namespace) -> int:
    cve_id = validate_cve_id(args.cve_id)
    artifact_dir = args.output_dir / cve_id
    spec_path = artifact_dir / "vulnerability_spec.json"
    record_path = artifact_dir / "cve_record.json"
    cache_path = args.cache_dir / f"{cve_id}.json"

    if cache_path.resolve() in (spec_path.resolve(), record_path.resolve()):
        raise CVEError("artifact and cache paths resolve to the same file; choose separate directories")
    if spec_path.exists() and not args.force:
        raise CVEError(
            f"vulnerability spec already exists at {spec_path}; use --force to replace it"
        )

    if cache_path.exists() and not args.refresh:
        try:
            raw_json = cache_path.read_bytes()
        except OSError as exc:
            raise CVEError(f"could not read cached CVE record {cache_path}: {exc}") from exc
        try:
            record = parse_record(raw_json, cve_id)
        except CVEError as exc:
            raise CVEError(f"cached CVE record {cache_path} is invalid: {exc}") from exc
        cache_status = "Using cached raw CVE record"
    else:
        record, raw_json = fetch_record(cve_id)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(raw_json)
        cache_status = "Cached raw CVE record"

    spec = build_vulnerability_spec(cve_id, record)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    record_path.write_bytes(raw_json)
    with spec_path.open("w", encoding="utf-8", newline="\n") as spec_file:
        json.dump(spec, spec_file, indent=2, ensure_ascii=False)
        spec_file.write("\n")

    print(f"{cache_status} at {cache_path}")
    print(f"Wrote evidence-gated vulnerability IR to {spec_path}")
    print("Status: insufficient_evidence; source discovery and root-cause analysis are still required.")
    return 0


def _create_database(args: argparse.Namespace) -> int:
    create_cpp_database(
        args.source_root,
        args.database,
        build_command=args.build_command,
        build_mode=args.build_mode,
        codeql_path=args.codeql_path,
    )
    print(f"Created CodeQL database at {args.database}")
    return 0


def _run_query_command(args: argparse.Namespace) -> int:
    if args.query_command == "compile":
        compile_query(args.query, codeql_path=args.codeql_path)
        print(f"Compiled CodeQL query {args.query}")
        return 0

    analyze_query(
        args.database,
        args.query,
        args.output,
        codeql_path=args.codeql_path,
    )
    print(f"Wrote SARIF results to {args.output}")
    return 0


def _run_pack_command(args: argparse.Namespace) -> int:
    if args.pack_command == "install":
        install_pack(args.pack_root, codeql_path=args.codeql_path)
        print(f"Resolved CodeQL pack dependencies in {args.pack_root}")
        return 0

    verify_pack(args.pack_root, codeql_path=args.codeql_path)
    print(f"CodeQL pack lock verified in {args.pack_root}")
    return 0


def _run_config_command(args: argparse.Namespace) -> int:
    if args.config_command == "show":
        base_url = os.environ.get("CVE2CHECKER_LLM_BASE_URL", "")
        model = os.environ.get("CVE2CHECKER_LLM_MODEL", "")
        key = os.environ.get("CVE2CHECKER_LLM_API_KEY") or os.environ.get(
            "OPENCODE_API_KEY"
        )
        print(f"base_url: {base_url or '(not set)'}")
        print(f"model: {model or '(not set)'}")
        print(f"key_present: {bool(key)}")
        return 0

    key = getpass.getpass("OpenCode Go API key: ").strip()
    if not key:
        raise ValueError("API key must not be empty")
    path = project_env_paths()[0]
    set_env_value(path, "OPENCODE_API_KEY", key)
    print(f"Saved OPENCODE_API_KEY to {path} (value hidden).")
    return 0


def _run_rag_command(args: argparse.Namespace) -> int:
    index = RagIndex(args.db)
    if args.rag_command == "index":
        total = 0
        for source in args.source:
            total += index_directory(
                index,
                args.collection,
                source,
                extensions=args.extensions,
                chunk_lines=args.chunk_lines,
                max_file_bytes=args.max_file_bytes,
            )
        print(
            f"Indexed {total} document chunk(s) from "
            f"{len(args.source)} source directory(ies) into {args.db}"
        )
        return 0

    results = index.search(args.collection, args.query, limit=args.limit)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0


def _run_evidence(args: argparse.Namespace) -> int:
    cve_id = validate_cve_id(args.cve_id)
    if args.cve_file is not None:
        raw_json = args.cve_file.read_bytes()
        record = parse_record(raw_json, cve_id)
    else:
        cache_path = args.cache_dir / f"{cve_id}.json"
        if cache_path.exists() and not args.refresh:
            raw_json = cache_path.read_bytes()
            record = parse_record(raw_json, cve_id)
        else:
            record, raw_json = fetch_record(cve_id)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_bytes(raw_json)

    result = build_evidence(
        cve_id,
        record,
        args.output_dir,
        repo_path=args.repo_path,
        fix_commit=args.fix_commit,
        github_token=args.github_token,
        context_lines=args.context_lines,
    )
    print(f"Repository: {result['repo_path']}")
    print(f"Vulnerable commit: {result['vulnerable_commit']}")
    print(f"Fix commit: {result['fix_commit']}")
    print(f"Wrote evidence artifacts under {result['artifact_dir']}")
    return 0


def _run_validate(args: argparse.Namespace) -> int:
    diff_text = args.diff.read_text(encoding="utf-8")
    diffs = parse_unified_diff(diff_text)
    changed = [
        *changed_ranges(diffs, "old"),
        *changed_ranges(diffs, "new"),
    ]
    feedback = validate_query(
        args.query,
        args.vuln_db,
        args.fixed_db,
        changed,
        args.output_dir,
        codeql_path=args.codeql_path,
        iteration=args.iteration,
        strict_fixed=args.strict_fixed,
    )
    if args.json:
        print(json.dumps(feedback, indent=2, ensure_ascii=False))
    else:
        print(f"Verdict: {feedback['verdict']}")
        print(
            "Vulnerable: "
            f"{feedback['vulnerable']['match_count']} match(es), "
            f"{feedback['vulnerable']['diff_intersection_count']} in diff"
        )
        print(
            "Fixed: "
            f"{feedback['fixed']['match_count']} match(es), "
            f"{feedback['fixed']['diff_intersection_count']} in diff"
        )
    return 0 if feedback.get("verdict") == "success" else 1


def _run_lsp_command(args: argparse.Namespace) -> int:
    client = CodeQLLanguageServer(
        codeql_path=args.codeql_path, pack_root=args.pack_root
    )
    client.start()
    try:
        diagnostics = client.diagnostics(args.query)
    finally:
        client.stop()
    print(json.dumps(diagnostics, indent=2, ensure_ascii=False))
    return 0 if not diagnostics else 1


def _build_llm(args: argparse.Namespace):
    api_key = (
        args.llm_api_key
        or os.environ.get("CVE2CHECKER_LLM_API_KEY")
        or os.environ.get("OPENCODE_API_KEY")
        or None
    )
    if args.llm_base_url and args.llm_model:
        fallback_models = [
            item.strip()
            for item in os.environ.get("CVE2CHECKER_LLM_FALLBACK_MODELS", "").split(
                ","
            )
            if item.strip()
        ]
        return build_llm_client(
            base_url=args.llm_base_url,
            model=args.llm_model,
            api_key=api_key,
            timeout=float(os.environ.get("CVE2CHECKER_LLM_TIMEOUT", "180")),
            max_tokens=int(os.environ.get("CVE2CHECKER_LLM_MAX_TOKENS", "32768")),
            fallback_models=fallback_models,
            attempts=int(os.environ.get("CVE2CHECKER_LLM_RETRIES", "3")),
            backoff=float(os.environ.get("CVE2CHECKER_LLM_BACKOFF", "2")),
        )
    if args.llm_base_url or args.llm_model:
        raise ValueError("--llm-base-url and --llm-model must be supplied together")
    return llm_from_env()


def _run_generate(args: argparse.Namespace) -> int:
    cve_id = validate_cve_id(args.cve_id)
    run_dir = args.output_dir / cve_id
    run_dir.mkdir(parents=True, exist_ok=True)
    state_path = run_dir / "state.json"
    state = _read_state(state_path) if args.resume else {"stages": {}}
    state["cve_id"] = cve_id
    state.setdefault("stages", {})
    _save_state(state_path, state)

    cve_path = run_dir / "cve.json"
    if args.resume and cve_path.is_file():
        record = parse_record(cve_path.read_bytes(), cve_id)
    else:
        record, raw_json = _load_generate_cve(args, cve_id)
        cve_path.write_bytes(raw_json)
    _mark_stage(state, state_path, "cve", "completed", path=str(cve_path))
    print(f"[cve] {cve_id}")

    source_path = run_dir / "source.json"
    diff_path = run_dir / "diff.patch"
    context_path = run_dir / "context.json"
    if (
        args.resume
        and _stage_completed(state, "evidence")
        and all(path.is_file() for path in (source_path, diff_path, context_path))
    ):
        evidence = _load_evidence(run_dir)
    else:
        evidence = build_evidence(
            cve_id,
            record,
            args.output_dir,
            repo_path=args.repo_path,
            fix_commit=args.fix_commit,
            github_token=os.environ.get("GITHUB_TOKEN"),
            context_lines=args.context_lines,
        )
        _mark_stage(
            state,
            state_path,
            "evidence",
            "completed",
            source=evidence["source"].get("repository_url"),
            vulnerable_commit=evidence["vulnerable_commit"],
            fix_commit=evidence["fix_commit"],
        )
    if args.vuln_commit and evidence["vulnerable_commit"].lower() != args.vuln_commit.lower():
        raise ValueError(
            "resolved vulnerable commit does not match --vuln-commit: "
            f"{evidence['vulnerable_commit']} != {args.vuln_commit}"
        )
    print(
        f"[evidence] {evidence['vulnerable_commit'][:12]} -> "
        f"{evidence['fix_commit'][:12]}"
    )

    worktree_root = run_dir / "generated-worktrees"
    vuln_src = worktree_root / "vulnerable"
    fix_src = worktree_root / "fixed"
    db_root = run_dir / "generated-db"
    vuln_db = db_root / "vulnerable"
    fixed_db = db_root / "fixed"
    build_mode = None if args.build_command else args.build_mode
    build_log = ""
    if not (
        args.resume
        and _stage_completed(state, "databases")
        and _database_ready(vuln_db)
        and _database_ready(fixed_db)
    ):
        vuln_src = add_worktree(
            evidence["repo_path"], vuln_src, evidence["vulnerable_commit"]
        )
        fix_src = add_worktree(
            evidence["repo_path"], fix_src, evidence["fix_commit"]
        )
        if not _database_ready(vuln_db):
            create_cpp_database(
                vuln_src,
                vuln_db,
                build_command=args.build_command,
                build_mode=build_mode,
                codeql_path=args.codeql_path,
            )
        if not _database_ready(fixed_db):
            create_cpp_database(
                fix_src,
                fixed_db,
                build_command=args.build_command,
                build_mode=build_mode,
                codeql_path=args.codeql_path,
            )
        build_log = (
            "CodeQL C/C++ databases created successfully.\n"
            f"Vulnerable source: {vuln_src} at {evidence['vulnerable_commit']}\n"
            f"Vulnerable database: {vuln_db}\n"
            f"Fixed source: {fix_src} at {evidence['fix_commit']}\n"
            f"Fixed database: {fixed_db}\n"
            f"Build mode: {build_mode or 'custom build command'}\n"
        )
        _mark_stage(
            state,
            state_path,
            "databases",
            "completed",
            vulnerable_db=str(vuln_db),
            fixed_db=str(fixed_db),
        )
    print(f"[databases] {vuln_db} | {fixed_db}")

    analysis_dir = run_dir / "generated-analysis"
    feasibility_path = analysis_dir / "feasibility.json"
    ir_path = analysis_dir / "vulnerability_ir.json"
    feasibility: dict | None = None
    vulnerability_ir: dict | None = None
    if args.resume and _stage_completed(state, "analysis") and feasibility_path.is_file():
        feasibility = json.loads(feasibility_path.read_text(encoding="utf-8"))
        if feasibility.get("decision") == "proceed" and ir_path.is_file():
            vulnerability_ir = json.loads(ir_path.read_text(encoding="utf-8"))
    if feasibility is None:
        llm = _build_llm(args)
        diff_summary = {
            "stats": evidence["source"].get("diff_stats", {}),
            "patch": evidence["diff"],
        }
        if not build_log:
            build_log = (
                f"Existing CodeQL databases: {vuln_db} and {fixed_db}\n"
            )
        feasibility = run_feasibility(
            record,
            evidence["source"],
            diff_summary,
            llm,
            build_log=build_log,
            codeql_version=args.codeql_version,
            max_attempts=args.max_attempts,
        )
        write_json_artifact(feasibility_path, feasibility)
    if feasibility.get("decision") != "proceed":
        _mark_stage(state, state_path, "analysis", "blocked", decision=feasibility.get("decision"))
        _write_generate_report(
            run_dir,
            cve_id,
            status="blocked",
            stages=state["stages"],
            evidence=evidence,
            artifacts={"cve": cve_path, "source": source_path, "diff": diff_path, "context": context_path, "feasibility": feasibility_path},
            metadata=_generate_metadata(args, evidence),
            summary={"decision": feasibility.get("decision")},
        )
        print(f"[analysis] blocked: {feasibility.get('decision')}")
        return 1
    if vulnerability_ir is None:
        if "llm" not in locals():
            llm = _build_llm(args)
        vulnerability_ir = run_root_cause(
            record,
            evidence["diff"],
            evidence["context"],
            llm,
            vulnerable_commit=evidence["vulnerable_commit"],
            fix_commit=evidence["fix_commit"],
            max_attempts=args.max_attempts,
        )
        write_json_artifact(ir_path, vulnerability_ir)
    _mark_stage(state, state_path, "analysis", "completed", decision="proceed")
    print(f"[analysis] proceed; IR {ir_path}")

    final_dir = run_dir / "final"
    final_query = final_dir / f"{cve_id}.ql"
    final_validation = final_dir / "validation_report.json"
    if (
        args.resume
        and _stage_completed(state, "synthesis")
        and final_query.is_file()
        and final_validation.is_file()
    ):
        previous = json.loads(final_validation.read_text(encoding="utf-8"))
        if previous.get("verdict") == "success":
            print("[synthesis] reusing successful final query")
            _write_generate_report(
                run_dir,
                cve_id,
                status="success",
                stages=state["stages"],
                evidence=evidence,
                artifacts={
                    "cve": cve_path,
                    "source": source_path,
                    "diff": diff_path,
                    "context": context_path,
                    "feasibility": feasibility_path,
                    "vulnerability_ir": ir_path,
                    "query": final_query,
                    "validation_report": final_validation,
                },
                metadata=_generate_metadata(args, evidence),
                summary={"verdict": "success", **previous.get("metrics", {})},
            )
            return 0

    synthesis_dir = run_dir / "generated-synthesis"
    ensure_query_pack(synthesis_dir, codeql_path=args.codeql_path)
    llm = _build_llm(args)
    rag = (
        RagIndex(args.rag_db)
        if args.rag_db is not None and args.rag_db.is_file()
        else None
    )
    lsp = None
    if not args.no_lsp:
        lsp = CodeQLLanguageServer(
            codeql_path=args.codeql_path, pack_root=synthesis_dir
        )
        lsp.start()
    try:
        tools = ToolBox(
            repo_root=Path(evidence["repo_path"]),
            workdir=synthesis_dir,
            rag=rag,
            lsp=lsp,
        )
        diffs = parse_unified_diff(evidence["diff"])
        changed = [
            *changed_ranges(diffs, "old"),
            *changed_ranges(diffs, "new"),
        ]

        def validate(query, iteration_dir, iteration):
            return validate_query(
                query,
                vuln_db,
                fixed_db,
                changed,
                iteration_dir,
                codeql_path=args.codeql_path,
                iteration=iteration,
                strict_fixed=args.strict_fixed,
            )

        result = run_synthesis(
            cve_id=cve_id,
            cve=record,
            cwe_ids=vulnerability_ir.get("cwe_ids", []),
            repo_path=evidence["repo_path"],
            vulnerable_commit=evidence["vulnerable_commit"],
            fix_commit=evidence["fix_commit"],
            diff=evidence["diff"],
            vulnerability_ir=vulnerability_ir,
            ast_snippets=[],
            workdir=synthesis_dir,
            llm=llm,
            tools=tools,
            validate=validate,
            codeql_version=args.codeql_version,
            max_iterations=args.max_iterations,
            max_tool_calls=args.max_tool_calls,
        )
    finally:
        if lsp is not None:
            lsp.stop()

    final_dir.mkdir(parents=True, exist_ok=True)
    if result.query_path is not None and Path(result.query_path).is_file():
        shutil.copy2(result.query_path, final_query)
    result_payload = {
        "status": result.status,
        "iterations": result.iterations,
        "query_path": str(result.query_path) if result.query_path else None,
        "feedback": result.feedback,
        "history": result.history,
    }
    write_json_artifact(synthesis_dir / "synthesis_result.json", result_payload)
    feedback = result.feedback or {}
    if feedback:
        write_json_artifact(final_validation, feedback)
    _mark_stage(
        state,
        state_path,
        "synthesis",
        "completed" if result.status == "success" else "failed",
        verdict=feedback.get("verdict"),
        iterations=result.iterations,
    )
    print(f"[synthesis] {result.status}; verdict={feedback.get('verdict')}")

    artifacts = {
        "cve": cve_path,
        "source": source_path,
        "diff": diff_path,
        "context": context_path,
        "feasibility": feasibility_path,
        "vulnerability_ir": ir_path,
        "synthesis_result": synthesis_dir / "synthesis_result.json",
    }
    if final_query.is_file():
        artifacts["query"] = final_query
    if final_validation.is_file():
        artifacts["validation_report"] = final_validation
    _write_generate_report(
        run_dir,
        cve_id,
        status=result.status,
        stages=state["stages"],
        evidence=evidence,
        artifacts=artifacts,
        metadata=_generate_metadata(args, evidence),
        summary={
            "verdict": feedback.get("verdict"),
            "iterations": result.iterations,
            **feedback.get("metrics", {}),
        },
    )
    return 0 if result.status == "success" else 1


def _load_generate_cve(
    args: argparse.Namespace, cve_id: str
) -> tuple[dict, bytes]:
    if args.cve_file is not None:
        raw_json = args.cve_file.read_bytes()
        return parse_record(raw_json, cve_id), raw_json
    cache_path = args.cache_dir / f"{cve_id}.json"
    if cache_path.is_file() and not args.refresh:
        raw_json = cache_path.read_bytes()
        return parse_record(raw_json, cve_id), raw_json
    record, raw_json = fetch_record(cve_id)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(raw_json)
    return record, raw_json


def _load_evidence(run_dir: Path) -> dict:
    source = json.loads((run_dir / "source.json").read_text(encoding="utf-8"))
    context = json.loads((run_dir / "context.json").read_text(encoding="utf-8"))
    return {
        "artifact_dir": str(run_dir),
        "source": source,
        "repo_path": source.get("repo_path"),
        "vulnerable_commit": source.get("vulnerable_commit"),
        "fix_commit": source.get("fix_commit"),
        "diff": (run_dir / "diff.patch").read_text(encoding="utf-8"),
        "diff_path": str(run_dir / "diff.patch"),
        "context": context.get("snippets", []),
        "context_path": str(run_dir / "context.json"),
    }


def _database_ready(path: Path) -> bool:
    return (path / "codeql-database.yml").is_file()


def _read_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"stages": {}}
    if not isinstance(state, dict):
        return {"stages": {}}
    state.setdefault("stages", {})
    return state


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _mark_stage(
    state: dict, state_path: Path, name: str, status: str, **extra: object
) -> None:
    state["stages"][name] = {
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    _save_state(state_path, state)


def _stage_completed(state: dict, name: str) -> bool:
    stage = state.get("stages", {}).get(name, {})
    return isinstance(stage, dict) and stage.get("status") == "completed"


def _generate_metadata(args: argparse.Namespace, evidence: dict) -> dict:
    return {
        "repo": evidence["source"].get("repository_url"),
        "vulnerable_commit": evidence["vulnerable_commit"],
        "fix_commit": evidence["fix_commit"],
        "model": args.llm_model or os.environ.get("CVE2CHECKER_LLM_MODEL", "unknown"),
        "endpoint": args.llm_base_url
        or os.environ.get("CVE2CHECKER_LLM_BASE_URL", ""),
        "codeql_version": args.codeql_version,
        "strict_fixed": bool(args.strict_fixed),
    }


def _write_generate_report(
    run_dir: Path,
    cve_id: str,
    *,
    status: str,
    stages: dict,
    evidence: dict,
    artifacts: dict,
    metadata: dict,
    summary: dict,
) -> None:
    write_run_report(
        run_dir / "final",
        cve_id=cve_id,
        status=status,
        stages=stages,
        artifacts=artifacts,
        metadata=metadata,
        summary=summary,
    )


def _run_analyze(args: argparse.Namespace) -> int:
    record = parse_record(args.cve_file.read_bytes())
    cve_id = record["cveMetadata"]["cveId"]
    source_data = json.loads(args.source_json.read_text(encoding="utf-8"))
    diff_path = source_data.get("diff_path")
    context_path = source_data.get("context_path")
    if not isinstance(diff_path, str) or not diff_path:
        raise ValueError("source.json is missing diff_path; run the evidence command first")
    if not isinstance(context_path, str) or not context_path:
        raise ValueError("source.json is missing context_path; run the evidence command first")
    diff_text = Path(diff_path).read_text(encoding="utf-8")
    context = json.loads(Path(context_path).read_text(encoding="utf-8"))
    snippets = context.get("snippets", []) if isinstance(context, dict) else []
    build_log = args.build_log.read_text(encoding="utf-8") if args.build_log else ""

    output_dir = args.output_dir or Path(source_data.get("artifact_dir", "."))
    output_dir.mkdir(parents=True, exist_ok=True)
    llm = _build_llm(args)

    diff_summary = {
        "stats": source_data.get("diff_stats", {}),
        "patch": diff_text,
    }
    feasibility = run_feasibility(
        record,
        source_data,
        diff_summary,
        llm,
        build_log=build_log,
        codeql_version=args.codeql_version,
        max_attempts=args.max_attempts,
    )
    write_json_artifact(output_dir / "feasibility.json", feasibility)
    print(f"Feasibility: {feasibility['decision']} ({feasibility['confidence']:.2f})")
    if feasibility["decision"] != "proceed":
        print("Stopped before query synthesis; see feasibility.json for missing evidence.")
        return 1

    vulnerability_ir = run_root_cause(
        record,
        diff_text,
        snippets,
        llm,
        vulnerable_commit=source_data.get("vulnerable_commit"),
        fix_commit=source_data.get("fix_commit"),
        max_attempts=args.max_attempts,
    )
    write_json_artifact(output_dir / "vulnerability_ir.json", vulnerability_ir)
    print(f"Wrote vulnerability IR to {output_dir / 'vulnerability_ir.json'}")
    return 0


def _run_synthesize(args: argparse.Namespace) -> int:
    record = parse_record(args.cve_file.read_bytes())
    cve_id = record["cveMetadata"]["cveId"]
    vulnerability_ir = json.loads(args.ir.read_text(encoding="utf-8"))
    diff_text = args.diff.read_text(encoding="utf-8")
    diffs = parse_unified_diff(diff_text)
    changed = [
        *changed_ranges(diffs, "old"),
        *changed_ranges(diffs, "new"),
    ]

    llm = _build_llm(args)
    ensure_query_pack(args.output_dir, codeql_path=args.codeql_path)

    rag = RagIndex(args.rag_db) if args.rag_db is not None else None
    lsp = None
    if not args.no_lsp:
        lsp = CodeQLLanguageServer(
            codeql_path=args.codeql_path, pack_root=args.pack_root
        )
        lsp.start()

    try:
        tools = ToolBox(
            repo_root=args.repo,
            workdir=args.output_dir,
            rag=rag,
            lsp=lsp,
        )

        def validate(query, iteration_dir, iteration):
            return validate_query(
                query,
                args.vuln_db,
                args.fixed_db,
                changed,
                iteration_dir,
                codeql_path=args.codeql_path,
                iteration=iteration,
                strict_fixed=args.strict_fixed,
            )

        result = run_synthesis(
            cve_id=cve_id,
            cve=record,
            cwe_ids=vulnerability_ir.get("cwe_ids", []),
            repo_path=args.repo,
            vulnerable_commit=args.vuln_commit,
            fix_commit=args.fix_commit,
            diff=diff_text,
            vulnerability_ir=vulnerability_ir,
            ast_snippets=[],
            workdir=args.output_dir,
            llm=llm,
            tools=tools,
            validate=validate,
            codeql_version=args.codeql_version,
            max_iterations=args.max_iterations,
            max_tool_calls=args.max_tool_calls,
        )
    finally:
        if lsp is not None:
            lsp.stop()

    print(f"Status: {result.status}")
    print(f"Iterations: {result.iterations}")
    if result.query_path is not None:
        print(f"Query: {result.query_path}")
    return 0 if result.status == "success" else 1
