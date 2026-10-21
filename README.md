# CVE2Checker: CVE-to-CodeQL

CVE2Checker is an evidence-driven pipeline that turns a C/C++ CVE into a custom CodeQL query and validates that the query detects the vulnerable revision but not the fixed revision. The design follows QLCoder (arXiv:2511.08462): a tool-using synthesis agent, a deterministic validator, same-version CodeQL documentation/examples in a retrieval index, and an outer repair loop.

## Status

| Phase | Scope | Status |
|---|---|---|
| 0 | Pinned CodeQL bundle, language-server client, RAG index, baseline query | Complete |
| 1 | CVE reference/source discovery, git evidence, diff/context extraction, DB build modes | Complete |
| 2 | Feasibility and root-cause schemas/prompts, LLM client, citation enforcement | Complete |
| 3 | SARIF parsing, diff-aware validator, iterative synthesis loop, LSP/RAG tools | Complete |
| 4 | Single-command checkpointed orchestrator, resume, manifest/report | Implemented (sequential; LangGraph optional) |
| 5 | C/C++ benchmark, ablations, evaluation report | Not implemented |

The synthesis loop is usable, but it is not yet a benchmarked CVE-to-query system. Do not treat a successful query as proof of a vulnerability outside the supplied vulnerable/fixed pair.

## Safety and scope

CVE metadata alone is not enough to infer a source-level root cause. `add` writes an `insufficient_evidence` vulnerability spec and a blocked generation gate. Feasibility must succeed, and every root-cause component must cite a path, line range, commit, and snippet before synthesis is allowed.

The included `BaselineDirectStrcpyCall.ql` is a low-precision demonstration, not a CVE detector. Finding `strcpy` does not prove a buffer overflow or a relationship to any CVE.

## Toolchain

- CodeQL is pinned in `.codeql-version` to `2.27.2`.
- The query pack pins `codeql/cpp-all` to `12.2.0` in `codeql-pack/qlpack.yml`.
- The Windows bundle is installed locally at `.tools/codeql` (gitignored). The CLI resolves this path automatically. Override it with `--codeql-path` or the `CODEQL_PATH` environment variable.
- Python 3.12 is the development target; the code also runs on Python 3.11.
- C/C++ database creation needs the target project's build tools. `--build-mode=none` is available as a documented fallback, but it can reduce database quality.

Resolve the query pack once and keep the generated lock file:

```powershell
python -m pip install -e .
python main.py pack install
python main.py pack ci
```

## CLI workflow

### 1. Fetch a CVE and write the initial spec

```powershell
python main.py add CVE-2021-3156
```

Outputs `artifacts/CVE-2021-3156/vulnerability_spec.json` and caches the raw record under `.cache/cve2checker/`.

### 2. Discover source and build evidence

Use `--cve-file` for an existing CVE v5 record, or omit it to fetch/cache from the CVE Services API. Fix commits can come from CVE commit references, a resolved GitHub PR, or `--fix-commit`. `GITHUB_TOKEN` is used automatically when present.

```powershell
python main.py evidence `
  --cve-id CVE-2021-3156 `
  --repo-path C:\src\project `
  --fix-commit <40-char-sha> `
  --output-dir artifacts
```

Outputs `source.json`, `diff.patch`, and `context.json` under `artifacts/<CVE>/`.

If `--repo-path` is omitted, the repository is cloned from the first GitHub reference. PR merge-commit resolution uses the GitHub API; without a token it is subject to rate limits.

### 3. Build the RAG index

```powershell
python main.py rag index `
  --db .cache/cve2checker/rag.sqlite `
  --collection codeql_cpp `
  --source .tools/codeql/qlpacks/codeql/cpp-all/12.2.0 `
  --source .tools/codeql/qlpacks/codeql/cpp-examples/0.0.0 `
  --source .tools/codeql/qlpacks/codeql/cpp-queries/1.9.1 `
  --source codeql-pack

python main.py rag search "TaintTracking Global ConfigSig" `
  --db .cache/cve2checker/rag.sqlite `
  --collection codeql_cpp `
  --limit 3
```

The index is SQLite FTS5-backed. `.codeql`, `.git`, caches, and dependency directories are skipped.

### 4. Run feasibility and root-cause agents

The agents use an OpenAI-compatible chat-completions endpoint. OpenCode Go exposes one at `https://opencode.ai/inference/go/openai/v1`. Put the configuration in the repository `.env` file (gitignored); `.env.example` shows the format:

```text
CVE2CHECKER_LLM_BASE_URL=https://opencode.ai/inference/go/openai/v1
CVE2CHECKER_LLM_MODEL=deepseek-v4.1-flash
CVE2CHECKER_LLM_API_KEY=
# Used as a fallback when CVE2CHECKER_LLM_API_KEY is empty:
OPENCODE_API_KEY=put-your-opencode-go-key-here
CVE2CHECKER_LLM_TIMEOUT=600
CVE2CHECKER_LLM_MAX_TOKENS=32768
CVE2CHECKER_LLM_RETRIES=3
CVE2CHECKER_LLM_BACKOFF=2
# Optional same-endpoint fallback models:
# CVE2CHECKER_LLM_FALLBACK_MODELS=glm-5.3-flash,mimo-v2.6-flash
```

Get the key from the [OpenCode Console](https://opencode.ai/console) (the same key used by `/connect` with OpenCode Go). The CLI loads `.env` automatically; existing shell environment variables win. Paste only the key into `OPENCODE_API_KEY`. For a stronger model, replace `deepseek-v4.1-flash` with `deepseek-v4-pro`. The client sends a stable `x-opencode-session` header for Go prompt caching. A small 1.5B local model is not sufficient for reliable schema/query generation.

```powershell
python main.py analyze `
  --cve-file .cache/cve2checker/CVE-2021-3156.json `
  --source-json artifacts/CVE-2021-3156/source.json
```

Outputs `feasibility.json` and, when the decision is `proceed`, `vulnerability_ir.json`. You can also pass `--llm-base-url`, `--llm-model`, and `--llm-api-key` explicitly. A blocked feasibility decision exits with code 1 and writes no IR.

### 5. Create CodeQL databases

```powershell
python main.py database create `
  --source-root C:\src\project-vulnerable `
  --database artifacts\db-vulnerable `
  --build-mode none

python main.py database create `
  --source-root C:\src\project-fixed `
  --database artifacts\db-fixed `
  --build-command "cmake --build build --config Release"
```

Prefer autobuild or a custom traced build for production. `--build-mode none` is a fallback.

### 6. Check a query with the language server

```powershell
python main.py lsp diagnostics --query codeql-pack\queries\BaselineDirectStrcpyCall.ql
```

Exit code 0 means no diagnostics; exit code 1 means the query has errors.

### 7. Validate a query against both revisions

```powershell
python main.py validate `
  --query codeql-pack\queries\BaselineDirectStrcpyCall.ql `
  --vuln-db artifacts\db-vulnerable `
  --fixed-db artifacts\db-fixed `
  --diff artifacts\CVE-2021-3156\diff.patch `
  --output-dir artifacts\CVE-2021-3156\validation
```

The validator compiles the query, runs it on both databases, parses SARIF, and checks whether alerts intersect changed lines. Success requires a vulnerable-side intersection and no fixed-side intersection. It writes `feedback.json` and exits 0 only on `success`. Use `--json` for the full feedback.

### 8. Run the synthesis loop

```powershell
python main.py synthesize `
  --cve-file .cache/cve2checker/CVE-2021-3156.json `
  --ir artifacts/CVE-2021-3156/vulnerability_ir.json `
  --repo C:\src\project `
  --vuln-commit <parent-sha> `
  --fix-commit <fix-sha> `
  --diff artifacts/CVE-2021-3156/diff.patch `
  --vuln-db artifacts\db-vulnerable `
  --fixed-db artifacts\db-fixed `
  --output-dir artifacts/CVE-2021-3156/synthesis `
  --rag-db .cache/cve2checker/rag.sqlite
```

Defaults: 10 outer iterations, 50 tool calls per iteration. The model must respond with a tool call or a final query; JSON, DSML, and XML tool formats are accepted. LSP tools are enabled by default; `--no-lsp` disables them. `--strict-fixed` rejects any fixed-side alert, even outside the patch.

### 9. Run the whole pipeline with one command

```powershell
python main.py generate `
  --cve-id CVE-2022-37434 `
  --cve-file .cache/cve2checker/CVE-2022-37434.json `
  --repo-path C:\src\zlib `
  --fix-commit eff308af425b67093bab25f80f1ae950166bece1 `
  --output-dir artifacts `
  --build-mode none `
  --rag-db .cache/cve2checker/rag.sqlite
```

`generate` derives the vulnerable parent commit, creates worktrees and both databases, runs feasibility and root-cause agents, runs the synthesis loop with a generated-query pack, validates each candidate, and writes the final report. It checkpoints after every stage; rerun with `--resume` to continue. Outputs:

```text
artifacts/<CVE>/
  state.json
  generated-analysis/
  generated-synthesis/
  final/query.ql
  final/validation_report.json
  final/manifest.json
  final/report.md
```

The orchestrator is sequential and checkpointed. It is not a LangGraph workflow.

## Implemented modules

```text
cve2checker/
  cve.py           CVE v5 fetch/cache and initial spec
  source.py        GitHub reference parsing and fix-commit discovery
  git_tools.py     shell-free git wrappers
  diff.py          unified diff parsing and changed-line mapping
  context.py       hunk/function source context
  evidence.py      evidence artifact orchestration
  rag.py           SQLite FTS5 retrieval index
  rag_index.py     directory indexing/chunking
  lsp.py           CodeQL language-server JSON-RPC client
  llm.py           OpenAI-compatible + scripted LLM clients
  prompts.py       agent prompt templates and response extraction
  schemas.py       feasibility and vulnerability-IR validation
  agents.py        feasibility and root-cause agents
  codeql.py        CodeQL CLI wrappers
  sarif.py         SARIF 2.1.0 parsing and location matching
  validator.py     compile/analyze/score loop feedback
  synthesis.py     tool-using synthesis and repair loop
  report.py        run manifest and Markdown report
  cli.py           CLI commands and checkpointed generate orchestrator
codeql-pack/       query pack and demonstration query
tests/             offline unit tests and opt-in real-tool integrations
```

## Tests

All deterministic tests are offline; CodeQL and LLM calls are mocked:

```powershell
python -m unittest discover -s tests -v
```

Opt-in real-tool gates:

```powershell
$env:CVE2CHECKER_LSP_INTEGRATION="1"
python -m unittest tests.test_lsp.RealCodeQLLSPTests -v
Remove-Item Env:CVE2CHECKER_LSP_INTEGRATION

$env:CVE2CHECKER_CODEQL_INTEGRATION="1"
python -m unittest tests.test_validator_integration tests.test_e2e_integration -v
Remove-Item Env:CVE2CHECKER_CODEQL_INTEGRATION
```

The real validator test creates two tiny C databases, runs the baseline query, and requires a vulnerable hit with no fixed hit. The end-to-end test runs the synthesis loop with a scripted agent and real CodeQL databases.

## Validated demo

`examples/CVE-2022-37434/` contains the zlib run artifacts:

- `CVE-2022-37434.ql` — query generated by `deepseek-v4.1-flash`.
- `CVE-2022-37434-Manual.ql` — manual reference query for comparison.
- `validation_report.json` — generated-query verdict: success, precision 0.75, F1 0.857.
- `validation_manual.json` — reference-query verdict: success, precision/F1 1.0.
- `feasibility.json`, `vulnerability_ir.json`, `summary.json` — intermediate evidence.

The generated query is broader than the reference query: it reports one fixed-side alert outside the changed lines. The reference query is intentionally specific to the `extra_max` guard.

## Known limitations

- Source context extraction is heuristic brace matching, not a real C/C++ AST. The synthesis API accepts `ast_snippets`, but the CLI currently passes an empty list.
- The feasibility/root-cause agents require an external LLM. Tests use a scripted backend.
- The tool protocol is a simple JSON ReAct loop, not native Claude Code/MCP tool use. QLCoder-style backends can be added behind the same `LLMClient` interface.
- CVE-to-source discovery relies on GitHub references and does not yet search arbitrary code hosts or map every CWE.
- The benchmark, held-out evaluation, and LangGraph workflow are not implemented.
- Model availability matters: OpenCode Go endpoints can return 503 or time out. The client retries transient failures and supports same-endpoint fallback models, but a capable model is still required.
- Default success follows the QLCoder predicate (no fixed-side alert intersecting the patch). Use `--strict-fixed` to reject any fixed-side alert.
- CodeQL licensing and terms apply to its use. QLCoder is MIT-licensed; this project adapts its architecture, not its Java-specific prompts or evaluation data.
