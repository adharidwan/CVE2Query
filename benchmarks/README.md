# CVE2Query Pilot Benchmark (5 CVEs)

This is a small pilot benchmark, not a statistically meaningful evaluation. It exists to show the end-to-end behavior of `generate`: feasibility gating, query synthesis, and deterministic validation on vulnerable/fixed revisions.

Settings: CodeQL 2.27.2, `--build-mode none`, 3 synthesis iterations, 12 tool calls, no LSP, QLCoder-style success predicate.

| CVE | Repository | Feasibility | Synthesis | Precision / F1 |
|---|---|---|---|---|
| CVE-2022-37434 | madler/zlib | proceed | **success** | 1.0 / 1.0 |
| CVE-2018-25032 | madler/zlib | unsupported | — | — |
| CVE-2018-13785 | glennrp/libpng | proceed | **success** | 1.0 / 1.0 |
| CVE-2021-46822 | libjpeg-turbo/libjpeg-turbo | proceed | compile_failed | — |
| CVE-2022-23308 | GNOME/libxml2 | proceed | **success** | 1.0 / 1.0 |

Summary:

- Attempted: 5
- Success: 3
- Correctly gated as unsupported: 1
- Failed to compile within budget: 1
- Success rate over CVEs that passed feasibility: 3/4 = 75%

## Interpretation

- The feasibility gate prevented an unsuitable CVE (CVE-2018-25032) from producing a speculative query.
- Three generated queries were specific enough to hit the vulnerable revision and stay silent on the fixed revision.
- CVE-2021-46822 is a model/output-quality failure, not a validator failure: the loop rejected non-compiling queries.
- These numbers are not comparable to QLCoder's 176-CVE Java benchmark. The sample is tiny, the CWE mix is narrow, and the model/endpoint was sometimes unstable.

## Reproduce

```powershell
python main.py generate `
  --cve-id CVE-XXXXXXXX-XXXXX `
  --fix-commit <fix-sha> `
  --output-dir artifacts-bench `
  --build-mode none `
  --rag-db .cache/cve2checker/rag.sqlite `
  --max-iterations 3 `
  --max-tool-calls 12 `
  --no-lsp
```

Each run writes `state.json`, `generated-analysis/`, `generated-synthesis/`, and `final/`. Use `--resume` to retry only unfinished stages.
