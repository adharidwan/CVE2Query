# CVE2Query — Penjelasan dan Script Demo

## 1. Pitch

**CVE2Query** mengubah satu CVE C/C++ menjadi custom **CodeQL query**, lalu membuktikan query tersebut mendeteksi versi vulnerable dan tidak mendeteksi versi fixed.

Masalah yang diselesaikan: CVE dan patch tersedia, tetapi menulis query CodeQL yang tepat tetap sulit dan membutuhkan ahli security serta program analysis. Pipeline ini mengotomatisasi bagian tersebut dengan LLM, tetapi keputusan akhir tetap ditentukan oleh **validator deterministik**.

Referensi: **QLCoder** (arXiv:2511.08462).

---

## 2. Arsitektur

```text
CVE ID
  │
  ▼
CVE record
  │
  ▼
Source discovery ──► repo, vulnerable commit, fix commit, diff, context
  │
  ▼
Feasibility Agent ──► proceed / insufficient_evidence / unsupported
  │
  ▼
Root Cause Agent ──► vulnerability_ir.json
  │                    source, sink, sanitizer, taint steps, citations
  ▼
Synthesis Agent ◄──► RAG (docs/examples), CodeQL LSP, read-only repo
  │
  ▼
Validator deterministik
  compile → vulnerable DB → fixed DB → SARIF → diff intersection
  │
  ├── success
  └── failure → feedback → repair (maks. 10 iterasi)
  │
  ▼
final query + validation report + manifest + report
```

### Success predicate

Query sukses jika:

1. Query compile.
2. Ada alert di vulnerable database yang lokasinya beririsan dengan changed lines.
3. Tidak ada alert di fixed database yang beririsan dengan changed lines.

Mode `--strict-fixed` memperketat: alert fixed apa pun dianggap gagal.

---

## 3. Struktur repo

```text
cve2checker/
  cve.py           CVE v5 fetch/cache
  source.py        GitHub reference parsing + fix commit discovery
  git_tools.py     clone, checkout, worktree, diff
  diff.py          unified diff → changed line ranges
  context.py       hunk/function context
  evidence.py      artifact evidence
  rag.py           SQLite FTS5 retrieval
  rag_index.py     index docs/examples
  lsp.py           CodeQL Language Server client
  llm.py           OpenAI-compatible client + retry/fallback
  schemas.py       feasibility + vulnerability IR contracts
  prompts.py       prompt templates + response parsers
  agents.py        feasibility + root-cause agents
  codeql.py        CodeQL CLI wrappers + query pack
  sarif.py         SARIF 2.1.0 parser
  validator.py     compile/analyze/score + feedback
  synthesis.py     synthesis + repair loop + tools
  report.py        manifest + Markdown report
  cli.py           CLI + checkpointed `generate`
codeql-pack/       baseline query pack
examples/          validated CVE examples
benchmarks/        5-CVE pilot results
tests/             190 tests
```

---

## 4. Alur end-to-end

### 4.1 CVE ingestion
`add` mengambil CVE v5 record dan menulis spec awal `insufficient_evidence`.

### 4.2 Source discovery
`evidence` mencari referensi GitHub:
- commit fix langsung,
- pull request (butuh GitHub token),
- atau `--fix-commit` manual.

Output: `source.json`, `diff.patch`, `context.json`.

### 4.3 CodeQL database
Dua database dibuat:
- vulnerable = parent commit,
- fixed = fix commit.

Mode: `autobuild`, `none`, atau `--build-command`.

### 4.4 Feasibility Agent
LLM memutuskan `proceed`, `insufficient_evidence`, atau `unsupported`. Input mencakup diff asli dan build evidence.

### 4.5 Root Cause Agent
LLM menghasilkan Vulnerability IR: source, sink, sanitizer, additional taint steps, precondition, dan diff location. Semua komponen wajib punya sitasi `file`, `line`, `commit`, `snippet`. Commit dibatasi ke vulnerable/fix commit.

### 4.6 Synthesis Agent
Agent menulis query dengan tools:
- RAG: dokumentasi dan contoh CodeQL,
- LSP: diagnostics, hover, definition, completion,
- read-only repo: baca file, list dir, search text.

Query ditulis ke CodeQL pack yang otomatis dibuat.

### 4.7 Validator
Compile query, jalankan di dua database, parse SARIF, dan cek irisan lokasi alert dengan changed lines. Hasilnya menjadi feedback untuk repair.

### 4.8 Orchestrator
`generate` menjalankan semua stage, menyimpan checkpoint `state.json`, dan mendukung `--resume`.

---

## 5. Studi kasus: CVE-2022-37434 (zlib)

Root cause di `inflate.c`:

```c
len = state->head->extra_len - state->length;
zmemcpy(state->head->extra + len, next,
        len + copy > state->head->extra_max ?
        state->head->extra_max - len : copy);
```

Jika `len >= extra_max`:
- `extra + len` keluar batas,
- `extra_max - len` bisa underflow.

Fix menambahkan:

```c
len < state->head->extra_max
```

Hasil pipeline:

| Item | Hasil |
|---|---|
| Vulnerable | 1 alert, 1 intersect diff |
| Fixed | 0 alert |
| Precision | 1.0 |
| F1 | 1.0 |
| Iterasi | 1 |

Query final:
`examples/CVE-2022-37434/CVE-2022-37434.ql`

---

## 6. Pilot benchmark 5 CVE

| CVE | Repo | Feasibility | Synthesis | Precision/F1 |
|---|---|---|---|---|
| CVE-2022-37434 | zlib | proceed | success | 1.0 / 1.0 |
| CVE-2018-25032 | zlib | unsupported | — | — |
| CVE-2018-13785 | libpng | proceed | success | 1.0 / 1.0 |
| CVE-2021-46822 | libjpeg-turbo | proceed | compile_failed | — |
| CVE-2022-23308 | libxml2 | proceed | success | 1.0 / 1.0 |

Ringkasan:
- 5 CVE dicoba.
- 3 sukses.
- 1 benar-benar di-gate sebagai `unsupported`.
- 1 gagal compile dalam batas 3 iterasi.
- Success rate untuk CVE yang lolos feasibility: 3/4 (75%).

Catatan: ini pilot benchmark, bukan evaluasi statistik. Model/endpoint sempat tidak stabil dan jumlah CVE sangat kecil.

Detail: `benchmarks/README.md` dan `benchmarks/cve5-results.json`.

---

## 7. Demo 10–12 menit

### Persiapan

```powershell
cd D:\Kuliah\CVE2Checker
python main.py config show
python -m unittest discover -s tests -q
```

Pastikan `key_present: True` dan tests lulus.

Buka:
- `examples/CVE-2022-37434/CVE-2022-37434.ql`
- `examples/CVE-2022-37434/validation_report.json`
- `artifacts-demo/generated-full/CVE-2022-37434/final/report.md`

### Urutan demo

**0. Pembuka (1 menit)**
- CVE banyak, query CodeQL sulit ditulis.
- Solusi: CVE → query otomatis + validasi deterministik.

**1. Arsitektur (2 menit)**
- Tunjukkan diagram.
- Tekankan: LLM mengusulkan, validator yang memutuskan.

**2. Evidence CVE (2 menit)**

```powershell
Get-Content artifacts-demo\generated-full\CVE-2022-37434\diff.patch
Get-Content artifacts-demo\generated-full\CVE-2022-37434\generated-analysis\vulnerability_ir.json
```

Jelaskan root cause zlib dan sitasi.

**3. Validasi live (2 menit)**

```powershell
python main.py validate `
  --query "artifacts-demo\generated-full\CVE-2022-37434\generated-synthesis\iterations\001\CVE-2022-37434-query-iter-1.ql" `
  --vuln-db "artifacts-demo\generated-full\CVE-2022-37434\generated-db\vulnerable" `
  --fixed-db "artifacts-demo\generated-full\CVE-2022-37434\generated-db\fixed" `
  --diff "artifacts-demo\generated-full\CVE-2022-37434\diff.patch" `
  --output-dir "artifacts-demo\generated-full\CVE-2022-37434\demo-validation" `
  --json
```

Tunjukkan verdict `success`, precision 1.0, F1 1.0.

**4. Query generated (2 menit)**
Buka `examples/CVE-2022-37434/CVE-2022-37434.ql`.
Jelaskan:
- source `extra_len`,
- sink `extra` pada memcpy,
- `offsetIsChecked` untuk `len < extra_max`.

**5. Orchestrator (1 menit)**

```powershell
python main.py generate `
  --cve-id CVE-2022-37434 `
  --cve-file .cache/cve2checker/CVE-2022-37434.json `
  --repo-path artifacts-demo/CVE-2022-37434/repo `
  --fix-commit eff308af425b67093bab25f80f1ae950166bece1 `
  --output-dir artifacts-demo/generated-full `
  --build-mode none `
  --rag-db .cache/cve2checker/rag.sqlite `
  --max-iterations 3 --max-tool-calls 12 --no-lsp --resume
```

Demo ini menggunakan `--resume` pada run yang sudah sukses, jadi cepat dan tidak memanggil LLM.

**6. Penutup (1 menit)**
- 3 query sukses dari 4 CVE yang lolos feasibility.
- Limitasi: model reliability, benchmark kecil, C/C++ only.

---

## 8. Kemungkinan pertanyaan dosen

**Ini menggantikan CodeQL?**
Tidak. Ini menghasilkan query; eksekusi dan analisis tetap CodeQL.

**Kenapa CodeQL, bukan CSA?**
Query lebih mudah di-generate LLM, library dataflow/taint sudah tersedia, dan tidak perlu compile plugin C++ ke LLVM.

**Kenapa tidak pakai query bawaan?**
Query bawaan general; coverage dan precision terbatas. Query per CVE lebih spesifik.

**Bagaimana mencegah hallucination?**
Evidence gate, IR wajib sitasi, commit dibatasi, schema validation, dan validator deterministik.

**Apakah query bisa dipakai ke repo lain?**
Bisa untuk repo C/C++ dengan pola serupa, tetapi query ini CVE-specific.

**Sudah dievaluasi banyak CVE?**
Belum. Ini pilot 5 CVE + 190 tests. Benchmark multi-CVE adalah future work.

**Apa kontribusinya?**
Adaptasi QLCoder ke C/C++, evidence-gated IR, validator diff-aware, checkpointed orchestrator, dan dukungan variasi tool-call model.

---

## 9. Limitasi

- Model reliability: output bisa bervariasi, endpoint bisa 503/timeout.
- Pilot benchmark hanya 5 CVE; belum ada held-out evaluation.
- Masih C/C++ saja.
- AST extraction masih heuristic (brace matching), bukan AST penuh.
- Orchestrator sequential, bukan LangGraph.
- Query generated bisa overfit ke CVE tertentu.
- Lisensi CodeQL tetap berlaku.

---

## 10. Checklist sebelum demo

- [ ] `python main.py config show` → `key_present: True`.
- [ ] `python -m unittest discover -s tests -q` → lulus.
- [ ] Buka `examples/CVE-2022-37434/`.
- [ ] Siapkan terminal di root repo.
- [ ] Jangan tampilkan `.env` atau API key.
- [ ] Gunakan `validate` live dan `generate --resume`; hindari fresh `generate` saat demo.
- [ ] Siapkan artifact cadangan jika endpoint LLM mati.
