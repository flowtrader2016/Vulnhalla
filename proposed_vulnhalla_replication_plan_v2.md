# Vulnhalla Replication Plan v2 (Corrected, Reproducible, and Validation-Driven)

Reference baseline:
- Local blog mirror: `blog_post.md`
- Original draft under review: `proposed_vulnhalla_replication_plan.txt`

This v2 plan is designed to replicate and exceed the quality bar of the CyberArk methodology by fixing query mapping ambiguity, enforcing reproducibility, and adding strict measurement/validation gates.

---

## 1. Objectives

Primary objective:
- Reproduce the blog’s methodology (CodeQL + guided-question LLM triage) with high scientific and operational rigor.

Secondary objective:
- Improve on reliability, reproducibility, and evaluator confidence (not just raw finding count).

Success criteria:
1. End-to-end run over at least 4 C/C++ repos with full artifacts and deterministic reruns.
2. Complete query/template coverage for the 14 issue categories.
3. Measured false-positive reduction with reviewer-validated sampling.
4. Cost and latency telemetry per query and per issue type.

---

## 2. Ground Truth from Blog (What Must Be Preserved)

From `blog_post.md`, the essential method is:
1. Run targeted CodeQL queries.
2. Pre-extract context entities (FunctionTree/Classes/Macros/Globals CSV) to avoid dynamic query latency.
3. Use issue-specific guided questions per finding class.
4. Let the LLM fetch additional code context via tools when needed.
5. Measure filtering outcome by issue type.

Important interpretation constraint:
- “Real issue” != “CVE-worthy exploitable vulnerability.” The blog explicitly separates these.

---

## 3. Current Repo State (As-Is)

Observed in this repo:
1. Issue query present: only `Copy function using source size`.
2. Issue template present: only `Copy function using source size.template`.
3. Generic fallback exists (`general.template`), which can hide template coverage gaps.
4. Query execution currently skips if both `FunctionTree.csv` and `issues.csv` exist (existence check only, no validity/hash check).

Implication:
- The current implementation can silently skip re-analysis after query changes and can silently use generic prompting for unmatched issue names.

---

## 4. Corrected Query Inventory (14 Categories)

The table below uses official CodeQL query-help IDs for the intended issue names. Some names in the blog correspond to legacy wording; ID is the canonical selector.

| # | Intended Issue Category | Canonical CodeQL ID (current docs) | Notes |
|---|---|---|---|
| 1 | Copy function using source size | `cpp/overflow-destination` | Already present in repo |
| 2 | Dangerous use of transformation after operation | `cpp/dangerous-use-of-transformation-after-operation` | Do **not** confuse with `cpp/dangerous-cin` |
| 3 | Incorrect return-value check for scanf-like function | `cpp/incorrectly-checked-scanf` | Stable |
| 4 | Missing return-value check for scanf-like function | `cpp/missing-check-scanf` | Stable |
| 5 | new[] array freed with delete | `cpp/new-array-delete-mismatch` | Stable |
| 6 | Not enough memory allocated for array of pointer type | `cpp/suspicious-allocation-size` | Prefer this over `cpp/allocation-too-small` for exact category |
| 7 | Operator precedence logic error | `cpp/operator-precedence-logic-error-when-use-bitwise-logical-operations` and `cpp/operator-precedence-logic-error-when-use-bool-type` | Current ecosystem split into two IDs |
| 8 | Pointer offset used before check | `cpp/late-negative-test` | Distinct from `cpp/offset-use-before-range-check` |
| 9 | Pointer to stack object used as return value | `cpp/return-stack-allocated-memory` | Query-help naming now often “Returning stack-allocated memory” |
| 10 | Potential double free | `cpp/double-free` | Stable |
| 11 | Potential use after free | `cpp/use-after-free` | Stable |
| 12 | Redundant/missing null check of parameter | `cpp/redundant-null-check-param` | Legacy names differ |
| 13 | Scanf function without specified length | `cpp/memory-unsafe-function-scan` | Replaces old phrasing/IDs |
| 14 | Unchecked return value used as offset | `cpp/missing-negativity-test` | Not `OffByOne.ql` |

### Query Path Policy (Critical)

Do **not** hardcode old repository paths in the plan.

Instead:
1. Resolve queries by `@id` from installed `codeql/cpp-all` pack.
2. Record resolved path + SHA256 into a local manifest.
3. Copy resolved `.ql` into `data/queries/cpp/issues/` only after ID/name verification.

This prevents path drift breakage across CodeQL releases.

Implementation constraint discovered during pilot execution:
4. Several upstream queries import helper modules from their original package directories (for example `ScanfChecks`). Copying only standalone `.ql` files into a flat folder can fail compilation.
5. For reproducible execution, either:
   - run queries from canonical installed pack paths resolved in the manifest, or
   - mirror required helper modules and directory layout, and include `codeql/cpp-queries` dependency in the local `qlpack.yml`.

---

## 5. Reproducibility Controls (Required Before Scaling)

### 5.1 Freeze analysis versions

Pin and record:
1. CodeQL CLI version.
2. `codeql/cpp-all` resolved version from lockfile.
3. LLM provider + exact model name.
4. Prompt template version hash.

Create artifact:
- `output/experiment_manifest.json` with version and hash metadata.

### 5.2 Remove floating dependency ambiguity

Current `qlpack.yml` uses `codeql/cpp-all: "*"`.

Plan:
1. Keep wildcard only for local development.
2. For experiment runs, generate and persist a lock snapshot (resolved versions) and refuse run if drift detected.

### 5.3 Deterministic cache invalidation

Current behavior skips on existence of `issues.csv` and `FunctionTree.csv`.

Required behavior:
1. Compute `issues_bundle_hash` from all issue `.ql` file hashes + query pack lock.
2. Compute `tools_bundle_hash` from all tool `.ql` file hashes + query pack lock.
3. Re-run issue analysis when `issues_bundle_hash` changes, regardless of file existence.
4. Re-run tool CSV generation only when `tools_bundle_hash` changes.
5. Validate non-empty output file checks (not just existence).

---

## 6. Template Engineering Standards

Goal:
- One dedicated template per query category (no accidental fallback).

### 6.1 Coverage requirements

1. Every query in section 4 must have a dedicated `.template`.
2. Filename must match the exact CodeQL issue `name` string produced in `issues.csv`.
3. Add CI/test to fail if any discovered `issue["name"]` has no exact template.

### 6.2 Prompt quality requirements

Each template must:
1. Force data-flow + control-flow reasoning.
2. Ask about exploitability, not pattern existence alone.
3. Include explicit “when this is NOT a bug” conditions.
4. Include concrete tool-usage guidance for missing context.

### 6.3 Avoid prompt drift

For each template, maintain:
1. `intent` note (why these questions exist).
2. 2-3 known true-positive examples.
3. 2-3 known false-positive examples.

Store in:
- `data/templates/cpp/notes/<template-name>.md` (new support files).

---

## 7. Execution Plan (Phased with Gates)

## Phase A: Asset Build + Verification

Tasks:
1. Build query manifest from canonical IDs in section 4.
2. Resolve and copy all required query files.
3. Add/create all templates for missing categories.
4. Add template coverage tests.

Exit gate:
- 100% manifest IDs resolved.
- 100% templates present for all discovered issue names in a dry-run corpus.

## Phase B: Runtime Hardening

Tasks:
1. Implement hash-based cache invalidation.
2. Add non-empty/valid CSV checks.
3. Parameterize CodeQL timeout (default experiment: 1200s).
4. Add per-query timing telemetry.

Exit gate:
- Re-running with unchanged hashes performs skips correctly.
- Any query set change triggers deterministic rerun.

## Phase C: Pilot Repos

Pilot targets:
1. `curl/curl`
2. `libuv/libuv`
3. `coinbase/cb-mpc`
4. `fireblocks/mpc-lib`

For each target:
1. Fresh DB fetch (or validated local DB).
2. Full query run.
3. LLM triage run with full telemetry capture.
4. Sampled human validation.

Exit gate:
- Stable rerun behavior.
- Measurable FP reduction and acceptable reviewer agreement.

## Phase D: Scale Batch

Tasks:
1. Add batch runner over vetted C/C++ subset from `codeql_targets.json`.
2. Enforce budget cap and automatic pause.
3. Export summary artifacts for each repo and each query type.

Exit gate:
- Complete runbook with reproducible outputs and clear confidence reporting.

---

## 8. Metrics and Validation Protocol

For each query category and repo:
1. Raw findings count.
2. Post-LLM findings count.
3. Reduction percentage.
4. True-positive precision estimate from sampled review.
5. “Potentially exploitable” proportion among confirmed real issues.
6. Mean/median query runtime.
7. Mean/median LLM rounds per issue.
8. Token and cost metrics (input/output separately).

### Sampling protocol

Use stratified sampling:
1. Sample from `1337`, `1007`, and `7331/3713` buckets.
2. Double-review sample with disagreement adjudication.
3. Publish confidence intervals, not single-point claims.

---

## 9. Cost Control Model

Current draft budget estimate is optimistic unless output tokens and multi-turn tool calls are modeled.

Required cost formula:
- `TotalCost = Σ_issue (PromptInTokens + ToolRoundInTokens + ToolRoundOutTokens + FinalOutTokens) * model_prices`

Controls:
1. Hard per-repo spend cap.
2. Hard global spend cap.
3. Stop/notify when cap threshold reached.
4. Persist per-issue cost ledger.

Outputs:
- `output/costs/<repo>.json`
- `output/costs/summary.json`

---

## 10. Deliverables

Required artifacts:
1. `query_manifest.json` (id, name, resolved path, sha256, pack version).
2. Template coverage report.
3. Runtime telemetry report (query + LLM).
4. Cost report.
5. Reviewer validation report.
6. Final replication summary with claims and confidence.

---

## 11. Immediate Implementation Backlog (Concrete Next Steps)

1. Create and validate `query_manifest.json` from the 14-category mapping above.
2. Add missing query files and templates.
3. Implement hash-based invalidation + non-empty CSV checks.
4. Add `--timeout` CLI override and set experiment default to 1200s.
5. Add per-issue token/cost logging in LLM analyzer.
6. Add coverage tests:
   - query manifest completeness
   - exact template match for all issue names encountered
   - cache invalidation behavior
7. Run pilot across the 4 targets.
8. Publish first benchmark pack (reduction + precision + cost + runtime).

---

## 12. Notes on Legacy Name Drift

Some blog labels map to renamed/split CodeQL IDs in current releases (for example operator precedence and scanf-length categories). The plan intentionally anchors to canonical IDs and derives filenames/metadata from real query outputs instead of static name assumptions.

That is the key change that makes this replication maintainable and trustworthy across CodeQL updates.
