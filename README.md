# Vulnhalla (Fork)
# Automated CodeQL Analysis with LLM Classification

<div align="center">
  <img src="images/vulnhalla_logo.png" alt="Vulnhalla" width="400">
</div>

> **This is a fork of [cyberark/Vulnhalla](https://github.com/cyberark/Vulnhalla)** with expanded query coverage, issue-specific LLM templates, pipeline hardening, and token cost tracking. See [What This Fork Adds](#-what-this-fork-adds) for the full list of changes.

For the original research and motivation behind Vulnhalla, see the CyberArk blog post:
**[Vulnhalla: Picking the True Vulnerabilities from the CodeQL Haystack](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)**

---

## TL;DR (Repo Snapshot)

- This repo is a fork of CyberArk's Vulnhalla and keeps the same core idea: use an LLM to triage noisy CodeQL findings.
- The original upstream project shipped with one C/C++ issue query and mostly generic LLM prompting.
- This fork expands that to 14 C/C++ issue queries, with one issue-specific template per query plus shared `template.template` and `general.template` files.
- The pipeline flow is: fetch CodeQL DB (or use local DB) -> run tool + issue queries -> build structured prompts -> run LLM triage -> write results.
- LLM triage is tool-assisted (`get_function_code`, `get_caller_function`, `get_class`, `get_global_var`, `get_macro`) to request more code context when needed.
- Pipeline hardening was added: max 20 LLM rounds per issue, force-conclude after repeated failed tool calls, and soft pressure to conclude after many tool rounds.
- Fail-open behavior for robustness: per-issue LLM API failures are skipped so one timeout/rate-limit does not kill the full run.
- Cost visibility was added: input/output token usage is tracked per issue type and as a run total.
- Artifacts are persisted for review: timestamped run logs in `logs/` and per-finding `*_raw.json` / `*_final.json` under `output/results/c/<issue_type>/`.
- Current operational scope is C/C++ query packs and C-language pipeline mode (`lang=c` mapped to `data/queries/cpp`).

---

## How It Works

Vulnhalla automates the complete security analysis pipeline:

1. **Fetch** CodeQL databases from GitHub for a target repository
2. **Run** CodeQL queries to detect potential security issues
3. **Triage** each finding with an LLM using guided, issue-specific templates
4. **Classify** results as True Positive, False Positive, or Needs More Data

The key insight from CyberArk's research: CodeQL finds the patterns, but produces many false positives. By feeding each finding through an LLM with structured questions specific to each vulnerability class, the pipeline achieves up to 96% false positive reduction while retaining real vulnerabilities.

---

## What This Fork Adds

The original CyberArk repo shipped with **1 CodeQL query** and **1 generic LLM template**. This fork fills the gaps identified in their blog post and hardens the pipeline for real-world use.

### Expanded Query Coverage (1 &rarr; 14 queries)

13 additional C/C++ queries vendored from `codeql/cpp-queries@1.5.11`, covering:

| Category | Queries |
|----------|---------|
| **Memory safety** | Potential use after free, Potential double free, `new[]` freed with `delete`, Returning stack-allocated memory |
| **Buffer overflow** | Copy function using source size (original), Not enough memory allocated for array of pointer type |
| **Input validation** | Scanf without specified length, Missing/Incorrect return-value check for scanf-like functions |
| **Integer/offset bugs** | Unchecked return value used as offset, Pointer offset used before it is checked |
| **Logic errors** | Operator precedence with bitwise/logical operations, Redundant/missing null check of parameter |
| **Unsafe transforms** | Dangerous use of transformation after operation |

Each query comes with its required `.qll` helper modules. See [`data/queries/cpp/issues/VENDORING.md`](data/queries/cpp/issues/VENDORING.md) for how vendoring works and how to add more queries.

### Issue-Specific LLM Templates (1 &rarr; 14 templates)

The original repo had only a `general.template` with generic instructions. This fork adds **13 issue-specific templates** (one per new query) that encode expert knowledge as structured questions. For example, the "Copy function using source size" template forces the LLM through 4 targeted questions:

1. What size are we using? Source or destination?
2. Does source point inside destination?
3. What are the source and destination sizes?
4. Can source be bigger than destination?

This guided approach is what makes the LLM effective at distinguishing real vulnerabilities from false positives — it's the core of the Vulnhalla methodology that the original repo didn't ship templates for.

### Pipeline Hardening

- **Infinite loop prevention**: Hard limit of 20 LLM rounds per issue (was unbounded)
- **Consecutive failure detection**: After 3 failed tool calls in a row, forces the LLM to give its best answer instead of looping
- **Tool call cap**: After 6 tool call rounds, prompts the LLM to conclude
- **Auto-saved run logs**: Every pipeline run writes a timestamped log to `logs/`
- **Token usage tracking**: Per-issue-type and grand total token counts printed at pipeline end for cost visibility
- **LLM error resilience**: Individual issue LLM failures (timeouts, rate limits) are skipped instead of crashing the whole run

### Bounty Target List

`codeql_targets.json` currently contains 283 GitHub repositories across 52 bug bounty programs (HackerOne, Bugcrowd, Internet Bug Bounty, etc.) with their available CodeQL database languages. Use this to find targets to scan.

### Validated Findings

The pipeline has been validated against real targets:

- **CVE-2025-9809** (RetroArch): Independently rediscovered a stack buffer overflow in the CUE file parser — found by the pipeline without prior knowledge of the CVE
- **GHSA-8w8q-5h9m-8xj8** (RetroArch): Novel stack buffer overflow in CHD metadata parsing via unbounded `sscanf %s` — discovered and submitted as a new security advisory

Details in [`logs/rediscovered_cve_validation.md`](logs/rediscovered_cve_validation.md).

---

## Quick Start

### Prerequisites

- **Python 3.10 – 3.13** (3.11 or 3.12 recommended; 3.14+ not supported due to grpcio)
- **CodeQL CLI** — [download](https://github.com/github/codeql-cli-binaries/releases), ensure `codeql` is in your PATH
- **LLM API key** — one of the providers currently wired in this repo (`openai`, `azure`, `anthropic`, `gemini`, `bedrock`, `mistral`, `codestral`, `groq`, `openrouter`, `huggingface`, `cohere`, `vertex_ai`, `ollama`)
- **(Optional) GitHub token** — for higher rate limits when downloading databases
- **Current analysis scope** — C/C++ CodeQL query packs only (`lang=c` mode)

### Setup

```bash
git clone https://github.com/flowtrader2016/Vulnhalla
cd Vulnhalla
cp .env.example .env
# Edit .env with your provider, model, and API key

pipx install poetry    # if you don't have Poetry
poetry install
poetry run vulnhalla-setup
```

### Configure `.env`

```env
CODEQL_PATH=codeql
PROVIDER=gemini
MODEL=gemini-3-flash-preview
GOOGLE_API_KEY=your-key-here

# Optional
GITHUB_TOKEN=ghp_your_token_here
LOG_LEVEL=INFO
```

Supported providers in this fork: `openai`, `azure`, `anthropic`, `gemini`, `bedrock`, `mistral`, `codestral`, `groq`, `openrouter`, `huggingface`, `cohere`, `vertex_ai`, `ollama`. See [Configuration Reference](#configuration-reference) for provider-specific variables.

### Run

```bash
# Analyze a GitHub repository
poetry run vulnhalla redis/redis

# Re-download database even if it exists
poetry run vulnhalla redis/redis --force

# Use a local CodeQL database
poetry run vulnhalla --local /path/to/codeql-db
```

The pipeline will:
1. Fetch the CodeQL database (or use local)
2. Run all 14 C/C++ queries
3. Triage each finding with the LLM
4. Print per-issue verdicts and a summary with token usage
5. Save results to `output/results/`

### View Results

```bash
# Terminal UI for browsing results
poetry run vulnhalla-ui

# List analyzed repos and counts
poetry run vulnhalla-list

# Validate configuration
poetry run vulnhalla-validate
```

---

## User Interface

```bash
poetry run vulnhalla-ui
```

**Layout:**
- **Left panel**: Issues table (ID, Repo, Issue Name, File, LLM decision, Manual decision)
- **Right panel**: LLM reasoning, code context, metadata, manual verdict dropdown
- **Bottom bar**: Language indicator (C only), decision filter, action buttons

**Key bindings:** `Up/Down` navigate, `Enter` show details, `/` search, `[`/`]` resize panels, `r` reload, `q` quit.

---

## Output Structure

```
output/results/c/Copy_function_using_source_size/
  1_raw.json      # CodeQL issue data + prompt sent to LLM
  1_final.json    # Full LLM conversation + verdict
  2_raw.json
  2_final.json
  ...
```

**Status codes in LLM output:**
- `1337` = True Positive (security vulnerability)
- `1007` = False Positive (code is secure)
- `7331` = Needs more data
- `3713` = Likely safe but uncertain

---

## Configuration Reference

### Required Variables

| Variable | Description |
|----------|-------------|
| `CODEQL_PATH` | Path to CodeQL CLI. Defaults to `codeql` if in PATH |
| `PROVIDER` | LLM provider name |
| `MODEL` | Model name (e.g., `gpt-4o`, `gemini-3-flash-preview`) |

### Provider API Keys

| Provider | Variable |
|----------|----------|
| OpenAI | `OPENAI_API_KEY` |
| Gemini | `GOOGLE_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Mistral | `MISTRAL_API_KEY` |
| Groq | `GROQ_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |

### Azure OpenAI

| Variable | Description |
|----------|-------------|
| `AZURE_OPENAI_API_KEY` | API key |
| `AZURE_OPENAI_ENDPOINT` | Endpoint URL |
| `AZURE_OPENAI_API_VERSION` | API version (default: `2024-08-01-preview`) |

### AWS Bedrock

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_REGION_NAME` | Yes | AWS region |
| `AWS_PROFILE` | No* | Profile for SSO/credential file auth |
| `AWS_ACCESS_KEY_ID` | No* | Access key (if not using profile) |
| `AWS_SECRET_ACCESS_KEY` | No* | Secret key (if not using profile) |
| `AWS_SESSION_TOKEN` | No | For temporary STS credentials |

\* Use `AWS_PROFILE` **or** access key + secret key.

**Bedrock example:**
```env
PROVIDER=bedrock
MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_REGION_NAME=us-east-1
AWS_PROFILE=your-profile
```

> Bedrock models must support tool calling. Compatible: Claude 3.x, Mistral, Cohere Command R.

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | — | GitHub API token for higher rate limits |
| `GITHUB_API_URL` | `https://api.github.com` | For GitHub Enterprise |
| `GITHUB_SSL_VERIFY` | `true` | Set `false` for self-signed certs |
| `LLM_TEMPERATURE` | `0.2` | Keep low for deterministic analysis |
| `LLM_TOP_P` | `0.2` | Keep low for focused output |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_FILE` | — | Optional log file path |
| `LOG_FORMAT` | `default` | `default` or `json` |
| `THIRD_PARTY_LOG_LEVEL` | `ERROR` | Suppress LiteLLM/urllib3 noise |

---

## Adding New Queries

1. Find the query in `~/.codeql/packages/codeql/cpp-queries/<version>/`
2. Copy the `.ql` file to `data/queries/cpp/issues/`, named exactly as the `@name` metadata
3. Check for local imports — if present, copy the `.qll` helper too
4. Create a matching template in `data/templates/cpp/<exact @name>.template`
5. Verify: `codeql query compile "data/queries/cpp/issues/<name>.ql"`

See [`VENDORING.md`](data/queries/cpp/issues/VENDORING.md) for details.

---

## Development

```bash
# Run tests
poetry run pytest -v

# Type checking
poetry run mypy src
```

---

## License

Original work Copyright (c) 2025 CyberArk Software Ltd. Licensed under the Apache License, Version 2.0 — see [LICENSE.txt](LICENSE.txt).

Fork modifications by [flowtrader2016](https://github.com/flowtrader2016).
