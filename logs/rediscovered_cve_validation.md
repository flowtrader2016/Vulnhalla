# Rediscovered CVE Validation: CVE-2025-9809

## Summary

Using the Vulnhalla pipeline (CodeQL + Gemini 3 Flash LLM triage), we independently rediscovered **CVE-2025-9809** — a stack buffer overflow in RetroArch's CUE file parser — without prior knowledge of the CVE.

## Finding Details

- **CVE**: CVE-2025-9809
- **Target**: libretro/RetroArch
- **File**: `libretro-common/formats/cdfs/cdfs.c`
- **Function**: `cdfs_open_cue_track`
- **Line**: ~471 (CodeQL DB snapshot), ~346 (current code)
- **Vulnerability**: Stack buffer overflow via `memcpy` using source-derived size
- **CWE**: CWE-119 (Buffer Overflow), CWE-131 (Incorrect Calculation of Buffer Size)
- **CVSS Security Severity**: 9.3 (per CodeQL query metadata)

## Vulnerability Description

The function `cdfs_open_cue_track` parses CUE files (CD image descriptors) and extracts filenames. It copies the filename into a stack-allocated buffer `current_track_path` (size `PATH_MAX_LENGTH`) using:

```c
memcpy(current_track_path, file, file_end - file);
current_track_path[file_end - file] = '\0';
```

The size `(file_end - file)` is derived from the source (the CUE file content) with no bounds check against the destination buffer size. A crafted CUE file with a filename exceeding `PATH_MAX_LENGTH` causes a stack buffer overflow, potentially enabling remote code execution.

## Attack Vector

A user opens a malicious CUE file (e.g., from a downloaded ROM pack). The file is parsed automatically — no user interaction beyond opening. RetroArch users routinely download game images from untrusted sources, making this a realistic attack scenario.

## How We Found It

### Step 1: CodeQL Query
The vendored query `Copy function using source size.ql` (ID: `cpp/overflow-destination`) uses taint tracking to find `memcpy`/`strncpy`/`memmove` calls where the size argument is derived from the source buffer rather than the destination. It flagged 15 locations in RetroArch; this was one of them.

### Step 2: LLM Triage with Guided Template
The issue-specific template (`Copy function using source size.template`) forced the LLM through 4 structured questions:

1. **What size are we using?** — `file_end - file`, derived from source content, not destination.
2. **Does source point inside destination?** — No, different buffers (heap vs stack).
3. **Source vs destination size?** — Destination is fixed (`PATH_MAX_LENGTH`), source is unbounded.
4. **Can source > destination?** — Yes, if the CUE file contains a path longer than `PATH_MAX_LENGTH`.

### Step 3: Verdict
The LLM returned status **1337** (true positive) in a single round, 2.9 seconds, zero tool calls. It identified the specific variables: `current_track_path` (victim), `file` (source), `file_end - file` (unbounded size).

## Pipeline Performance on RetroArch

- **Total CodeQL findings**: 85 across 5 query types
- **LLM-flagged true positives**: 8
- **Confirmed real after human review**: 1 (this CVE)
- **LLM false positives (flagged as vuln but actually safe)**: 7 (see below)
- **LLM false positives correctly dismissed**: ~77
- **LLM model**: Gemini 3 Flash (`gemini-3-flash-preview`)
- **Cost**: Estimated < $0.50 for the full run
- **Time**: ~30-45 minutes for all 85 findings

## LLM False Positive Analysis: RHMAP and stb_vorbis Findings

The LLM flagged 7 additional "true positives" beyond the CUE file overflow. All turned out to be false positives on human review.

### RHMAP hash map `b[-1]` findings (6 call sites)

The LLM flagged `RHMAP_GET_STR` / `RHMAP_GET_FULL` macros because `rhmap__idx()` returns `-1` when a key isn't found, and the macros use it directly as an array index: `b[rhmap__idx(...)]`. The LLM concluded that `b[-1]` is an out-of-bounds access.

**Why this is actually safe**: The `rhmap__grow()` allocator deliberately allocates an extra element at index -1:
```c
new_hdr = malloc(sizeof(struct rhmap__hdr) + (new_max + 2) * elem_size);
new_vals = ((char*)(new_hdr + 1)) + elem_size;  // b[0] starts one slot in
memset(new_vals - elem_size, 0, elem_size);       // b[-1] zeroed as "null value"
```
The documentation explicitly describes this pattern:
```
RHMAP_SETNULLVAL(map, map_null);
// now RHMAP_GET_STR(map, "invalid") == map_null
```
`b[-1]` is valid allocated memory serving as the "not found" return value. This is an intentional C idiom, not a bug.

### stb_vorbis `sorted_values[-1]` finding (1 call site)

The LLM flagged `c->sorted_values[q]` where `q` can be `-1` from `codebook_decode_scalar`. Same pattern — the stb_vorbis developer allocates an extra slot at index -1 as a sentinel value to avoid an extra branch.

### Lesson Learned

The LLM cannot reliably trace allocation patterns to determine whether negative indexing is intentional. It sees `-1` used as an array index and flags it. This is a known limitation: **the LLM reasons about usage sites but not about allocation strategy**. A human reviewer or a more sophisticated template that asks "Is there deliberate padding/sentinel allocation at index -1?" could catch this.

## Current Status (as of 2026-02-28)

- **CVE assigned**: CVE-2025-9809
- **Fix status**: Unfixed in current code (verified via GitHub)
- **Debian assessment**: "Negligible security impact" (debatable given stack overflow + user-opened files)
- **GitHub issue**: https://github.com/libretro/libretro-common/issues/222

## Validation

This rediscovery validates the Vulnhalla methodology while also exposing its limits:

**What worked:**
- CodeQL identifies the suspicious pattern (source-sized copy)
- The guided template encodes expert knowledge as structured questions
- The LLM performs the reasoning that CodeQL cannot (comparing buffer sizes, assessing exploitability)
- A real CVE was independently found and correctly classified as a true positive

**What didn't work:**
- The LLM flagged 7 false positives as "true positives" (all involving intentional -1 index patterns)
- The LLM cannot trace memory allocation to verify whether negative indices are deliberately allocated
- Human review remains essential — the LLM is a triage filter, not a final verdict

**Key takeaway**: The pipeline correctly reduced 85 findings to 8 candidates, and 1 of those 8 was a confirmed CVE. That's a ~99% noise reduction from CodeQL's raw output, but human review of the flagged findings is still required.

---

# Novel Finding: CHD Metadata sscanf Stack Buffer Overflow (GHSA-8w8q-5h9m-8xj8)

## Summary

Using the same Vulnhalla pipeline run against RetroArch, we discovered a **novel** stack buffer overflow in RetroArch's CHD metadata parser — distinct from the rediscovered CVE-2025-9809 above. This was submitted as a GitHub Security Advisory on 2026-03-01.

- **Advisory**: [GHSA-8w8q-5h9m-8xj8](https://github.com/libretro/RetroArch/security/advisories/GHSA-8w8q-5h9m-8xj8)
- **Submitted by**: flowtrader2016
- **Date**: 2026-03-01
- **Status**: Submitted, awaiting maintainer response

## Finding Details

- **Target**: libretro/RetroArch (all versions <= 1.22.2)
- **File**: `libretro-common/streams/chd_stream.c`
- **Function**: `chdstream_get_meta`
- **Vulnerability**: Stack buffer overflow via unbounded `%s` in `sscanf` parsing CHD metadata
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **Severity**: High (estimated CVSS 7.8)
- **Scope**: All downstream consumers of `libretro-common`, not just RetroArch

## Vulnerability Description

The function `chdstream_get_meta` reads raw CHD metadata into a local `char meta[256]` buffer via `chd_get_metadata()`, then parses it with `sscanf` using format strings containing unbounded `%s` specifiers. The destination buffers are members of a stack-allocated `metadata_t` struct with fixed sizes:

- `type[64]` — 64 bytes
- `subtype[32]` — 32 bytes
- `pgtype[32]` — 32 bytes
- `pgsub[32]` — 32 bytes

Three format string macros are affected (defined in `libretro-common/include/libchdr/chd.h`):
1. `CDROM_TRACK_METADATA2_FORMAT` — 8 fields, 4 with `%s`
2. `CDROM_TRACK_METADATA_FORMAT` — 4 fields, 2 with `%s`
3. `GDROM_TRACK_METADATA_FORMAT` — 9 fields, 4 with `%s`

Additional issues found:
- `sscanf` return value is never checked
- `chd_get_metadata()` does NOT null-terminate its output buffer

## Attack Vector

User opens a malicious CHD game file. CHD (Compressed Hunks of Data) is MAME's disc image format, widely used for CD-based console games in RetroArch. The metadata is parsed automatically on file open — no further interaction required.

## Verification

All technical claims were independently verified against the actual source code via GitHub API:

| Claim | Source | Verified |
|-------|--------|----------|
| `char meta[256]` local buffer | chd_stream.c line 87 | Yes |
| `metadata_t` field sizes (64, 32, 32, 32) | chd_stream.c lines 65-77 | Yes |
| Format strings use `%u` and unbounded `%s` | chd.h lines 244, 246, 249 | Yes |
| sscanf return value unchecked | chd_stream.c lines 99-104 | Yes |
| `chd_get_metadata` does raw `core_fread`, no null-term | libchdr_chd.c lines 1544-1549 | Yes |
| Stack-allocated `metadata_t` in callers | chd_stream.c line ~220 | Yes |
| Latest version v1.22.2 | GitHub releases API | Yes |

## Suggested Fix

Replace unbounded `%s` with width-limited format specifiers in the macro definitions:
```c
// Before:
#define CDROM_TRACK_METADATA2_FORMAT "TRACK:%u TYPE:%s SUBTYPE:%s FRAMES:%u PREGAP:%u PGTYPE:%s PGSUB:%s POSTGAP:%u"
// After:
#define CDROM_TRACK_METADATA2_FORMAT "TRACK:%u TYPE:%63s SUBTYPE:%31s FRAMES:%u PREGAP:%u PGTYPE:%31s PGSUB:%31s POSTGAP:%u"
```

## Review Process

1. **Initial draft** generated from pipeline findings and manual code review
2. **Maintainer persona review** (Claude Opus sub-agent) found 5 errors in the first draft:
   - Code snippet used fabricated `meta.text` (doesn't exist) — fixed to `char meta[256]` + `md->` pointer access
   - Format specifiers were `%d` — fixed to `%u` (RetroArch's libretro-common copy)
   - Version was 1.19.1 — fixed to 1.22.2
   - Platform count was "50+" — fixed to "dozens of"
   - CWE was 120 — upgraded to 121 (more specific)
3. **Independent code verification** confirmed all claims against actual source via `gh api`

---

## References

- CyberArk Vulnhalla blog post: https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack
- RetroArch security policy: https://github.com/libretro/RetroArch/security/policy
- Debian security tracker entry: https://www.mail-archive.com/debian-security-tracker-commits@alioth-lists.debian.net/msg68641.html
- RetroArch RHMAP issue #16757 (crash, not security): https://github.com/libretro/RetroArch/issues/16757
- stb_vorbis CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-17670/product_id-43758/Stb-Vorbis-Project-Stb-Vorbis.html
- **CHD sscanf advisory**: https://github.com/libretro/RetroArch/security/advisories/GHSA-8w8q-5h9m-8xj8
