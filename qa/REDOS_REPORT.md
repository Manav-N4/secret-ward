# ReDoS (catastrophic backtracking) check: secret-ward @ `e03dce0`

Date: 2026-11-27 · Python 3.9.6 (stock macOS `/usr/bin/python3`, clean env) · Script: `qa/redos_check.py`
Raw output: `qa/logs/redos_screen.log`, `qa/logs/redos.json` (git-ignored).

## Verdict
> **Update:** both patterns are fixed on `qa/fix-redos`, with output byte-identical. `TEXT_COND` keeps a quadratic residual. See "Fix applied" at the end.

**Two patterns are confirmed dangerous end to end.** A single short line in a hidden-set file can stall the run for tens of seconds. A few such lines would exceed the 900 s limit.

| Pattern | Shape | Worst measured |
|---|---|---|
| `TEXT_COND` (`conditions.py:17`) | super-cubic | one 330-character line: **49.6 s** |
| `AGE_PATTERNS[0]` (`detect.py:242`) | cubic | one 2,000-space padded field: **51.2 s** |

Both shapes are plausible in real exports. Hospital systems often produce fixed-width or padded text, such as `Diagnosis` followed by many spaces and then a long clause, or `Age` followed by many spaces. Neither occurs in the practice data, which is why every timing so far looked fine.

Another 12 patterns are quadratic. They only become slow on runs of several thousand characters, so the risk from them is low. The remaining 97 timed patterns are fast: every one stays under 17 ms on every adversarial input at 2,000 characters.

## How the test works
- **Inventory.** The script finds every `re.*` call in `src/secretward/*.py` with the AST: 118 call sites, of which 113 are timed. Module-level patterns are timed as the **real compiled objects imported from the engine**, so the rule lists from `config/rules/` are included. The 5 patterns built per input at run time are listed but not timed (see the end).
- **Screen.** Each pattern is run against 88 adversarial inputs of about 2,000 characters:
  - long runs of spaces or newlines;
  - word, capital-letter, digit, `1-`, `a-`, `a.`, Devanagari and base64-like runs, each ending in a character that breaks the match;
  - 35 trigger keywords (`age`, `diagnosis`, `s/o`, `pin`, `house no`, ...), each followed by a long whitespace run with and without trailing text.
- **Timeout and fit.** Each pattern runs in a forked child that is killed if one call takes more than 2 s. Anything over 20 ms is re-timed at 1k / 2k / 4k / 8k characters to fit the exponent k in t ∝ N^k.
- **End to end.** The two patterns that hit the timeout were re-run as the full `main.py` pipeline on one-file inputs, with a 120–180 s kill.

## Results

| # | Pattern (source) | Risk shape | Adversarial input | Time | Exponent | End-to-end (whole pipeline, 1 file) | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | `TEXT_COND` `conditions.py:17`<br>`(?:diagnosis\|…)\s*[:\-]?\s*([^\n;]{4,80}?)\s*(?:\(ICD\))?\s*(?:[;\n.]\|$)` | The same whitespace run can be split between `\s*`, `\s*`, the lazy capture (which also accepts spaces) and the trailing `\s*` `\s*`. That gives polynomially many ways to fail. | `"Diagnosis"` + N spaces + a 112-char clause with no `.` or `;` | N=50: 64 ms<br>N=100: 1.7 s<br>N=150: 13.1 s<br>N=200: >30 s (killed) | ≈ 5 | No colon: **2.0 s / 13.0 s / 49.6 s** at 100 / 150 / 200 spaces<br>With `Diagnosis:`: 0.2 s / 0.5 s at 100 / 150 | **DANGEROUS** |
| 2 | `AGE_PATTERNS[0]` `detect.py:242`<br>`(\bage(?:d)?\s*(?:/\s*sex)?\s*[:\-]?\s*)(\d{1,3})` | Three `\s*` runs separated only by optional tokens, so there are O(N³) ways to split a whitespace run before the required digit fails. | `"Age"` + N spaces (or newlines) + `": not recorded"` | N=400: 218 ms<br>N=800: 1.7 s<br>N=1600: 13.2 s | 3.0 | txt: **6.8 s** (1,000 spaces), **51.2 s** (2,000)<br>CSV cell: **6.8 s** (1,000) | **DANGEROUS** |
| 3 | `REL_RX` `detect.py:309` | `\.?\s*[:\-]?\s*` | `"s/o"` + 2,000 spaces | 172 ms | 2.0 | `"S/o"` + 8,000 spaces: 8.5 s | quadratic, low (needs 1,000s of spaces) |
| 4 | `TRIG_RX` `detect.py:310` | `\s*[:\-]?\s*(?:\(\s*)?` | `"relative"` + 2,000 spaces | 103 ms | 2.0 | – | quadratic, low |
| 5 | `ADDR_LINE` `detect.py:265` | `(?m)^\s*`: every blank line starts a new `\s*` scan | 2,000 newlines | 98 ms | 2.0 | – | quadratic, low |
| 6 | `DISTRICT` `detect.py:266` | `\s*[:\-]?\s*` | `"distt"` + spaces | 72 ms | 2.0 | – | quadratic, low |
| 7 | `DEVA_RUN` `detect.py:341` | `[ऀ-ॿ]+(?:\s+[ऀ-ॿ]+)+`, unanchored | one 2,000-char Devanagari word | 66 ms | 2.0 | – | quadratic, low (unrealistic input) |
| 8 | `ID_TOKEN` `detect.py:154` | `(?:[-/][A-Za-z]{1,4})*…(?:\d{1,4}[-/])*` | `"a-"` × 1,000 | 65 ms | 2.0 | – | quadratic, low |
| 9 | `ADDR_PARTS` `detect.py:268` | `(?:\s*no\.?)?\s*[:\-]?\s*` | `"h.no"` + spaces | 46 ms | 2.0 | – | quadratic, low |
| 10 | PIN `re.sub` `detect.py:300` | `(?:\s*code)?\s*[:\-]?\s*` | `"pin"` + spaces | 44 ms | 2.0 | – | quadratic, low |
| 11 | `AGE_PATTERNS[1]`, `[2]` `detect.py:243-244` | `\s*[:\-]?\s*` | `"umar"` / `"आयु"` + spaces | 38–39 ms | 2.0 | – | quadratic, low |
| 12 | `LOG_LINE` `detect.py:318`, `LOW_REL_RX` `detect.py:334` | `(?m)^\s*…`, `\s*[:\-]?\s*` | newlines; `"son of"` + spaces | 32 ms | 1.8–2.0 | – | quadratic, low |
| 13 | `EMAIL` `detect.py:152` | Unanchored `[\w.+-]+@`: each start rescans the run | 2,000 digits | 20 ms | 2.0 | – | quadratic, low |
| 14 | `WORDLIKE`, `NUM` `ner.py:24-25` | – | digit run | 26 ms in scan mode | 2.0 | – | **safe**. The engine only calls them with `.match()` on single tokens, so the quadratic result is a scan-mode artifact. |
| 15 | the other 97 timed patterns | Includes 10 the static check flagged, which turned out bounded or anchored | all 88 inputs | ≤ 17 ms worst | – | – | **safe** |

**Not timed:** `gazetteer.py:117/118/120/131` and `conditions.py:74`. These are built per input from the name, place and rare-condition lists.
- The gazetteer `word`/`gap` patterns are only matched against short gazetteer entries.
- `rx_other` and the rare-condition pattern are alternations of `re.escape`d literals bounded by lookarounds. That makes them linear per start position, not a backtracking shape. This alternation is the small residual cost already seen in the scaling test.

## Why it matters
- `sanitize()` gets a whole text file as one string, and normalisation does not collapse whitespace. So padding anywhere in a note reaches every pattern.
- `TEXT_COND` runs in `_rare_conditions()` (`pipeline.py:379`) on **every** text file and every CSV/JSON text value, even with `rare_condition_max_patients: 0`.
- For text files it runs **once per unit**, rescanning the whole file each time (`pipeline.py:384-387`), so the cost above is multiplied by the number of records in that file.

## Fix applied (branch `qa/fix-redos`): only the two dangerous patterns
Each change makes every whitespace run belong to exactly one quantifier, so a run can no longer be split between several quantifiers. Python 3.9 has no atomic groups or possessive quantifiers (they arrived in 3.11), so the patterns were restructured instead:

- **`AGE_PATTERNS[0]`:** `\s*(?:/\s*sex)?\s*[:\-]?\s*` → `\s*(?:/\s*sex\s*)?(?:[:\-]\s*)?`
- **`TEXT_COND` prefix:** `\s*[:\-]?\s*` → `\s*(?:[:\-]\s*)?`
- **`TEXT_COND` trailing part:** `\s*(?:\(ICD\))?\s*` → `\s*(?:\(ICD\)\s*)?`

Why the matches can't change:
- Each rewrite accepts the same set of strings, because two whitespace runs in a row (`\s*\s*`) match exactly what one `\s*` matches.
- The engine tries the possible end positions in the same order, so it picks the same first match.
- The lazy capture and its 4–80 bounds are untouched.

Deliberately **not** done, because it would change what matches:
- **Making the capture start on a non-space character.** The original pattern relies on a capture starting inside the whitespace to match short conditions like `Dx: TB.` (it captures `" TB."`).
- **Collapsing whitespace before detection.** It would change output bytes.
- **Touching the 12 low-risk quadratic patterns.**

### Verification (Python 3.9.6, clean env)
1. **Speed, on the same adversarial inputs:**

   | Case | Before | After |
   |---|---|---|
   | `AGE`, regex alone, 2,000 spaces | killed at 2 s | 0.18 ms (20,000 spaces: 1.9 ms) |
   | `TEXT_COND`, regex alone, 200 spaces + clause | over 30 s | 48 ms |
   | Full pipeline: `age2000` | 51.2 s | 0.12 s |
   | Full pipeline: `csv_age1000` | 6.8 s | 0.12 s |
   | Full pipeline: `diagNC200` | 49.6 s | 0.16 s |
   | Full pipeline: `diagNC150` | 13.0 s | 0.14 s |

   Every pipeline output was identical to the pre-fix run.
   - **Residual risk:** `TEXT_COND` is still quadratic, at 1.6 s for 1,000 spaces and 6.5 s for 2,000. The screen therefore still flags it at N = 2,000, alongside the 12 low-risk ones. It was roughly N⁵ before.
2. **Dev set:** `sanitized/`, `records.jsonl`, `quarantine/` and stdout are byte-identical to `e03dce0`. `report.json` is identical apart from timing and resources. check_dev: 0/3230 leaked, 0/4 canaries, 4826/4855 medical kept, linking 1.00/1.00.
3. **Mutated and scale sets:** all byte-identical to `e03dce0`. These are the 8 mutated sets in `qa/mutated/` (`headers`, `dates`, `names`, `all`, `all_v2`, `v3_csvonly`, `v3_textjson`, `v3_full`) and the 1,000 and 4,000-file distinct-people sets.
4. **Differential test, old vs new compiled patterns:**
   - 306,000 random strings built from the patterns' own tokens (keywords, `:`, `-`, `;`, `.`, ICD codes, spaces, tabs, newlines, digits), checking `finditer` spans and every group: **0 mismatches**.
   - Real data: 2,124 `TEXT_COND` and 349 `AGE` matches across the dev and mutated inputs, all identical.
