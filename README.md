# secret-ward

An offline, CPU-only, LLM-free privacy firewall for multilingual (English, Hindi, Hinglish)
hospital records. Built for Yugaantar DevForge, Track 3 "Secret Wards".

## Setup and run

**Requires Python 3.9 or newer** (tested on 3.9, 3.11, 3.12 and 3.13 with identical results).
Use `python3`: many machines have no bare `python`.

```bash
python3 -m pip install -r requirements.txt     # installs nothing: standard library only
RAKSHA_SECRET=<secret> python3 main.py --input <input dir> --output <empty output dir>
```

**Fails loudly, never silently:** exit code 2 if Python is older than 3.9; exit code 3 if
most files fail inside our own code (instead of quarantining everything and reporting success).

No network access is used at run time. Standard library only: no third-party packages (Devanagari transliteration is built in, `src/secretward/translit.py`).

**Models declared:** none. No LLMs, no generative models, no pretrained transformers.
Detection is rules + runtime gazetteers + a rule-based transliteration phonetic key.

## Architecture

```
input/ ──► read + decode (BOM, UTF-16, cp1252) ──► quarantine anything unparseable
              │
              ▼
   PASS 1  harvest: classify every CSV column / JSON key by header hints AND value shape,
           learn names, relatives, villages, ID numbers, PINs, districts from THIS input
              │
              ▼
   LINK    union-find on strong keys (hospital IDs, phone, Aadhaar, ABHA) with
           merge blockers (gender, age > 3 y apart, no shared sound-alike name token);
           name-only records join only if exactly one cluster fits
              │
              ▼
   PASS 2  sanitize every value: normalise → protect doctors/ASHA → base64 →
           IDs → phones/Aadhaar/ABHA → DOB removed, dates shifted per patient →
           ages → 10-year bands → addresses → district + PIN prefix → names
           (labels, relatives, triggers, honorifics, gazetteer, cross-script, phone proximity)
              │
              ▼
   WRITE   sanitized/ (same paths, formats, headers; PII file names renamed),
           records.jsonl (pseudonym also written INSIDE each record), honest report.json
```

| Module | Job |
|---|---|
| `src/secretward/normalize.py` | mirrors the scorer: NFKC, zero-width removal, homoglyph folding, Devanagari digits |
| `src/secretward/rules.py` + `config/rules/*.txt` | all labels, relations, honorifics, triggers, safe words, header hints as editable data |
| `src/secretward/fields.py` | column/key semantics (hints + value shape) and per-type cleaning |
| `src/secretward/gazetteer.py` | runtime name/place/ID gazetteer, cross-script skeleton key |
| `src/secretward/translit.py` | built-in Devanagari to Latin transliteration (no dependency) |
| `src/secretward/detect.py` | free-text sanitizer (layers listed above) |
| `src/secretward/dates.py` | date finding/shifting in any format; DD/MM vs MM/DD voting per file and hospital ID prefix |
| `src/secretward/link.py` | patient clustering with merge blockers |
| `src/secretward/privacy.py` | HMAC pseudonyms, per-patient non-zero shifts, age bands, PIN prefix |
| `src/secretward/pipeline.py` | orchestration, JSON/CSV/text handlers, quarantine, file renaming |

## Privacy design (policy in `config/policy.yaml`)

* **Pseudonyms:** `PSN-` + HMAC-SHA256(RAKSHA_SECRET, cluster key). Not reversible, changes with the secret.
* **Dates:** every date of one patient shifts by the same secret non-zero offset (±180 days),
  so intervals and stay lengths are exact while a global un-shift is impossible.
* **Ages:** 10-year bands. On the practice registry, gender + 5-year band + district leaves
  101/240 people unique; 10-year bands leave 50/240. DOB is removed (it would reveal the exact age).
* **One band per patient:** every record of a linked patient gets the SAME truthful band (a
  10-year window containing all their stated ages). Per-record bands let an attacker who pools
  "40-49" and "50-59" learn the age is 49-50.
* **Local k-anonymity:** patients whose (gender, band, district) group in the release has fewer
  than `min_group_size` patients get a 20-year band; if still alone, district and PIN prefix are
  hidden too. Only those patients are coarsened; everyone else keeps full detail.
* **Location:** house, mohalla, village, tehsil removed; district kept; PIN reduced to 3 digits
  (adds no identifying power beyond district on the practice data).
* **Replacements:** typed placeholders (`[NAME]`, `[PHONE]` …), never fake names (a fake name can
  collide with a real person and count as a leak).

## Security design

* No intermediate data is written to disk: everything stays in memory, so there is nothing to encrypt at rest.
* The secret is read from the environment only and never printed or stored.
* stdout prints counts only; a custom exception hook prints only the exception type (Python error
  messages can contain record values); quarantine reasons are fixed codes.
* Village/locality columns are recognised by their **values** (place-name morphology such as
  -pur, -ganj, Kalan, Khurd, plus places learned from other files), not only by header name.
* Files we cannot parse safely (corrupt, truncated, too deeply nested, wrong format, binary, PDF, images, XML)
  are quarantined, never copied.

## Dev tools (practice data only, never run on hidden data)

| Script | What it measures |
|---|---|
| `bash scripts/check_all.sh [kit] [--full]` | the whole routine: pipeline, contract, self-check, traps, attacker, (held-out), submission check |
| `scripts/attack.py` | our re-implementation of attacks A3-A5 from the kit's ATTACKS.md, ours vs raw |
| `scripts/heldout.py` | leaks when name sources are removed (no registration tables, free text only) |
| `scripts/lost_probes.py`, `scripts/link_misses.py` | which medical values we lost, which links we missed |

## Measured on the practice data (`check_dev.py`)

| Metric | Starter | secret-ward v0.1 |
|---|---|---|
| PII pieces leaked | 2718 / 3230 (84.1%) | 0 / 3230 |
| Canaries found | 4 / 4 | 0 / 4 |
| Medical values kept | 4855 / 4855 | 4855 / 4855 |
| Linking precision / recall | 0 / 0 | 1.00 / 0.82 |
| Runtime | ~2 s | ~2 s |

Privacy, measured with `scripts/attack.py` (our approximation of the official arena; lower is better):

| Attack | Raw input | v0.1 | v0.2 (one band per patient + local k-anonymity) |
|---|---|---|---|
| A3 record linkage, mean probability on the true person | 0.670 | 0.086 | 0.039 |
| A4 patients re-identified after pooling (confidence >= 0.5) | 93.8% | 37.5% | 6.2% |
| A5 targeted attack success | 100% | 51.4% | 49.0% |

Held-out (`scripts/heldout.py`): without registration tables 3 / 2263 PII leaked; free text only 0 / 569.

## Known limitations

* Tuned and measured on the practice data so far; the unseen-format round will expose gaps.
* Free-text names with no label, honorific, relation marker, trigger or gazetteer match are missed.
* Cross-script matching uses a coarse phonetic skeleton; rare spellings can slip.
* XML/PDF/image files are quarantined rather than cleaned.
* Rare-diagnosis records are not yet coarsened further (planned); A5 (targeted attack) is our weakest privacy number.
* With only ~50 patients per release, local k-anonymity coarsens many patients; on larger releases fewer will be affected.
