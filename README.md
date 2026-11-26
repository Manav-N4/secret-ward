# secret-ward

An offline, CPU-only, LLM-free privacy firewall for multilingual (English, Hindi, Hinglish)
hospital records. Built for Yugaantar DevForge, Track 3 "Secret Wards".

## Setup and run

**Requires Python 3.9 or newer** (tested on 3.9, 3.11, 3.12 and 3.13 with identical results).
Use `python3`: many machines have no bare `python`.

```bash
python3 -m pip install -r requirements.txt     # one optional package: cryptography (quarantine vault)
RAKSHA_SECRET=<secret> python3 main.py --input <input dir> --output <empty output dir>
```

**Fails loudly, never silently:** exit code 2 if Python is older than 3.9; exit code 3 if
most files fail inside our own code (instead of quarantining everything and reporting success).

No network access is used at run time. The pipeline itself is standard library only (Devanagari transliteration is built in, `src/secretward/translit.py`). The one package, `cryptography`, only encrypts quarantined files; if it is missing the run still succeeds and quarantined files are simply not kept.

**Models declared:** one small classical-ML model **we trained ourselves**: an averaged-perceptron
name classifier (`src/secretward/ner.py`, about 600 weights in `src/secretward/ner_weights.json`,
retrain with `python3 scripts/train_ner.py --kit <toolkit>`). Trained on synthetic sentences we
generated (`scripts/nocue_data.py`, train split) plus the practice free text labelled by its answer key.
It never sees the identity of the word it judges (only shape, endings and neighbouring words), so it
cannot memorise names. No LLMs, no generative models, no pretrained models of any size.
Switch it off with `ner_enabled: 0` in `config/policy.yaml`.

**How the detectors combine:** column rules and the runtime gazetteer handle structured data; context
rules (labels, relations, honorifics, triggers, log lines) handle names with cues; the classifier runs
last, only on sentences of 6+ words, only on standalone Title-case words, and never on drug stems,
medical suffixes, clinical or calendar words (`config/rules/medical_stems.txt`, `medical_words.txt`).

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
| `src/secretward/vault.py` | encrypted quarantine vault (AES-256-GCM, per-file keys) |

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
* **Rare conditions (A5 defence, measured, shipped off):** `src/secretward/conditions.py` can generalise
  diagnoses seen in very few patients to their ICD-10 chapter (`rare_condition_max_patients`). On the
  practice data it cost 2.1-6.1% of medical values (N=1..5) and did not lower the targeted attack:
  the attacker wins through common conditions combined with profile consistency and the exact length of
  stay, which the rules require us to keep. Re-measured after the linking fix, N = 1..5: A5 stays at
  0.486 while medical values fall to 97.9-93.9% (after the fragment-guard fix). QA's independently built
  attacker agrees: A5 flat for every N from 0 to 5. Coarser k-anonymity (k up to 8, location hidden for
  groups under 5) also leaves A5 at 0.486. In a ~50-patient release, condition + gender alone already
  narrows typhoid or TB to one person. We keep it off and report A5 as our known residual risk.
* **Replacements:** typed placeholders (`[NAME]`, `[PHONE]` …), never fake names (a fake name can
  collide with a real person and count as a leak).

## Security design

Threat model: assume the server (and the output folder) is stolen one day.

* **Encrypted quarantine vault.** A quarantined file is the riskiest thing we hold, because nothing
  was removed from it. It is kept only as AES-256-GCM ciphertext in `output/quarantine/<sha256>.swv`
  (the spec's allowed, unscanned folder), never under its original name, which can itself be PII.
  Each file gets its own key and nonce, derived with HKDF-SHA256 from `RAKSHA_SECRET` and the file's
  SHA-256: a leaked per-file key opens one file, not the vault. GCM authenticates, so a tampered
  file refuses to open. If encryption is unavailable, nothing is written: plaintext is never a fallback.
  `scripts/vault_check.py --check` proves exact restore, wrong-key refusal, tamper refusal and no
  plaintext runs (7 / 7 on the practice data); `--open SHA --to PATH` is the authorised-operator restore.
* **Keys kept away from data.** The only secret is `RAKSHA_SECRET`, held in the environment, never
  printed, logged or written. The output folder holds ciphertext, HMAC pseudonyms and shifted dates;
  none of them can be reversed without the secret.
* No other intermediate data is written to disk: parsing, linking and cleaning happen in memory, and
  the vault writes ciphertext only (via a temp file that is itself ciphertext).
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
| `scripts/attack.py` | our re-implementation of attacks A3-A5 from the kit's ATTACKS.md, ours vs raw. On data other than the default practice set pass `--input` and `--truth` (and `--registry`/`--facts`) |
| `scripts/heldout.py` | leaks when name sources are removed (no registration tables, free text only) |
| `scripts/nocue_eval.py`, `scripts/train_ner.py` | blind no-cue name test; retrain the classifier |
| `scripts/hinglish_eval.py` | 40 Hinglish nursing notes, names with no registration table |
| `scripts/vault_check.py` | quarantine vault: exact restore, wrong key and tampering refused, no plaintext |
| `scripts/score.py` | estimates official parts check_dev does not show: temporal intervals, generalization, token retention |
| `scripts/lost_probes.py`, `scripts/link_misses.py` | which medical values we lost, which links we missed |

## Measured on the practice data (`check_dev.py`)

| Metric | Starter | secret-ward v0.1 |
|---|---|---|
| PII pieces leaked | 2718 / 3230 (84.1%) | 0 / 3230 |
| Canaries found | 4 / 4 | 0 / 4 |
| Medical values kept | 4855 / 4855 | 4826 / 4855 (99.4%; 29 districts hidden on purpose for the smallest groups) |
| Temporal intervals (`scripts/score.py`) | n/a | 15286 / 15286 date pairs exact |
| Linking precision / recall | 0 / 0 | 1.00 / 1.00 (was 0.82: disease durations like "x 8 yrs" were misread as ages; a hospital name was read as a patient name) |
| Runtime | ~2 s | ~2 s (linear: 8,000 synthetic files with 40,000 distinct people in 18 s, 274 MB) |

Privacy, measured with `scripts/attack.py` (our approximation of the official arena; lower is better):

| Attack | Raw input | v0.1 | v0.2 (one band per patient + local k-anonymity) |
|---|---|---|---|
| A3 record linkage, mean probability on the true person | 0.670 | 0.086 | 0.031 |
| A4 patients re-identified after pooling (confidence >= 0.5) | 93.8% | 37.5% | 6.2% |
| A5 targeted attack success | 100% | 51.4% | 51.2% (complete patient clusters give the attacker fuller profiles) |

No-cue names (`scripts/nocue_eval.py`, blind: test templates, names and drug decoys never seen in
training): rules only 0% of names removed; rules + classifier **88% removed, 100% of drug decoys kept,
99.4% of other words kept**.

Hinglish nursing notes (`scripts/hinglish_eval.py`, 40 notes written by a teammate, no registration
table): **105 / 105 name parts removed, 40 / 40 notes fully clean, 19 / 19 clinical words kept**,
both one note per file and all 40 as one multi-line note. This set found a real bug: a name that
started the second line of a note was judged with the previous line as context (74% before the fix).

Held-out (`scripts/heldout.py`): without registration tables 0 / 2263 PII leaked; free text only 0 / 569;
every CSV header renamed to unseen wording 0 / 3230, linking precision 1.00; phones, Aadhaar,
IDs, DOBs, labels and relation markers rewritten into new formats 0 / 3230, linking 1.00 / 1.00.

## Known limitations

* Tuned and measured on the practice data so far; the unseen-format round will expose gaps.
* Free-text names with no label, honorific, relation marker, trigger or gazetteer match are missed.
* Cross-script matching uses a coarse phonetic skeleton; rare spellings can slip.
* XML/PDF/image files are quarantined rather than cleaned.
* A5 (targeted attack, about 49% on practice data) is our weakest privacy number. Its main drivers (common
  condition + exact length of stay + consistent profile) cannot be removed without breaking clinical utility.
* With only ~50 patients per release, local k-anonymity coarsens many patients; on larger releases fewer will be affected.
