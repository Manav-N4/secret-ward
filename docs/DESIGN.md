# secret-ward: design notes

The [README](../README.md) is the summary. This page has the detail behind each choice, for a
reviewer who wants to check the reasoning.

## Detection order

Free text is cleaned in this order (`src/secretward/detect.py`). Earlier layers are more certain;
later layers only see what is left.

1. **Normalise** like the scorer: NFKC, zero-width characters, homoglyphs, Devanagari digits.
2. **Protect** doctors (`Dr. <name>`), ASHA workers, doses, eponyms, wards.
3. **Hidden channels:** base64 blocks are decoded, cleaned and re-encoded.
4. **IDs and digits:** hospital IDs (harvested patterns), phones in every format incl. landlines
   (`0522-2345678`), Aadhaar (masked and full), ABHA. Ranges such as `150000-410000` and values
   with units are guarded. IDs stored as JSON **numbers** under unknown keys go through the same
   rules (10+ digits only, so lab values, ages and years are never touched).
5. **Dates:** DOB removed; every other date shifted by the patient's secret offset. DD/MM vs MM/DD
   is decided by voting per file and per hospital-ID prefix.
6. **Ages:** age patterns only (`52/M`, `52 Yrs`, `52 वर्ष`), never durations (`x 8 yrs`), replaced
   by the patient's single band.
7. **Addresses:** house, mohalla, village, tehsil removed; district and 3-digit PIN prefix kept.
8. **Names**, in order: labels → relation markers → lowercase names after strong cues → triggers →
   honorifics (before and after, incl. Hinglish kin words) → `Md.` / `Mohd` prefix → nursing log lines
   → learned gazetteer (Latin and Devanagari) → cross-script pairs → names next to phone numbers →
   **our classifier** → surname after a found name → absorb generic parts (Singh, Devi) and leftover
   initials.

The classifier only judges lines of 6+ words, only standalone Title-case words, never ALL-CAPS
abbreviations, and never words with drug stems, medical suffixes or clinical / calendar meaning
(`config/rules/medical_stems.txt`, `medical_words.txt`). Each line of a note is judged on its own.

## Column typing

`src/secretward/fields.py` types each CSV column / JSON key from two signals: header hints
(`config/rules/headers.txt`, incl. Hinglish and Devanagari wording) and the shape of its values
(phone, Aadhaar, ABHA, hospital-ID pattern, date of birth, place-name morphology, `S/o`-style
prefixes). Value shape wins when the header is unknown, which is why renamed headers still leak nothing.

## Privacy details (`config/policy.yaml`)

| Setting | Value | Why |
|---|---|---|
| `age_band_years` | 10 | 5-year bands leave 20 / 48 patients unique on the register; 10-year, 11 / 48 |
| one band per patient | on | per-record bands let an attacker pool "40-49" and "50-59" into "49-50" |
| `min_group_size` | 3 | groups smaller than 3 get a 20-year band |
| `hide_location_below` | 2 | a patient still alone also loses district and PIN |
| `date_shift_max_days` | 180 | per-patient, never 0, keyed by the secret: no global un-shift |
| `pin_keep_digits` | 3 | adds no identifying power beyond the district on the practice data |
| `rare_condition_max_patients` | 0 (off) | see below |
| `ner_enabled` | 1 | the trained classifier |

Replacements are typed placeholders (`[NAME]`, `[PHONE]` …), never fake names: a fake name can
collide with a real person and count as a leak.

### Rare conditions: built, measured, switched off

`src/secretward/conditions.py` can generalise diagnoses seen in very few patients to their ICD-10
chapter. On the practice data, for N = 1..5, it cost 2.1-6.1% of medical values and left the
targeted attack (A5) flat. Coarser k-anonymity (k up to 8, location hidden below 5) also left A5
flat. QA's independent attacker agrees. The attacker wins through common conditions (TB, typhoid,
diabetes: 6-9 patients each) combined with profile consistency and the exact length of stay, which
the rules require us to keep. So the switch stays off and A5 is reported as our residual risk.

## Linking

`src/secretward/link.py`: union-find over strong keys. Merge blockers: different stated gender,
stated ages more than 3 years apart, no shared sound-alike name token. Records that list several
patients (indexes, rosters) drop their strong keys so they cannot bridge two people. Only
person-shaped names are used (a FHIR Organization "name" is not a patient). Name-only records
attach only when exactly one cluster fits.

## Dev tools

All read the kit's practice answer key and are never run on hidden data.

| Script | Purpose |
|---|---|
| `scripts/check_all.sh [kit] [--full]` | the whole routine |
| `scripts/attack.py` | A3-A5 from the kit's ATTACKS.md, ours vs raw (`--input`, `--truth`, `--registry`, `--facts` for other data) |
| `scripts/reid_risk.py` | patients unique on the released quasi-identifiers, against the attacker's register |
| `scripts/heldout.py` | four held-out variants of the practice data |
| `scripts/nocue_eval.py`, `scripts/nocue_data.py`, `scripts/train_ner.py` | blind no-cue name test, its generator, classifier training |
| `scripts/hinglish_eval.py` | 40 Hinglish nursing notes |
| `scripts/score.py` | temporal intervals, generalisation, token retention |
| `scripts/vault_check.py` | encrypted quarantine (`--check`, or `--open SHA --to PATH` to restore one file) |
| `scripts/lost_probes.py`, `scripts/link_misses.py` | which medical values we lost, which links we missed |
| `scripts/gen_scale.py` | synthetic scale test (8,000 files) |
| `qa/mutate.py`, `qa/attack_sim.py` | QA lead's mutation harness (rewrites the answer key too) and independent attacker |
| `docs/make_brief.py` | builds `docs/brief.pdf` |
