# Windows Secrets Generator — 04: Tasklist

Deliverable 5 of 5 (final): [00 Objective/Scope/Background](00-OBJECTIVE-SCOPE-AND-BACKGROUND.md) → [01 Requirements](01-REQUIREMENTS.md) → [02 Design](02-DESIGN.md) → [03 References & Test Vectors](03-REFERENCES-AND-TEST-VECTORS.md) → **04 Tasklist**. This turns the validated design + corpus into an ordered, dependency-aware build sequence for `tools/gen_secrets.py`. Every task names the requirement it satisfies and the test that proves it. The design is **lab-validated** ([03 §3.6](03-REFERENCES-AND-TEST-VECTORS.md)) — this is execution, not discovery.

## 1. Definition of Done

The oracle is complete when **all** hold:

- `tools/gen_secrets.py` is a **single PEP 723 file**, runs via `uv run tools/gen_secrets.py …`, `requires-python >=3.11`, deps exactly `pycryptodome` + `rich` (NFR-DEP-1/2/5).
- Every **published KAT** (§2 of 03 — NT/LM, RFC3961 DES, RFC3962 AES iteration vectors, [MS-KILE] §4.4) passes.
- Every **committed lab fixture** (`tools/tests/fixtures/secrets/*.json`, 7 accounts) passes — `compute_secrets(Identity(**identity), password) == expected`, skipping `oracle_skip_fields` (NFR-COR-1/2).
- **Property tests** pass: determinism, import-audit (no `impacket`/`ntdswolf`, `rich` lazy), output allow-list, dedup equalities, FR-VAL reject-cases (03 §4).
- `uv run ruff check` (`select=["ALL"]`) and `uv run ty check` (`all="error"`) are **green**.

## 2. Build phases (ordered; each task → requirement → test)

| Phase | Tasks | Satisfies | Verified by |
|-------|-------|-----------|-------------|
| **P0 — Scaffold** | PEP 723 header; module docstring (oracle role); `MD4` fail-fast import; `AccountType` StrEnum; frozen `Identity`/`Secrets`; section dividers | NFR-DEP-1/2/5, D2, NFR-ROB-1 | imports clean; `--help` runs |
| **P1 — Encodings** | `_utf16le`, `_oem14` (LM, OEM cp437), `_aes_pwd` (UTF-8 + blob UTF-16LE→UTF-8), `_des_pwd` (**ANSI cp1252**), `_wdigest_bytes` (**ISO-8859-1**) | 02 §4 (lab-confirmed) | per-encoder micro-tests |
| **P2 — The six algorithms** | `compute_nt_hash`, `compute_lm_hash`, `compute_kerberos_des_key`, `compute_kerberos_aes_key(…,iters=4096)`, `compute_wdigest_hashes` | FR-SEC-1…7 | **published KATs** (03 §2), red→green |
| **P3 — Salt & identity** | `compute_kerberos_salt` (user/computer/trust rules); the **29-combo constant** (empty-realm 15–20, implicit UPN `sAM@dns`) | FR-ACC, 02 §1/§6 | salt KATs; WDigest combo unit test |
| **P4 — Dispatch** | `compute_secrets(identity, pw)`: account-type routing, warn-and-skip, dedup (`rc4==nt`, `des-crc==des-md5`) | FR-SEC-8, FR-ACC-1…5 | missing-input + dedup tests |
| **P5 — CLI** | argparse: mutually-exclusive password group, `--managed-blob` gate, `--account-type` enum, stdin; `validate` (FR-VAL order, [MS-SAMR] §3.1.1.8.4); exit 2/0 | FR-IN, FR-VAL, FR-CLI | reject-case tests; exit codes |
| **P6 — Formatters** | `format_text` (labelled, `wdigest[01..29]`), `format_json` (flat + `meta`), `format_pretty` (rich panels, lazy import) | FR-OUT-1…5 | snapshot + determinism tests |
| **P7 — Fixture wiring** | load `tools/tests/fixtures/secrets/*.json`; assert per-field, honour `oracle_skip_fields` | NFR-COR-1/2 | the 7 lab fixtures pass |
| **P8 — Gates** | ruff ALL, ty strict, pytest; import-audit + property tests | NFR-COD, NFR-DEP-3/4, 03 §4 | CI green |

Dependencies: P0→P1→P2→P3→P4→{P5,P6}→P7→P8 (P5 and P6 are parallel after P4).

## 3. Traceability (requirement → phase → test)

Built from [01](01-REQUIREMENTS.md) FRs/NFRs: FR-IN→P5; FR-SEC-1/2→P2(§2.1); FR-SEC-3→P2(dedup); FR-SEC-4→P2(03 §2.2); FR-SEC-5/6→P2(03 §2.3/2.4); FR-SEC-7→P2/P3(03 §3.6); FR-SEC-8→P4; FR-ACC-*→P3/P4(+03 §3.6 fixtures); FR-VAL-*→P5; FR-OUT-*→P6; NFR-COR-*→P7; NFR-DEP/COD→P8. The full matrix is the test suite itself (each test ids its requirement).

## 4. Risks & notes

- **`svc_uni2` codepage limitation** ([03 §3.6]): non-Western >U+00FF passwords' DES/WDigest are out of scope — the fixture's `oracle_skip_fields` enforces this; do not chase a best-fit codepage.
- **Published-vector transcription**: pull RFC3961/3962 + [MS-KILE] §4.4 key bytes verbatim from the local specs at the start of P2 (no fabrication).
- **DES/AES encoding split is lab-confirmed** (DES→cp1252, AES→UTF-8) — implement per 02 §4, not the naive "both UTF-8".
- **No `--self-test`** (02 D12); all verification is the external pytest suite.

## 5. Resolved decisions (build decision log)

| # | Decision | Note |
|---|----------|------|
| D1 | **Write `gen_secrets.py` + tests now** | The design is lab-validated; this session implements to the §1 Definition of Done. |
| D2 | **Tests + fixtures under `tools/tests/`** | Co-located with the standalone oracle (fixtures already at `tools/tests/fixtures/secrets/`). |
| D3 | **Strict red→green per function** | Failing KAT first, then implement until green. |
| D4 | **`_des_pwd` = cp1252 hardcoded** | Western ANSI, matches the lab + spec; non-Western >U+00FF is out of scope (`svc_uni2`). No flag. |
| D5 | **`svc_uni2` skip fields = `xfail` with reason** | `xfail('non-Western codepage, out of scope')` — keeps the limitation visible every run. |
| D6 | **No CI for now** | Local `uv run ruff/ty/pytest`; CI wiring deferred. |
| D7 | **Dedicated `tools/pyproject.toml`** | Standalone ruff(ALL)/ty(strict)/pytest config; not coupled to NTDSWolf's package. |
| D8 | **`_oem14` = cp437 (US OEM)** | The spec's OEM sense; academic for ASCII-only LM KATs. |
| D9 | **Build the 3 deferred fixtures now** | gMSA via `--managed-blob`, a real interdomain-trust, a child-domain second realm — added to the P7 corpus. |
| D10 | **Published RFC/MS KATs = mandatory P2 gate** | RFC3961 DES + RFC3962 AES (iteration vectors) + [MS-KILE] §4.4 + NT/LM, before any lab fixture. |
| D11 | **Text format shows the `kerberos_salt` line** | Consistent with JSON `meta`; lets an operator see the salt that produced the keys. |
| D12 | **Keep [02 §3] names** | `compute_` prefix + `Identity`/`Secrets` fields as designed — frozen in code. |
