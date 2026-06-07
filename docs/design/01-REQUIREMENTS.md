# Windows Secrets Generator — 01: Requirements

Deliverable 2 of 5: [00 Objective/Scope/Background](00-OBJECTIVE-SCOPE-AND-BACKGROUND.md) → **01 Requirements** → [02 Design](02-DESIGN.md) → [03 References & Test Vectors](03-REFERENCES-AND-TEST-VECTORS.md) → [04 Tasklist](04-TASKLIST.md). This document turns 00's locked scope into numbered, testable *shall*-statements — the **contract**. It says *what*, never *how* (that's 02). Every requirement is traceable to a 00 section and to a verification method (a KAT/snapshot/property-test/lint defined in 03, scheduled in 04). All §6 open questions are **resolved** (decision log, §7).

## 1. Conventions

**SHALL** = mandatory, **SHOULD** = recommended, **MAY** = optional ([RFC2119] sense). Each requirement carries an ID, a statement, `[src: …]` (its 00 section or the §7 decision), and `[v: …]` (how verified). IDs are stable.

## 2. Functional Requirements

### 2.1 Inputs (FR-IN)

- **FR-IN-1** The tool SHALL accept a cleartext password via `--password`. `[src: 00 §1]` `[v: NT/LM KATs]`
- **FR-IN-2** The tool SHALL accept a raw password blob as hex via `--password-hex`, treating the **entire** decoded blob as the password bytes by default. `[src: 00 §2.4]` `[v: machine-account KAT]`
- **FR-IN-3** When `--managed-blob` is given with `--password-hex`, the tool SHALL hash only the **first 256 bytes** of the decoded blob (the gMSA/dMSA `CurrentPassword`). Absent the flag it SHALL NOT truncate — selection is explicit, never inferred from length. `[src: 00 §6 D4; §7 D7]` `[v: gMSA KAT MD4(blob[:256])]`
- **FR-IN-4** The tool SHALL read the password from stdin via `--password -`, to keep it out of `argv`/shell history. `[src: 00 §1]` `[v: manual]`
- **FR-IN-5** The tool SHALL accept the identity inputs `--user` (sAMAccountName), `--realm`, `--dns-domain`, `--netbios`, `--upn`, and `--account-type {user,computer,trust}` (default: `computer` for `--managed-blob` or a `$`-suffixed `--user`, else `user`). There SHALL be **no** `--iterations` flag. `[src: 00 §2.4; §7 D12; 02 §1 D1]` `[v: salt KATs]`
- **FR-IN-6** The salt rule SHALL **default** to `computer` for `--managed-blob` or a `$`-suffixed `--user` (machine/gMSA), else `user`; an explicit `--account-type` always overrides. Because `$` is ambiguous (computer host-salt vs trust krbtgt-salt vs `$`-suffixed-user salt), **trust accounts and `$`-suffixed user accounts SHALL pass `--account-type` explicitly**. `[src: 02 §1 D1; user]` `[v: account-type-default test; machine-salt KAT]`
- **FR-IN-7** For raw blobs (machine/trust/gMSA), the tool SHALL apply the UTF-16LE→UTF-8 (`errors="replace"`) re-encoding before the Kerberos string-to-key. `[src: 00 §2.4]` `[v: machine-account Kerberos snapshot]`
- **FR-IN-8** An **empty** password (`--password ""`) is a valid input: the tool SHALL compute the canonical empty-string secrets (NT `31d6cfe0d16ae931b73c59d7e0c089c0`, LM `aad3b435b51404eeaad3b435b51404ee`, and the matching Kerberos keys), not reject it. `[src: §7 D6]` `[v: empty-string KATs]`

### 2.2 Secrets — the six (FR-SEC)

- **FR-SEC-1** Emit the **NT hash** = `MD4(UTF-16LE(pw))`. `[src: 00 §3.1]` `[v: MS-SAMR §4.3 KAT]`
- **FR-SEC-2** **Always** emit the **LM hash**, with: empty/disabled ⇒ `aad3b435b51404eeaad3b435b51404ee`; >14 chars or non-OEM-representable ⇒ the blank placeholder. No flag gates it. `[src: 00 §3.1; §7 D4]` `[v: LM KATs incl. edge cases]`
- **FR-SEC-3** Emit **Kerberos RC4-HMAC** (etype 23) = the NT hash, on its **own labelled line**. `[src: 00 §3.1, D10]` `[v: equality with FR-SEC-1]`
- **FR-SEC-4** Emit the **Kerberos DES key** under **both** `des-cbc-crc` (etype 1) and `des-cbc-md5` (etype 3) labels (identical bytes). `[src: 00 §3.1, D10]` `[v: RFC3961 App-A KAT]`
- **FR-SEC-5** Emit **Kerberos AES128-CTS-HMAC-SHA1-96** (etype 17), iteration count fixed at **4096** (AD's `DefaultIterationCount`, [MS-SAMR] §3.1.1.8.11.6). `[src: 00 §3.1; §7 D12]` `[v: RFC3962 App-B + MS-KILE KATs]`
- **FR-SEC-6** Emit **Kerberos AES256-CTS-HMAC-SHA1-96** (etype 18), iteration count fixed at **4096**. `[src: 00 §3.1; §7 D12]` `[v: RFC3962 App-B KATs]`
- **FR-SEC-7** Emit **WDigest** — 29 MD5 digests, UTF-8 encoded. `[src: 00 §3.1]` `[v: DSInternals 29-hash snapshot]`
- **FR-SEC-8** Compute the salted secrets (DES/AES/WDigest) **only** when their inputs are present. With no `--realm` the tool SHALL emit NT/LM/RC4 and **warn-and-skip** Kerberos/WDigest, writing to stderr exactly which secrets were skipped and which input was missing. `[src: 00 §3.1; §7 D5]` `[v: missing-input property test]`
- **FR-SEC-9** The tool SHALL **NOT** emit any out-of-scope item: AES-SHA2 (etype 19/20), `Primary:CLEARTEXT`, NTLM-Strong-NTOWF, NetNTLM, DCC1/DCC2, DPAPI pre-keys, or the `supplementalCredentials` container bytes. `[src: 00 §3.2]` `[v: output-field allow-list test]`

### 2.3 Account-type handling (FR-ACC)

- **FR-ACC-1** Handle **user** accounts (password → all applicable secrets). `[src: 00 §2.4]`
- **FR-ACC-2** Handle **computer** accounts (the `host/` salt rule). `[src: 00 §2.4]` `[v: MS-KILE machine example]`
- **FR-ACC-3** Handle **sMSA/MSA** accounts (computer-like, via `--password-hex`). `[src: 00 §2.4]`
- **FR-ACC-4** Handle **gMSA/dMSA** via `--password-hex --managed-blob` over `blob[:256]`; the tool SHALL **NOT** attempt KDS-root-key derivation. `[src: 00 §2.4, D3]`
- **FR-ACC-5** Handle **trust** accounts with **full Kerberos** support — NT/RC4 **and** DES/AES128/AES256 of the trust password. The trust-account salt is **resolved in [02 §1](02-DESIGN.md)**: `UPPER(realm)+"krbtgt"+sAMAccountName-without-$` (the `krbtgt/<partner>` principal salt; lab-confirmed `TEST$`→`SNOW.LABkrbtgtTEST`), **not** the user rule. `[src: 00 §2.4; §7 D1; 02 §1 D4]` `[v: DSInternals trust snapshot]`

### 2.4 Input validation — strict, spec-based (FR-VAL)

Per §7 D11, identity inputs SHALL be validated against their spec-defined formats and malformed values rejected with an error that **cites the violated rule**. Validation is spec-grounded, not invented heuristics.

- **FR-VAL-1** `--user` (sAMAccountName) SHALL be validated per **[MS-SAMR] §3.1.1.8.4**: contains ≥1 non-blank character (rule 8); does not end with `.` (rule 9); contains none of `U+0000`–`U+001F` nor any of `" / \ [ ] : | < > + = ; ? , *` (rule 10). `[src: §7 D11]` `[v: validation unit tests]`
- **FR-VAL-2** When `--account-type` is `computer` or `trust`, `--user` SHALL end with a single `$` ([MS-SAMR] §3.1.1.8.4 rule 11); when `user`, it SHALL be ≤20 characters (rule 12). `[src: §7 D11; 02 §1]` `[v: validation unit tests]`
- **FR-VAL-3** `--realm` SHALL be a valid DNS domain name ([RFC1035] label rules); the Kerberos realm is its upper-cased form ([MS-KILE] §3.1.1.2). `--upn` SHALL be `<name>@<realm>`. Malformed values are rejected. `[src: §7 D11]` `[v: validation unit tests]`
- **FR-VAL-4** `--password-hex` SHALL decode as valid hexadecimal; with `--managed-blob` the decoded blob SHALL be ≥256 bytes. Violations are errors. `[src: §7 D11]` `[v: bad-input tests]`

### 2.5 Output (FR-OUT)

- **FR-OUT-1** The default **text** format SHALL be the tool's **own clean labelled style** — `[section]` blocks of aligned `label : value` lines: `meta` (account-type, realm, `sAMAccountName`, `Kerberos salt`, then provided netbios/dns/upn — account-type first, D15), `ntlm`, `kerberos` (enctypes in **etype order** with the number in parens, D16), `wdigest` numbered `wdigest[01..29]`, then a trailing `[skipped]` block; no RID/pwdump fields. `[src: §7 D9]` `[v: snapshot]`
- **FR-OUT-2** The **json** format SHALL group the same sections as **nested objects** — `meta` (incl. `kerberos_salt`), `ntlm` (`nt_hash`/`lm_hash`), `kerberos` (the enctypes `des_cbc_crc`/`des_cbc_md5`/`aes128_cts_hmac_sha1_96`/`aes256_cts_hmac_sha1_96`/`rc4_hmac`, etype-ordered) — plus `wdigest[]` and `skipped[]` arrays (D7/D8). Absent sections and keys SHALL be **omitted** (not `null`). `[src: §7 D8]` `[v: schema test]`
- **FR-OUT-3** The **pretty** format SHALL render via `rich` (tables/panels), imported lazily only on that path, into an in-memory buffer so exactly one copy reaches stdout. `[src: 00 §1]`
- **FR-OUT-4** Output SHALL be **deterministic**: identical inputs ⇒ byte-identical output (no timestamps, no randomness). `[src: 00 §1]` `[v: run-twice equality test]`
- **FR-OUT-5** All hex SHALL be lowercase; enctype labels SHALL follow the established `des-cbc-md5`/`aes256-cts-hmac-sha1-96` naming. `[src: 00 §3.1]`
- **FR-OUT-6** All three formats (`text`/`json`/`pretty`) SHALL present the **identical sections** — `meta` (identity + `Kerberos salt`), `ntlm`, `kerberos` (the enctype keys), `wdigest`, and `skipped` — rendered from one source of truth (`_sections`); no format may show a field another hides, and an empty section/row SHALL be dropped in every format alike. `[src: §7 D13]` `[v: cross-format parity test]`
- **FR-OUT-7** The PBKDF2 iteration count is a fixed **4096** ([RFC3962] §4) and SHALL be documented, not echoed in any output. `[src: §7 D14]`
- **FR-OUT-8** The `meta` section SHALL echo the **supplied** password (the user's own input) — cleartext for typed/stdin passwords, the raw blob as hex for `--password-hex`/`-b64`/`--managed-blob` (which have no cleartext). `[src: user; §7 D17]` `[v: password-echo test]`
- **FR-OUT-9** Every `meta` value outside **printable ASCII (0x21–0x7E)** SHALL be **UTF-8 hex-encoded**, with its label/key marked (`… (hex)` / `…_hex`), so output is always terminal-safe. `[src: user; §7 D17]` `[v: hex-rule test]`

### 2.6 CLI (FR-CLI)

- **FR-CLI-1** The flags SHALL be almost entirely *inputs*; the only behaviour flag is `--format {text,json,pretty}` (default `text`). `[src: 00 §1]`
- **FR-CLI-2** The tool SHALL emit every secret computable from the inputs given — no `--only`/selection flags. `[src: 00 §1]`
- **FR-CLI-3** The tool SHALL process **one account per invocation**; no batch/file input. Bulk use is a shell loop. `[src: §7 D2]`

## 3. Non-Functional Requirements

### 3.1 Correctness & spec-compliance (NFR-COR)

- **NFR-COR-1** Every emitted secret SHALL match the published known-answer vectors in [03](03-REFERENCES-AND-TEST-VECTORS.md). `[v: KAT suite, must pass]`
- **NFR-COR-2** Where no published KAT exists (WDigest, machine/trust Kerberos), every secret SHALL match a **committed DSInternals snapshot** generated from lab accounts with known passwords — the agreed oracle, no impacket. `[src: §7 D3]` `[v: snapshot tests]`
- **NFR-COR-3** Each function SHALL cite its controlling spec section in its docstring; every deviation from the literal spec (e.g. WDigest UTF-8 vs Latin-1) SHALL be documented inline. `[src: project spec-compliance rules]`
- **NFR-COR-4** Source-of-truth hierarchy SHALL be **spec > DSInternals > impacket**, all reference-only. `[src: 00 §4]`

### 3.2 Dependencies & packaging (NFR-DEP)

- **NFR-DEP-1** The tool SHALL be a single self-contained file (`tools/gen_secrets.py`) with PEP 723 inline metadata, runnable via `uv run`. `[src: 00 §1]`
- **NFR-DEP-2** External dependencies SHALL be exactly **pycryptodome** (MD4/DES/AES) and **rich** (pretty only, lazy-imported); everything else stdlib. `[v: import audit]`
- **NFR-DEP-3** The tool and its tests SHALL **NOT import impacket** (runtime or test). `[src: 00 §4]` `[v: import audit]`
- **NFR-DEP-4** The tool SHALL **NOT import `ntdswolf`** (it is an independent oracle). `[src: 00 §1]` `[v: import audit]`
- **NFR-DEP-5** Target runtime SHALL be **Python ≥3.11** (`requires-python >=3.11`), matching the project's ruff/ty floor; no 3.14-only features. `[src: §7 D10]` `[v: runs on 3.11 + 3.14]`

### 3.3 Code quality (NFR-COD)

- **NFR-COD-1** `uv run ruff check` (`select = ["ALL"]`) SHALL pass; protocol-weak-primitive `# noqa` (S324/S304/S305) SHALL carry a spec reason. `[v: CI lint]`
- **NFR-COD-2** `uv run ty check` (`all = "error"`) SHALL pass; every function fully typed. `[v: CI typecheck]`
- **NFR-COD-3** Functions SHALL have Google-style docstrings; the module docstring states the oracle role. `[src: project Python rules]`

### 3.4 Robustness & safety (NFR-ROB)

- **NFR-ROB-1** The tool SHALL fail fast with a clear message if pycryptodome (MD4) is unavailable. `[src: 00 §2; MD4 gotcha]`
- **NFR-ROB-2** Malformed inputs SHALL be rejected per FR-VAL with spec-citing errors; a non-empty password that simply cannot form LM (>14/non-OEM) yields the LM placeholder, not an error. `[src: §7 D6, D11]` `[v: bad-input tests]`
- **NFR-ROB-3** The tool SHALL NOT emit any **derived** secret it was not given (the random `NTLM-Strong-NTOWF`, `Primary:CLEARTEXT`, etc. stay out of scope per 00 D8). The **supplied** password is echoed in `meta` by explicit design (FR-OUT-8); note this writes it to stdout (and any redirect / scrollback). `[v: output-field allow-list test]`

## 4. Traceability

Every FR/NFR cites its 00 source or §7 decision, and every FR cites a verification artefact defined in [03](03-REFERENCES-AND-TEST-VECTORS.md) and scheduled in [04](04-TASKLIST.md). The full requirement→design→test matrix is assembled in 04 once 02 fixes the module decomposition.

## 5. How this leads into 02 (Design)

01 fixes the *contract*; [02](02-DESIGN.md) chooses the *realization* and SHALL, at minimum: (a) **pin and cite the trust-account Kerberos salting principal** (FR-ACC-5, the one carried-forward research item); (b) decompose the FR-SEC algorithms into typed functions, each with its iteration parameter exposed for KATs but the CLI fixed at 4096; (c) define the CLI grammar for the FR-IN flags and the FR-VAL validation order; (d) fix the exact `text`/`json`/`pretty` schemas for FR-OUT; (e) state where pycryptodome/rich are imported to satisfy NFR-DEP. Each §7 decision is a fixed input to 02.

## 6. (Open questions — none)

All requirements-level questions are resolved; see §7. New questions surfaced during 02 are recorded there.

## 7. Resolved decisions (requirements decision log)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Trusts: full Kerberos** (NT/RC4/DES/AES) | The tool is a completeness oracle; a trust password hashes like any account. The only unknown — the TDO-account salting principal — is pinned against the spec in 02 (FR-ACC-5), not avoided. |
| D2 | **Single account per invocation** | Keeps the CLI and the JSON schema simple and matches the KAT/oracle use; bulk is a shell loop. |
| D3 | **Oracle = published KATs + committed DSInternals snapshots** | Strongest proof for the no-published-KAT secrets (WDigest, machine/trust Kerberos) without violating the never-import-impacket rule (NFR-DEP-3). Snapshots come from lab accounts with known passwords. |
| D4 | **Always emit LM** | An oracle reflects exactly what AD can store in `dBCSPwd`, including the blank placeholder; no `--lm` gate. |
| D5 | **Missing salt inputs ⇒ warn and skip** | With no `--realm`, still deliver NT/LM/RC4 and tell the user on stderr what was skipped and why. Serves the common "just the NT hash" case without silent omission. |
| D6 | **Empty password ⇒ canonical hashes** | `""` is a well-defined, legitimate input (disabled/blank accounts); emit `31d6…`/`aad3…`, don't reject. |
| D7 | **Managed blob via explicit `--managed-blob`** | `--password-hex` hashes the whole blob; `--managed-blob` deterministically triggers `[:256]`. No length heuristic — honours the project's no-guess rule. |
| D8 | **JSON keys = enctype/hash labels** | Flat keys (`nt_hash`, `aes256_cts_hmac_sha1_96`, `wdigest[]`) in cracking/tooling vocabulary; maps cleanly to hashcat/secretsdump expectations. |
| D9 | **Text = own clean labelled style** | RID was dropped, so secretsdump's `:rid:` layout doesn't fit; labelled lines are clearer and self-documenting. |
| D10 | **Runtime Python ≥3.11** | Matches the project's ruff `target-version`/ty `python-version`; nothing needs 3.14-only features; maximal portability (still runs on 3.14). |
| D11 | **Strict, spec-based input validation** | Validate identity inputs against their spec formats — sAMAccountName per [MS-SAMR] §3.1.1.8.4 (rules 8–12), realm as a DNS name ([RFC1035]/[MS-KILE]) — and reject with errors that cite the rule. Catches typos that would silently produce wrong salts, without inventing non-spec checks. |
| D12 | **Hardcode 4096 iterations at the CLI** | AD always uses `DefaultIterationCount = 4096` ([MS-SAMR] §3.1.1.8.11.6); the string-to-key function still takes an `iterations` parameter so RFC3962 vectors (counts 1/2/5/1200…) test directly. No `--iterations` flag. |
