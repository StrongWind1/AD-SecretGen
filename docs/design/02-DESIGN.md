# Windows Secrets Generator — 02: Design

Deliverable 3 of 5: [00 Objective/Scope/Background](00-OBJECTIVE-SCOPE-AND-BACKGROUND.md) → [01 Requirements](01-REQUIREMENTS.md) → **02 Design** → [03 References & Test Vectors](03-REFERENCES-AND-TEST-VECTORS.md) → [04 Tasklist](04-TASKLIST.md). This document chooses the *realization* of 01's contract: module layout, the typed data model, one function per algorithm (with exact spec cites and steps), the salt rules, the CLI grammar, the output schemas, and the import strategy. It opens (§1) by discharging the one carried-forward research item — the trust-account Kerberos salt. All §12 questions are **resolved** (decision log, §13).

## 1. Resolved: the trust-account Kerberos salt (closes 01 FR-ACC-5)

**Authority: [MS-KILE] §3.1.1.2 (Cryptographic Material).** The spec defines exactly **two** salt forms, selected by account class (verbatim):

- **User accounts:** `<DNS of the realm, uppercased>` + `<user name>` — concatenated, **no separator** (the spec's `|` is notation; the worked AES-128 example in [MS-KILE] §4.4 yields `DOMAIN.COMhostclient.domain.com`, no delimiter).
- **Computer accounts:** `<realm DNS, uppercased>` + `"host"` + `<computer name, lowercased, trailing "$" stripped>` + `"."` + `<realm DNS, lowercased>`.

An **interdomain trust account** is a **user-class** object (`objectClass: user`, `UF_INTERDOMAIN_TRUST_ACCOUNT 0x0800`), whose `sAMAccountName` is the partner's NetBIOS/flat name followed by `$` ([MS-ADTS] "Essential Attributes of Interdomain Trust Accounts"). [MS-KILE] §3.1.1.2 names only the user/computer forms, so the trust case had to be settled empirically — and **real AD uses neither**:

> **Trust salt = `UPPER(localRealmDNS)` + `"krbtgt"` + `<sAMAccountName without the trailing "$">`** — the RFC4120 default salt for the principal `krbtgt/<partner flat name>` in the local realm. **Lab-confirmed**: `TEST$` in `snow.lab` → `SNOW.LABkrbtgtTEST` (DSInternals `DefaultSalt`, [03 §3.5.1](03-REFERENCES-AND-TEST-VECTORS.md)).

This is why "trust AES keys use a different salt": the stored key is salted as `krbtgt/<partner>`, not as the account's own name. **Caution:** a plain *user* account whose name merely ends in `$` is salted by the *user* rule (`UPPER(realm)+sAMAccountName`) — the `$` suffix alone is **not** what selects the trust salt; being a genuine interdomain trust is. (My earlier `svc_dollar$` "proxy" was exactly this red herring.)

**Consequence for FR-IN-6 (amended — D1).** A `$`-suffixed name is ambiguous: computer (host salt), a real trust (krbtgt salt), or a plain user (user salt). So the `$` suffix and `--managed-blob` are used only as a **default toward `computer`** (the overwhelmingly common case — machine and gMSA/dMSA accounts), **never a locked inference**: an explicit `--account-type {user,computer,trust}` always overrides. Trust accounts and any `$`-suffixed *user* account therefore require an explicit `--account-type`.

## 2. Architecture

One file, `tools/gen_secrets.py`, organised top-to-bottom with `# --- Section ---` dividers; all logic in **pure, typed, module-level functions** (no classes except frozen dataclasses). Data flow:

```
argv ──▶ parse_args ──▶ validate (FR-VAL) ──▶ Identity ─┐
                                                         ├─▶ compute_secrets(Identity, pw) ──▶ Secrets ──▶ format_{text,json,pretty} ──▶ stdout
password / --password-hex(+--managed-blob) ─────────────┘
```

Sections, in order: (1) imports + MD4 fail-fast; (2) constants (`KGS!@#$%`, `"kerberos"`, the WDigest combo table, enctype labels); (3) encodings; (4) the six algorithms; (5) salt + identity; (6) account dispatch (`compute_secrets`); (7) the three formatters; (8) CLI (`parse_args`, `validate`, `main`).

## 3. Data model (frozen dataclasses — 01-style immutable records)

```python
class AccountType(StrEnum):  # salt rule; CLI defaults computer for $/--managed-blob, overridable
    USER = "user"
    COMPUTER = "computer"
    TRUST = "trust"  # = user salt, $ retained (§1)


@dataclass(frozen=True, slots=True)
class Identity:
    sam_account_name: str  # --user
    realm_dns: str  # --realm (DNS form; Kerberos realm = UPPER(realm_dns))
    account_type: AccountType
    netbios_domain: str | None  # --netbios    (WDigest 1–7,18–20,27–29)
    dns_domain: str | None  # --dns-domain (WDigest 8–14; default realm_dns)
    upn: str | None  # --upn        (WDigest 15–17,24–26)


@dataclass(frozen=True, slots=True)
class Secrets:
    nt: bytes
    lm: bytes
    rc4_hmac: bytes  # == nt
    des: bytes | None  # 8 B; etypes 1 & 3 share it
    aes128: bytes | None
    aes256: bytes | None
    wdigest: tuple[bytes, ...]  # 0 or 29
    salt: str | None  # computed Kerberos salt (shown in the meta section; salts DES+AES)
    skipped: tuple[str, ...]  # secrets not computed + why (FR-SEC-8)
```

`None`/empty marks "not computable from the inputs given" (drives FR-SEC-8 warn-and-skip). The formatters consume `Secrets` + `Identity`; nothing else.

## 4. Encoding layer

| Helper | Encoding | Used by | Spec |
|--------|----------|---------|------|
| `_utf16le(pw)` | UTF-16LE | NT hash, Kerberos pre-image (str input) | [MS-NLMP] §3.3.1 |
| `_oem14(pw)` | OEM codepage, uppercased, 14 bytes | LM hash | [MS-NLMP] §3.3.1 |
| `_aes_pwd(pw\|blob)` | str→**UTF-8**; raw blob→UTF-16LE-decode-then-UTF-8 (`errors="replace"`) | AES string-to-key | [MS-KILE] §3.1.1.2 |
| `_des_pwd(pw)` | str→**ANSI codepage (cp1252)**; ASCII identical | DES string-to-key | [RFC3961] §6.2 + lab finding |
| `_wdigest_bytes(s)` | **ISO-8859-1 (cp28591)** | WDigest | [MS-SAMR] §3.1.1.8.11.3.1 |

**Three password encodings — all lab-confirmed 29/29 against real AD** (snow.lab, 2026-06-07; [03 §3.5](03-REFERENCES-AND-TEST-VECTORS.md)): **AES → UTF-8**, **DES → legacy ANSI codepage (cp1252 ≈ Latin-1)** for non-ASCII, **WDigest → ISO-8859-1** (D3 **CONFIRMED** — the earlier "real AD uses UTF-8" hypothesis was *wrong*). All three coincide for ASCII. Latin-1/ANSI cannot encode code points > 0xFF (the documented `svc_uni2` failure path); non-Western codepages make non-ASCII DES/WDigest locale-dependent.

## 5. The six algorithms (one function each)

| Function | Signature → out | Steps | Spec |
|----------|-----------------|-------|------|
| `compute_nt_hash` | `(pw_bytes) -> bytes[16]` | `MD4(utf16le)` | [MS-NLMP] §3.3.1 (NTOWFv1); RC4-HMAC = this ([RFC4757]) |
| `compute_lm_hash` | `(pw) -> bytes[16]` | upper→OEM[:14]→two 7-byte halves→DES-ECB(`KGS!@#$%`); >14/non-OEM ⇒ blank | [MS-NLMP] §3.3.1 (LMOWFv1) |
| `compute_kerberos_des_key` | `(pw_bytes, salt) -> bytes[8]` | `mit_des_string_to_key`; etypes **1 and 3 share it**; pw via `_des_pwd` (**ANSI/cp1252**, lab finding) | [RFC3961] §6.2; [MS-SAMR] §3.1.1.8.11.4 |
| `compute_kerberos_aes_key` | `(pw_bytes, salt, n, iters=4096) -> bytes[n]` | `DK(PBKDF2-HMAC-SHA1(pw,salt,iters,n), "kerberos")`; pw via `_aes_pwd` (**UTF-8**); n=16→e17, n=32→e18 | [RFC3962] §4; [MS-KILE] §3.1.1.2; [MS-SAMR] §3.1.1.8.11.6 |
| `compute_wdigest_hashes` | `(Identity, pw) -> tuple[bytes,...]` | 29× `MD5(colon-join(parts))` per the §6 table | [MS-SAMR] §3.1.1.8.11.3.1 |

`rc4_hmac` is the `compute_nt_hash` result (emitted under its own label, 01 D10). `iters` is a function parameter so the [RFC3962] vectors (counts 1/2/1200/5) test directly, but the CLI fixes 4096 (01 D12). MD4/DES/AES come from **pycryptodome**; MD5/SHA1/PBKDF2 from stdlib `hashlib`.

## 6. Salt & the WDigest combinations

`compute_kerberos_salt(identity) -> str` (per §1):

- `USER`: `UPPER(realm_dns) + sam_account_name`.
- `TRUST`: `UPPER(realm_dns) + "krbtgt" + sam_account_name.rstrip("$")` — the `krbtgt/<partner>` principal salt, **lab-confirmed** (`TEST$` → `SNOW.LABkrbtgtTEST`); **not** the user rule.
- `COMPUTER`: `UPPER(realm_dns) + "host" + LOWER(sam_account_name.rstrip("$")) + "." + LOWER(dns_domain or realm_dns)`.

The 29 WDigest pre-images ([MS-SAMR] §3.1.1.8.11.3.1, RFC2617 `A1 = username:realm:password`), each `MD5(latin-1(...))`. `S`=sAMAccountName, `N`=NETBIOSDomainName, `D`=DNSDomainName, `U`=userPrincipalName (**implicit `S@D` when unset** — lab-confirmed), `\`=literal backslash. **Lab-confirmed correction: hashes 15–20 use an EMPTY realm → `principal::password` (double colon)**, not `principal:password`. Each cell below is the `username:realm` portion; the password is appended as the final `:password`:

| # | username:realm | # | username:realm | # | username:realm |
|---|-------|---|-------|---|-------|
| 1 | S:N | 11 | S:UPPER(D) | 21 | S:Digest |
| 2 | lower(S):lower(N) | 12 | S:lower(D) | 22 | lower(S):Digest |
| 3 | UPPER(S):UPPER(N) | 13 | UPPER(S):lower(D) | 23 | UPPER(S):Digest |
| 4 | S:UPPER(N) | 14 | lower(S):UPPER(D) | 24 | U:Digest |
| 5 | S:lower(N) | 15 | **U:** (empty) | 25 | lower(U):Digest |
| 6 | UPPER(S):lower(N) | 16 | **lower(U):** | 26 | UPPER(U):Digest |
| 7 | lower(S):UPPER(N) | 17 | **UPPER(U):** | 27 | N\S:Digest |
| 8 | S:D | 18 | **N\S:** (empty) | 28 | lower(N\S):Digest |
| 9 | lower(S):lower(D) | 19 | **lower(N\S):** | 29 | UPPER(N\S):Digest |
| 10 | UPPER(S):UPPER(D) | 20 | **UPPER(N\S):** | | |

So #1 = `MD5(latin-1("S:N:password"))`, #15 = `MD5(latin-1("U::password"))`, #21 = `MD5(latin-1("S:Digest:password"))`. **All 29 validated 29/29 against real AD** ([03 §3.5](03-REFERENCES-AND-TEST-VECTORS.md)). Hashes needing an absent input are skipped individually and named in `Secrets.skipped`; the table is a module constant of `(name_fn, realm)` tuples — no per-hash code.

## 7. CLI grammar (argparse — stdlib, satisfies NFR-DEP-2)

```
gen_secrets.py (--password STR | --password-hex HEX | --password -) [--managed-blob]
               [--user SAM] [--realm DNS] [--account-type {user,computer,trust}]
               [--netbios NAME] [--dns-domain FQDN] [--upn UPN]
               [--format {text,json,pretty}]
```

- Password source is a **required mutually-exclusive group** (D6); `--managed-blob` is valid only with `--password-hex` (else argparse error) and truncates to `blob[:256]` (FR-IN-3).
- `--account-type` is an **enum**, default `user`; there is **no `$`-inference** and **no `--salt` override** (D1, D5).
- **Validation order** (`validate`, FR-VAL): decode/availability → identity-format checks ([MS-SAMR] §3.1.1.8.4: rules 8–10 always; rule 11 `$` when type∈{computer,trust}; rule 12 ≤20 when type=user) → realm as DNS name → cross-field (salted secrets need `--realm`; WDigest combos need their fields). Missing-but-optional ⇒ warn-and-skip; malformed ⇒ **exit 2** with a message citing the violated rule (D11).
- No `--iterations`, no `--only` (01 D12, FR-CLI-2). `--format` is the sole behaviour flag.

## 8. Output schemas

**All three formats present the identical information in the identical sections** (FR-OUT-6) — **meta** (the inputs: account-type, realm, `sAMAccountName`, the echoed `password`, the `Kerberos salt`, and any netbios/dns-domain/upn provided — non-printable values hex-encoded), **ntlm** (`nt`/`lm`), **kerberos** (the enctypes in **etype order** with the number in parens), **wdigest** (29 hashes) — plus a trailing **skipped** list. One source of truth, `_sections()`, yields ordered `(section, [(display-label, json-key, value)])`; the three formatters only lay it out. An empty section/row (e.g. no `--netbios` ⇒ no WDigest) is omitted in **every** format alike, so none can show a field another hides. The **salt** is account metadata: it salts **DES (1/3) and AES (17/18)** identically (only **RC4 (23)** is saltless — its key is the NT hash, so it's always present, and `kerberos.rc4-hmac` == `ntlm.nt`); calling it "the AES salt" would be wrong (D15). Iterations are a fixed 4096 (D14) and are **not** echoed.

- **text** (default, FR-OUT-1) — `[section]` blocks of aligned `label : value` lines, WDigest **numbered 01..29** (D9); `des-cbc-crc`/`des-cbc-md5` on their own lines (same bytes, FR-SEC-4); a trailing `[skipped]` block:
  ```
  [meta]
  account-type                 : user
  realm (AD domain)            : corp.local
  sAMAccountName               : alice
  password                     : P@ssw0rd!
  Kerberos salt                : CORP.LOCALalice
  netbios-domain               : CORP

  [ntlm]
  nt                           : 7facdc498ed1680c4fd1448319a8c04f
  lm                           : e52cac67419a9a22ce171273f527391f

  [kerberos]
  des-cbc-crc (1)              : <16hex>
  des-cbc-md5 (3)              : <16hex>
  aes128-cts-hmac-sha1-96 (17) : <32hex>
  aes256-cts-hmac-sha1-96 (18) : <64hex>
  rc4-hmac (23)                : 7facdc498ed1680c4fd1448319a8c04f

  [wdigest]
  wdigest[01]                  : <hex>   …   wdigest[29] : <hex>

  [skipped]
  kerberos des/aes (no --realm)
  ```
- **json** (FR-OUT-2) — the same sections as **nested objects** `{ "meta":{ …, "kerberos_salt" }, "ntlm":{…}, "kerberos":{…etype-ordered…}, "wdigest":[…29…], "skipped":[…] }` (D8); the parens etype numbers are display-only (the json key is the bare enctype name). Absent sections/keys are **omitted**, not `null`. The echoed `meta.kerberos_salt` makes Kerberos mismatches debuggable.
- **pretty** (FR-OUT-3) — `rich`, imported lazily inside the formatter only; the same sections as **grouped panels** META / NTLM / KERBEROS / WDIGEST (D8). Renders into an in-memory buffer (`record=True, file=StringIO`) so `main` prints exactly one copy.

All hex lowercase; output deterministic (FR-OUT-4). The `meta` section echoes the **supplied** password (FR-OUT-8/D17) and hex-encodes any value outside printable ASCII 0x21–0x7E (FR-OUT-9/D17); no *derived* cleartext is emitted (NFR-ROB-3).

## 9. Dependencies & imports

- **Top of file:** `from Crypto.Hash import MD4`, `from Crypto.Cipher import DES, AES`, stdlib `hashlib`/`hmac`/`argparse`/`dataclasses`/`enum`. The `MD4` import is wrapped to **fail fast** with an actionable message if pycryptodome is missing (NFR-ROB-1).
- **Lazy:** `import rich…` only inside `format_pretty` (NFR-DEP-2) — text/json paths never import it.
- **Never:** `impacket`, `ntdswolf` (NFR-DEP-3/4) — enforced by an import-audit test.
- PEP 723 header pins `dependencies = ["pycryptodome", "rich"]`, `requires-python = ">=3.11"` (01 D10).

## 10. Testing seams

Pure functions + injectable `salt`/`iters` make every algorithm directly KAT-testable without the CLI; `compute_secrets` is deterministic given `(Identity, pw)`; the formatters are pure `Secrets → str`. **All verification lives in the external pytest suite** — there is no embedded `--self-test` (D12); the script ships only the tool. The corpus and oracle wiring are [03](03-REFERENCES-AND-TEST-VECTORS.md); the build order is [04](04-TASKLIST.md).

## 11. How this leads into 03

Every function in §5/§6 names the published vector or DSInternals snapshot that pins it; [03](03-REFERENCES-AND-TEST-VECTORS.md) assembles that corpus (RFC3961/3962 appendices, the [MS-KILE] §4.4 AES-128 example at 1000 iterations, NT/LM KATs, lab DSInternals snapshots incl. the trust-salt confirmation and the non-ASCII WDigest decider) and the import-audit/determinism property tests, then [04](04-TASKLIST.md) sequences the build.

## 12. (Open questions — none)

All design questions resolved; see §13.

## 13. Resolved decisions (design decision log)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **`--account-type {user,computer,trust}` enum** (defaults to `computer` for `$`/`--managed-blob`, else `user`) | One orthogonal selector for the salt rule; the `$`/managed-blob default is a convenience for the common machine/gMSA case and is **overridable** (§1) — trust and `$`-suffixed user accounts pass it explicitly. Extensible without flag-conflict states. |
| D2 | **Frozen `@dataclass`es** (`Identity`, `Secrets`) | Strong typing for ty `all=error`, matches the project's immutable-record rule, makes the formatter contracts explicit. |
| D3 | **WDigest encoding = ISO-8859-1** — **lab-CONFIRMED** | Validated 29/29 vs real AD (`svc_uni1`, [03 §3.5]): Latin-1, not UTF-8. Lab also corrected two combos: hashes 15–20 use an **empty realm** (`principal::password`) and the **implicit UPN = `sAM@dnsdomain`** (§6). |
| D4 | **Trust salt = krbtgt principal** — **lab-CONFIRMED** | A real interdomain trust account is salted `UPPER(realm)+"krbtgt"+sam-without-$` (`TEST$` → `SNOW.LABkrbtgtTEST`), **not** the user rule. A user account merely ending in `$` uses the user rule (the `svc_dollar$` red herring). |
| D5 | **No `--salt` override** | Salt is always computed from identity + account-type; smallest CLI; RFC reproduction happens at the function level (injectable `salt`). |
| D6 | **Required mutually-exclusive password group** | `--password \| --password-hex \| --password -`, `--managed-blob` gated to `--password-hex`; explicit and argparse-native. |
| D7 | **JSON = nested sections** | `meta`/`ntlm`/`kerberos` objects + `wdigest`/`skipped` arrays — the same sections every format shows. `meta` echoes account-type, realm, `sam_account_name`, `kerberos_salt`, and the provided netbios/dns/upn; `meta.kerberos_salt` makes mismatches debuggable. Absent sections/keys are omitted (not `null`); what's missing is named in `skipped`. |
| D8 | **pretty = grouped panels** | META / NTLM / KERBEROS / WDIGEST panels give the 29 WDigest a bounded block and keep the logical grouping — the same sections as text/json (D13). |
| D13 | **All formats carry identical information in identical sections** | text, json, and pretty render from one source of truth, `_sections()`; no format may show a field another hides, and an empty section is dropped everywhere alike. Prevents the drift where json's `meta` (realm, iterations) once outran text/pretty. |
| D14 | **Iterations fixed at 4096, not echoed** | RFC3962 §4 / [MS-KILE] mandates 4096 for AD; it's a constant, not a per-account fact, so it's documented rather than shown in any format. |
| D15 | **Salt labelled `Kerberos salt`, placed in `meta`** | [RFC3961] §6.2 hashes `password+salt` for **DES** and [RFC3962] §4 PBKDF2s `password,salt` for **AES** — DES (1/3) and AES (17/18) share the *same* salt; only **RC4 (23)** is saltless. So it is account metadata, not "the AES salt" — labelling it for AES alone would be a factual error. |
| D16 | **Kerberos enctypes in etype order, number in parens** | List `des-cbc-crc (1)` / `des-cbc-md5 (3)` / `aes128-…-96 (17)` / `aes256-…-96 (18)` / `rc4-hmac (23)` by ascending etype, so the section reads in protocol order; the number is display-only (json keys stay the bare names). |
| D17 | **Echo the supplied password in `meta`; hex-encode non-printable meta values** | User choice: `meta` echoes the input password (cleartext, or raw blob as hex) so output is a self-documenting record. Any meta value outside printable ASCII 0x21–0x7E is UTF-8 hex-encoded with a `… (hex)` / `…_hex` marker — terminal-safe and unambiguous. Reverses the old "no cleartext in output" stance for the *supplied* password only (NFR-ROB-3); it lands in stdout/redirects. |
| D9 | **WDigest numbered `01..29`** | secretsdump/DSInternals convention; the index→combination map lives in the §6 table/comment. |
| D10 | **`compute_` prefix on algorithm functions** | Verb-explicit that these *derive* (vs NTDSWolf's `decrypt_*` inverse); reads clearly. |
| D11 | **Exit 2 on validation error; 0 on warn-skip** | Malformed input is a hard failure citing the rule; partial output from missing optional inputs is success (serves the NT-hash-only call). |
| D12 | **No embedded `--self-test`; external pytest only** | Single source of test truth, smaller file; the 03/04 suite is the verification home. |
