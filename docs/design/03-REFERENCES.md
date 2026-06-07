# Windows Secrets Generator — 03: References & Test Vectors

Deliverable 4 of 5: [00 Objective/Scope/Background](00-OBJECTIVE-SCOPE-AND-BACKGROUND.md) → [01 Requirements](01-REQUIREMENTS.md) → [02 Design](02-DESIGN.md) → **03 References & Test Vectors** → [04 Tasklist](04-TASKLIST.md). This document assembles the **pass/fail bar**: the authoritative sources every function cites, the published known-answer vectors that pin the deterministic algorithms, and the **lab golden snapshots** (snow.lab via netexec + DSInternals) that pin everything with no published vector — WDigest, machine/trust Kerberos, gMSA. Each [02 §5/§6](02-DESIGN.md) function maps to at least one vector here; [04](04-TASKLIST.md) sequences the build against them.

## 1. Sources & citation map (spec > DSInternals > impacket)

Local authoritative specs in `tools/` (pandoc-converted): `MS-SAMR-260427.md`, `MS-NLMP.pdf`, `MS-ADTS-240610.md`, `MS-DRSR-171201.md`, `MS-KILE-240610.md`. Each function names its controlling section ([02 §5/§6](02-DESIGN.md)); consolidated:

| Secret / step | Primary citation | Cross-refs |
|---------------|------------------|-----------|
| NT hash (NTOWFv1) | [MS-NLMP] §3.3.1 | [MS-SAMR] §2.2.11.1 |
| LM hash (LMOWFv1) | [MS-NLMP] §3.3.1 | — |
| RC4-HMAC (etype 23) = NT | [RFC4757] §3–4 | [MS-KILE] §3.1.5.7 |
| DES string-to-key (etype 1/3) | [RFC3961] §6.2 | [MS-SAMR] §3.1.1.8.11.4 |
| AES string-to-key (etype 17/18) | [RFC3962] §4 | [MS-KILE] §3.1.1.2; [RFC3961] §5.1 (DK) |
| Kerberos salt (user/computer/trust) | [MS-KILE] §3.1.1.2 | [02 §1] (trust) |
| WDigest (29 × MD5) | [MS-SAMR] §3.1.1.8.11.3.1 | [RFC2617] §3.2.2.2 |
| Identity validation | [MS-SAMR] §3.1.1.8.4; [RFC1035] | — |
| Secret-attribute set / PEK | [MS-DRSR] §4.1.10.3.11; [MS-ADTS] | (context only — not computed) |

**Hierarchy rule (NFR-COR-4):** where sources disagree, **spec wins**; DSInternals is the empirical oracle (snapshotted, §3); impacket is read-only reference. The one standing spec-vs-reality tension is WDigest encoding ([02 D3], settled by §3.5.2).

## 2. Published known-answer vectors (deterministic bedrock)

Hard-coded in the pytest suite as parametrized constants — no lab needed, runs in CI.

### 2.1 NT / LM (confident, transcribed)

| Input | `compute_nt_hash` | `compute_lm_hash` |
|-------|-------------------|-------------------|
| `""` | `31d6cfe0d16ae931b73c59d7e0c089c0` | `aad3b435b51404eeaad3b435b51404ee` |
| `"Password"` | `a4f49c406510bdcab6824ee7c30fd852` | `e52cac67419a9a224a3b108f3fa6cb6d` |
| `"OLDPASSWORD"` | `6677b2c394311355b54f25eec5bfacf5` | `c9b81d939d6fd80cd408e6b105741864` |
| `>14 chars` | (MD4 of the full pw) | `aad3b435b51404eeaad3b435b51404ee` (placeholder) |

RC4-HMAC(pw) == `compute_nt_hash(pw)` for every row (equality test, FR-SEC-3).

### 2.2 DES string-to-key — [RFC3961] §6.2 / Appendix

Parameters fixed by the RFC; exact key bytes **transcribed from [RFC3961] at build** (not paraphrased here, to avoid a wrong vector):

| password | salt | expected etype-1/3 key |
|----------|------|------------------------|
| `"password"` | `"ATHENA.MIT.EDUraeburn"` | *(RFC3961 §6.2 worked example)* |
| `"potatoe"` | `"WHITEHOUSE.GOVdanny"` | *(RFC3961)* |

### 2.3 AES string-to-key — [RFC3962] Appendix B

The canonical iteration-count vectors (drive `compute_kerberos_aes_key(..., iters=n)`; exact keys transcribed from [RFC3962] App-B at build):

| iters | password | salt | etype 17 (AES128) / etype 18 (AES256) |
|-------|----------|------|----------------------------------------|
| 1 | `"password"` | `"ATHENA.MIT.EDUraeburn"` | App-B |
| 2 | `"password"` | `"ATHENA.MIT.EDUraeburn"` | App-B |
| 1200 | `"password"` | `"ATHENA.MIT.EDUraeburn"` | App-B |
| 5 | `"password"` | `"\x12…"` (the 0x12-prefixed salt) | App-B |
| 1200 | `"X"×64` | `"pass phrase…"` | App-B |

### 2.4 [MS-KILE] §4.4 AES-128 worked example

`password = U+FFFF × repeated`, `salt = "DOMAIN.COMhostclient.domain.com"` (a **computer**-account salt), `iterations = 1000 (0x3e8)` → the AES-128 key printed in [MS-KILE] §4.4. Pins both `compute_kerberos_aes_key` and the **computer** salt rule + UTF-16→UTF-8 password re-encode.

## 3. Lab golden snapshots (snow.lab)

The only oracle for the secrets with no published KAT (WDigest 29, machine/trust/gMSA Kerberos, the salt rules in the wild). Generated once, committed as static fixtures, compared in CI. **None of the tooling below is imported by the tool or its tests** (NFR-DEP-3) — it only *produces* the static expected values.

### 3.1 The two oracle tools (defense in depth)

- **DSInternals `Get-ADReplAccount` — primary.** The only tool that decodes the **WDigest 29** and exposes the **Kerberos salt** explicitly; also yields NT/LM, history, and all Kerberos keys. This is the authoritative golden source.
- **netexec `--ntds` (DRSUAPI dcsync) — independent cross-check.** Gives NT/LM + Kerberos keys (etype 17/18/23 and DES) from a *different* codebase. Where it overlaps DSInternals, the two **must agree** (catches a bug in either oracle); it does **not** cover WDigest.

A golden case is "both tools agree on NT/LM/Kerberos, and DSInternals additionally fixes WDigest 29 + salt."

### 3.2 Account matrix (created with known passwords)

Realm shown generically as `<REALM>` / `<NB>` (no lab IPs or DC names committed — undercover rule). New user/computer accounts are created for the deterministic cases; the existing gMSA/trust accounts supply those.

Passwords and exact commands are in the **[lab-fixture-runbook](lab-fixture-runbook.md)**; snapshot every row on **both the 2022 and 2025 DCs**.

| Account | `--account-type` | Password | Pins |
|---------|------------------|----------|------|
| `svc_ascii` | user | ASCII + UPN | user salt; UPN-independence |
| `svc_long` | user | >14 chars | LM blank placeholder |
| `svc_uni1` | user | 0x80–0xFF (`Paßwörd…`) | WDigest **Latin-1 confirmed** + DES ANSI |
| `svc_uni2` | user | >0xFF (Cyrillic+Ω) | NT/AES ok; DES/WDigest = codepage limit |
| `svc_dollar$` | user | known pw | user salt for a `$`-named **user** (NOT a trust — §3.5.1) |
| `TEST$` (real trust) | trust | (salt readout) | **trust salt = krbtgt principal** `SNOW.LABkrbtgtTEST` — §3.5.1 |
| `WSGOLD$` | computer | known machine pw | **computer salt** (`host/…`) |
| `nw_reverse` (existing) | user | reversible-encryption | `Primary:CLEARTEXT` **omitted** (FR-SEC-9) |

*(Built this pass — all 7 committed as fixtures (§3.6). Deferred, since the salt rules they'd exercise are already confirmed above: a real interdomain-trust account, gMSA via `--managed-blob`, and a child-domain second realm.)*

### 3.3 Generation procedure

1. **Create** (RSAT/PowerShell on the DC — precise control of password & type): `New-ADUser -AccountPassword … -Enabled $true`, `New-ADComputer …` (then set a known password), gMSA/trust already exist. (Account creation is via AD cmdlets, not netexec, because we need exact passwords and types.)
2. **Cross-check dump (netexec):** `nxc smb <DC> -u <DA> -p <pw> --ntds` (or impacket `secretsdump.py -just-dc-user <acct> <REALM>/<DA>@<DC>`) → capture NT/LM + the `aes256-cts-hmac-sha1-96` / `aes128…` / `des-cbc-md5` lines.
3. **Primary dump (DSInternals):** `Get-ADReplAccount -SamAccountName <acct> -Server <DC> -Credential $c | Format-Custom` → capture NT/LM, `KerberosNew` keys **+ Salt**, and the **WDigest** array (29).
4. **Reconcile & commit:** assert netexec≡DSInternals on the overlap; write one fixture per account (§3.4).

### 3.4 Fixture format

One JSON per account under `tests/fixtures/secrets/<account>.json`, committed (throwaway test accounts; **no lab IPs/DC names**, §7 Q5):

```json
{
  "password": "Passw0rd!Test",            // or "password_hex" for blobs/managed
  "managed_blob": false,
  "identity": { "sam_account_name": "svc_ascii", "realm_dns": "<REALM>",
                "account_type": "user", "netbios_domain": "<NB>",
                "dns_domain": "<REALM>", "upn": "svc_ascii@<REALM>" },
  "expected": {
    "nt_hash": "…", "lm_hash": "…", "rc4_hmac": "…",
    "des_cbc_md5": "…", "aes128_cts_hmac_sha1_96": "…", "aes256_cts_hmac_sha1_96": "…",
    "kerberos_salt": "<REALM>SVC_ASCII…",
    "wdigest": ["…29 entries…"]
  },
  "source": "DSInternals Get-ADReplAccount; cross-checked netexec --ntds"
}
```

The test loads each fixture, runs `compute_secrets(Identity(**identity), password)`, and asserts field-by-field equality (skipping fields the inputs can't produce).

### 3.5 The two deciders — both RESOLVED against real AD (2026-06-07)

- **3.5.1 Trust salt — ✅ CORRECTED by real data.** The `svc_dollar$` "proxy" was a red herring: a plain user account ending in `$` salts as a **user** (`SNOW.LABsvc_dollar$`), which is *not* how a real trust is salted. The genuine interdomain trust account **`TEST$`** (in `snow.lab`, partner `test.snow.lab`) salts as **`SNOW.LABkrbtgtTEST`** = `UPPER(realm)+"krbtgt"+sam-without-$` (the RFC4120 `krbtgt/<partner>` principal salt; DSInternals `DefaultSalt`). `compute_kerberos_salt(TRUST, "TEST$", "snow.lab")` reproduces it, and [02 §1] was corrected accordingly. (`svc_dollar$` is now an `account_type=user` fixture.)
- **3.5.2 WDigest encoding ([02 D3]) — ✅ Latin-1 CONFIRMED.** `svc_uni1`'s stored WDigest matches **Latin-1**, not UTF-8 (`wdigest[01] = 95613e16… = MD5(latin-1("svc_uni1:SNOW:Paßwörd-Demo9"))`). The earlier UTF-8 hypothesis was wrong. The dump also corrected two combos fed back to [02 §6]: **hashes 15–20 use an empty realm** (`principal::password`) and the **implicit UPN is `sAM@dnsdomain`**. All 29 validated 29/29.

### 3.6 Validation results

Built the full matrix on the live lab (accounts created via **bloodyAD** over sealed LDAP — LDAPS had no cert), dumped **all** accounts with both tools, and ran the cross-check:

- **secretsdump `-just-dc` ≡ DSInternals `Get-ADReplAccount`: 46/46 accounts agree** on NT/LM/Kerberos (the D7 hard-fail cross-check passes). DSInternals ran *on the DC* via WinRM (its replication interop is Windows-only); WDigest was additionally extracted from Linux via impacket's decrypted `supplementalCredentials` (secretsdump does not print WDigest) — all three sources agree.
- **The oracle (from-password) == DSInternals byte-for-byte** for every known-password account: `svc_ascii`, `svc_long`, `svc_uni1`, `svc_dollar$`, `WSGOLD$`, `nw_reverse` → NT + AES256 + AES128 + DES + **WDigest 29/29**. Salts confirmed for user (UPN-independent), computer, and trust.
- **Limitation — `svc_uni2` (Cyrillic, >U+00FF):** NT and AES reproduce, but **DES and WDigest do not** — those characters are outside the DC's ANSI/Latin-1 codepage and AD's lossy best-fit substitution is locale-dependent, out of clean scope. Recorded in the fixture as `oracle_skip_fields`. **The oracle is exact for ASCII and Latin-1/Western passwords.**

Committed: **`tools/tests/fixtures/secrets/*.json`** (7 accounts, real `snow.lab` realm — crypto-bound). The §3.5 corrections were applied to [02 §4/§5/§6/§13].

## 4. Property / invariant tests (no oracle needed)

- **Determinism** (FR-OUT-4): `compute_secrets` twice on the same input ⇒ identical `Secrets`; each formatter twice ⇒ identical bytes.
- **Import audit** (NFR-DEP-3/4): the tool's import graph contains no `impacket`, no `ntdswolf`; `rich` appears only under `format_pretty`.
- **Output allow-list** (FR-SEC-9): no out-of-scope field (AES-SHA2, CLEARTEXT, NTLM-Strong, NetNTLM) ever appears.
- **Dedup equalities** (00 §2.3): `rc4_hmac == nt`; `des-cbc-crc bytes == des-cbc-md5 bytes`.
- **Validation** (FR-VAL): each [MS-SAMR] §3.1.1.8.4 rule (8–12) and the realm/DNS rule has a reject-case test citing the rule; exit code 2.

## 5. Requirement → vector traceability (assembled fully in 04)

Every FR-SEC/FR-VAL/FR-OUT maps to ≥1 artefact above: FR-SEC-1/2 → §2.1; FR-SEC-3 → §2.1 equality; FR-SEC-4 → §2.2; FR-SEC-5/6 → §2.3 + §2.4; FR-SEC-7 → §3 (+ §3.5.2); FR-ACC-2 → §2.4; FR-ACC-5 → §3.5.1; FR-ACC-4 → §3 gMSA row; FR-VAL-* → §4; FR-OUT-4 → §4.

## 6. How this leads into 04

[04](04-TASKLIST.md) turns this into the build order: stand up the published-KAT tests first (red→green per function, zero lab dependency), then the property tests, then wire the **already-committed** lab fixtures (§3.6) as snapshot tests. The two deciders are resolved (§3.5); the corpus is locked.

## 7. Resolved decisions (test-corpus decision log)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Oracle = DSInternals primary + nxc `--ntds` cross-check** | DSInternals is the only source for WDigest 29 + the explicit salt; nxc is an independent NT/LM/Kerberos second opinion from a different codebase. |
| D2 | **Generate the full matrix now** | Real golden data settles the empirical unknowns (trust salt, Latin-1 vs UTF-8) before any code is written; procedure in the [runbook](lab-fixture-runbook.md). |
| D3 | **Extra accounts: reversible-encryption, second realm/child domain, both 2022+2025 DCs** | CLEARTEXT-omission proof; realm-string coverage; per-OS `supplementalCredentials` differences. |
| D4 | **Whole `--ntds` once per DC, sliced per account** | Fewer DC hits; one dump per OS, accounts grepped out for the cross-check. |
| D5 | **Fixtures committed, genericized** | Throwaway accounts, hashes only, realm → `<REALM>`, **no lab IPs/DC names/real domain** (undercover rule). CI reproducible offline. |
| D6 | **gMSA: pull the real managed-password blob** | `Get-ADServiceAccount -Properties msDS-ManagedPassword`; a true end-to-end gMSA golden case, not a synthetic stub. |
| D7 | **Cross-check: hard-fail on any disagreement** | Two oracles exist precisely to catch a bug in either before it poisons a fixture. |
| D8 | **Two unicode accounts** (0x80–0xFF decider + >0xFF failure path) | The 0x80–0xFF account cleanly decides Latin-1 vs UTF-8 (§3.5.2); the >0xFF account exercises the Latin-1 encode-failure path. |
| D9 | **Exact published-vector bytes transcribed at 04 build** | From the local RFC3961/3962 + [MS-KILE] §4.4 text; §2 fixes the parameters now, the bytes are pulled verbatim during the build (no fabrication). |
| D10 | **No history fixtures** | Per 00 D9 there is no history mode; `ntPwdHistory` = NT-of-prior-password is documentation only. |
| D11 | **Determinism corpus = small seeded table** | A fixed representative set (runtime randomness is disallowed for determinism); no hypothesis dependency. |

The two empirical results that feed back into the design the moment they're dumped: **§3.5.1** (trust salt confirms [02 §1]) and **§3.5.2** (the Latin-1-vs-UTF-8 WDigest decider, [02 D3]).
