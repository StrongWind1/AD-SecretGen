# Windows Secrets Generator — 00: Objective, Scope & Background

Deliverable 1 of 5. The set flows: **00 Objective/Scope/Background → [01 Requirements](01-REQUIREMENTS.md) → [02 Design](02-DESIGN.md) → [03 References & Test Vectors](03-REFERENCES-AND-TEST-VECTORS.md) → [04 Tasklist](04-TASKLIST.md).** This document fixes *what we are building and why*, and the domain facts every later document depends on. It introduces no requirements, design, or tasks — those are downstream. Scope here is **locked** by the decision log in §6.

## 1. Objective

Build one self-contained Python script, `tools/gen_secrets.py`, that takes a **password** (a cleartext string, or a raw password blob as hex) plus an **account identity** and emits every credential value Active Directory stores **PEK-encrypted in `NTDS.dit`** for that account — each byte-for-byte identical to what a real domain controller would compute and store.

It is the **inverse of NTDSWolf**. NTDSWolf decrypts secrets *out of* a database; this tool derives the same secrets *from* a password. The two must agree, so the tool is a deterministic **reference oracle**: given known inputs it produces ground-truth values, letting NTDSWolf's extraction be validated against independently-derived truth instead of against itself (this closes the "richer-fixture verification" gap).

One framing decides the whole scope: **this is a *hasher*, not a *decryptor*.** Its unit of work is "a password/blob → its hashes and keys." It does not unwrap the PEK, derive a gMSA password from a KDS root key, decrypt LAPS, or read BitLocker keys — those are extraction/decryption (NTDSWolf's job). See §2.4.

## 2. Background — the secret landscape in `NTDS.dit`

### 2.1 The encryption chain

Credential material in the database is protected in layers; the tool produces the **innermost plaintext** — the value that exists *before* any of this is applied:

1. **BOOTKEY / SYSKEY** — assembled from the `SYSTEM` registry hive (the LSA `JD`/`Skew1`/`GBG`/`Data` class keys). **Not in `NTDS.dit`.**
2. **PEK** (Password Encryption Key) — stored in `NTDS.dit` as the `pekList` attribute (per [MS-ADTS], `pekList` is internal: "Access is never granted"), encrypted under the bootkey: RC4 keyed by `MD5(bootkey + salt)` pre-Server-2016, **AES-256-CBC** (with a stored IV) on Server 2016+.
3. **Secret attributes** — each value PEK-encrypted. [MS-DRSR] models this in the replication path: an encrypted value is an `ENCRYPTED_PAYLOAD` ([MS-DRSR] §4.1.10.2.19), produced by `EncryptValuesIfNecessary` ([MS-DRSR] §4.1.10.5.11), for any attribute where `IsSecretAttribute` ([MS-DRSR] §4.1.10.3.11) is true. On modern DCs the per-value cipher is AES-128-CBC with a per-value IV.
4. **Per-RID DES layer** — the NT and LM hashes get an *additional* obfuscation: the 16-byte hash split into two 8-byte halves, each DES-encrypted under a key derived from the account RID. History attributes concatenate the per-RID-encrypted hashes.

The tool reproduces the value at the bottom of this stack (the raw NT hash, raw Kerberos key, etc.); layers 1–4 are NTDSWolf's concern. *(The `IsSecretAttribute` set and the `ENCRYPTED_PAYLOAD` structure are normative in [MS-DRSR]; the supplementalCredentials structures are normative in [MS-SAMR]. The on-disk JET PEK blob format is not a published spec — it is community-documented, e.g. impacket/ntdissector `crypto.py`, DSInternals — but the generator never touches it.)*

### 2.2 The PEK-encrypted *secret attributes*

The authoritative set is `IsSecretAttribute` ([MS-DRSR] §4.1.10.3.11): `{ currentValue, dBCSPwd, initialAuthIncoming, initialAuthOutgoing, lmPwdHistory, ntPwdHistory, priorValue, supplementalCredentials, trustAuthIncoming, trustAuthOutgoing, unicodePwd }` (plus `pekList` itself, the key). What each holds, and whether it is *derived from a password*:

| Secret attribute (LDAP) | Holds | Password-derived? |
|-------------------------|-------|-------------------|
| `unicodePwd` | NT hash | ✅ |
| `dBCSPwd` | LM hash | ✅ |
| `ntPwdHistory` | prior NT hashes | ✅ (same algorithm) |
| `lmPwdHistory` | prior LM hashes | ✅ (same algorithm) |
| `supplementalCredentials` | Kerberos keys, WDigest, optional cleartext, NTLM-Strong-NTOWF | ✅ (mostly — see §2.3) |
| `trustAuthIncoming` / `trustAuthOutgoing` | trust passwords (current + previous) | ✅ (via the trust password) |
| `initialAuthIncoming` / `initialAuthOutgoing` | initial trust auth | ✅ (trust password) |
| `currentValue` / `priorValue` (on `secret` objects) | LSA secrets, **DPAPI domain backup keys** | ❌ arbitrary blob |
| `pekList` | the PEK itself | ❌ random key |

### 2.3 Inside `supplementalCredentials` — and the duplicates

`supplementalCredentials` is a `USER_PROPERTIES` container ([MS-SAMR] §2.2.10) whose key-packages are:

- **Primary:Kerberos** ([MS-SAMR] §3.1.1.8.11.4) → `des-cbc-md5`, `des-cbc-crc` (salted with the logon name, 4096 iterations).
- **Primary:Kerberos-Newer-Keys** ([MS-SAMR] §3.1.1.8.11.6) → `aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96` (salted, 4096 iterations) (+ DES if enabled). Enctype IDs per [MS-SAMR] §2.2.10.8 are **1, 3, 17, 18** only.
- **Primary:WDigest** ([MS-SAMR] §3.1.1.8.11.3.1) → 29 MD5 digests over login/domain combinations.
- **Primary:CLEARTEXT** ([MS-SAMR] §3.1.1.8.11.5) → the cleartext password, stored only when `userAccountControl` has `ENCRYPTED_TEXT_PWD_ALLOWED` (`0x0080`) (the Enable-Per-User-Reversibly-Encrypted-Password control, [MS-ADTS] §6.1.1.2.7.46).
- **Primary:NTLM-Strong-NTOWF** ([MS-SAMR] §3.1.1.8.11.7) → a **random** 16-byte value (Server 2016+).

Collapsing duplicates is the central scoping move — **the same value appears under many names:**

- **NT hash** = `unicodePwd` = every `ntPwdHistory` entry = Kerberos **RC4-HMAC** (etype 23) = `MD4(`gMSA/dMSA managed-password blob`[:256])` (validated). One 16-byte value.
- **LM hash** = `dBCSPwd` = every `lmPwdHistory` entry.
- **Kerberos DES** — `des-cbc-crc` (etype 1) and `des-cbc-md5` (etype 3) are the **same 8-byte key**; they differ only in the on-wire checksum.

So everything password-derived and PEK-encrypted reduces to **six** algorithms: NT hash, LM hash, Kerberos DES, AES128, AES256, WDigest. That six-way set is the locked scope (§3) and the seed of [01 Requirements](01-REQUIREMENTS.md).

### 2.4 Account / object-type coverage

Because the tool is a hasher, it covers every object **whose secret is itself a password/blob** — and stops where a secret is stored cleartext, independently encrypted, or KDS-derived:

| Object type | Its `NTDS.dit` secret | Tool coverage |
|-------------|------------------------|---------------|
| **User** | password | ✅ directly (`--password`) |
| **Computer** | machine password (random UTF-16LE blob) | ✅ `--password-hex`; `host/` salt rule |
| **sMSA / MSA** (`msDS-ManagedServiceAccount`) | auto-managed password (computer-like) | ✅ `--password-hex` |
| **gMSA / dMSA** (`msDS-GroupManagedServiceAccount` / `msDS-DelegatedManagedServiceAccount`) | 256-byte managed-password **blob derived from the KDS root key** | ✅ **from the blob** (`MD4(blob[:256]) = unicodePwd NT hash`, validated); the KDS→blob derivation (a decryption step NTDSWolf performs) is **out of scope** for this oracle |
| **Trust** (`trustAuth*`) | trust password blob | ✅ from the blob — **⚠ the trust-account Kerberos salt rule is an open research item** carried to 01/02 |
| **LAPS v1** (`ms-Mcs-AdmPwd`) | **cleartext**, ACL-protected (not PEK-encrypted) | ⚠ not a derivation — feed the cleartext and it hashes it; the tool does not extract it |
| **LAPS v2** (`msLAPS-EncryptedPassword`) | **DPAPI-NG-encrypted** (KDS-keyed) | ⚠ not a derivation — decrypt (KDS, out of scope), then feed the cleartext |
| **BitLocker** (`msFVE-RecoveryPassword`) | a 48-digit **recovery key** | ❌ not a credential you hash — fully out of scope |

The honest one-line boundary: **we cover users, computers, MSA, and gMSA/dMSA/trusts at the point you hold their password blob.** We are not a KDS deriver, a DPAPI-NG decryptor, or a BitLocker tool.

## 3. Scope

### 3.1 In scope — the six (locked)

| Secret the tool emits | Algorithm | Covers these PEK-encrypted forms |
|-----------------------|-----------|----------------------------------|
| **NT hash** (NTOWFv1) | `MD4(UTF-16LE(pw))` | `unicodePwd`, `ntPwdHistory[*]`, Kerberos **RC4-HMAC** (etype 23) |
| **LM hash** (LMOWFv1) | `DES-ECB("KGS!@#$%")` ×2 over the uppercased OEM-14 password | `dBCSPwd`, `lmPwdHistory[*]` |
| **Kerberos DES key** (etype 1 = etype 3) | `mit_des_string_to_key` | `Primary:Kerberos` — `des-cbc-crc` **and** `des-cbc-md5` (same key) |
| **Kerberos AES128-CTS** (etype 17) | `DK(PBKDF2-HMAC-SHA1, "kerberos")`, 16 B | `Primary:Kerberos-Newer-Keys` |
| **Kerberos AES256-CTS** (etype 18) | `DK(PBKDF2-HMAC-SHA1, "kerberos")`, 32 B | `Primary:Kerberos-Newer-Keys` |
| **WDigest** (29 × MD5) | `MD5("<name>:<realm>:<pw>")` over 29 identity combos | `Primary:WDigest` |

These are computed from a cleartext password or a raw blob (`--password-hex`, hashing `blob[:256]` for managed-password blobs), for any account type in §2.4 whose secret is a password/blob, including trust passwords. The output labels each enctype separately — `rc4-hmac` (`= NT hash`), `des-cbc-crc` and `des-cbc-md5` (same key) — even where the bytes are shared. Algorithm detail is deferred to [02 Design](02-DESIGN.md); the testable output contract is [01 Requirements](01-REQUIREMENTS.md).

### 3.2 Out of scope (and why)

- **AES-SHA2 Kerberos enctypes** (19 `aes128-cts-hmac-sha256-128`, 20 `aes256-cts-hmac-sha384-192`; [RFC8009]) — **not** in the [MS-SAMR] §2.2.10.8 enctype table (only 1/3/17/18), Server-2025-only, and their storage in `supplementalCredentials` is unconfirmed. Out under the strict-spec scope; revisit if confirmed stored.
- **Client-side cached / derived credentials NOT in `NTDS.dit`** — **DCC1 / MSCASH** (hashcat 1100), **DCC2 / MSCASH2** (hashcat 2100), and the **DPAPI master-key pre-keys** are password-derived but live in the `SECURITY` hive / client, never in the `.dit`. Out (they're the line between "NTDS.dit oracle" and "general hash tool").
- **NTLM network responses** (NetNTLMv1/v2, LMv1/LMv2) and **Kerberos cracking blobs** (Kerberoast / AS-REP) — wire/ephemeral forms that need a server challenge / SPN / ticket structure; never stored in the `.dit`. With them go the NTLM session keys, `NTOWFv2`, and the SAMR password-change CEK.
- **`Primary:NTLM-Strong-NTOWF`** — random by spec; not derivable.
- **`Primary:CLEARTEXT`** — *is* the input password, not a derivation; omitted from output.
- **The `supplementalCredentials` container serialization** — we emit the credential *values*, not the `USER_PROPERTIES` wrapper bytes.
- **KDS root-key → gMSA/dMSA password derivation, LAPS v1/v2 extraction or decryption, BitLocker recovery keys, DPAPI domain backup keys** — extraction/decryption, not password derivation; NTDSWolf's job (§2.4).
- **The bootkey → PEK chain and the per-RID DES layer** — NTDSWolf removes them; the generator emits the value before them.

## 4. How this leads into 01 (Requirements)

The §3.1 in-scope set becomes the **functional requirements** in [01](01-REQUIREMENTS.md) ("the tool *shall* emit NT/LM/Kerberos/WDigest for the §2.4 account types, in the formats of [02](02-DESIGN.md)"). The constraints implied here — spec-compliance, self-containment, the dependency policy (pycryptodome + rich; **never import impacket**), the source hierarchy (spec → DSInternals → impacket, [03](03-REFERENCES-AND-TEST-VECTORS.md)) — become the **non-functional requirements**. The one open research item (the trust-account Kerberos salt, §2.4) is carried into 01 as a requirement to resolve before that secret is locked.

## 5. Glossary (terms reused verbatim from the specs)

PEK / `pekList`, *secret attribute* ([MS-DRSR] §4.1.10.3.11), `ENCRYPTED_PAYLOAD`, `supplementalCredentials` / `USER_PROPERTIES` ([MS-SAMR] §2.2.10), NTOWFv1 / LMOWFv1 ([MS-NLMP] §3.3.1), enctype / `string-to-key` ([RFC3961]), KDS root key, managed password. The full glossary with citations lives in [03](03-REFERENCES-AND-TEST-VECTORS.md); this document uses the spec terms only.

## 6. Resolved decisions (scope decision log)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Scope = NTDS.dit-stored, password-derived, deduplicated** — exactly the six of §3.1 | Confirmed after reviewing NTDSWolf's emitted fields and ntdissector's decoders (both decode the same `.dit` set) and the full "generate-from-a-password" landscape; nothing password-derived is missing *within* the `.dit`. DCC1/DCC2, DPAPI pre-keys, and wire/cracking forms are deliberately excluded as not stored in the `.dit`. |
| 2 | **Trusts: supported**; trust-account Kerberos **salt to be verified** | Trust keys are NT/Kerberos of the trust password (§2.4); the exact salting principal for a TDO `<REMOTE>$` account is an unverified gap, carried to 01/02. |
| 3 | **gMSA / dMSA: from the managed-password blob only** | The KDS-root-key → 256-byte-blob derivation is a decryption step (NTDSWolf performs it offline); this oracle's input is the blob itself, and the usable secrets (NT hash + Kerberos keys) come from hashing `blob[:256]`. |
| 4 | **Managed-blob input: hash `blob[:256]`** | Validated: `MD4(msDS-ManagedPassword.CurrentPassword[:256]) = unicodePwd` NT hash. |
| 5 | **AES-SHA2 (etype 19/20): out** | Strict to the [MS-SAMR] §2.2.10.8 enctype table (1/3/17/18); AES-SHA2 storage in the `.dit` is unconfirmed. |
| 6 | **LAPS v1/v2: out as targets** (hash-if-fed) | Not derivations — v1 is stored cleartext, v2 is DPAPI-NG-encrypted; extraction/decryption is NTDSWolf's job. |
| 7 | **BitLocker: fully out** | A recovery key is not a credential you hash. |
| 8 | **`Primary:CLEARTEXT`: omitted** | It is the input password, not a derived secret. |
| 9 | **History: no special mode** | `ntPwdHistory`/`lmPwdHistory` are just NT/LM of prior passwords; each `--password` is hashed independently. |
| 10 | **Output: separate labelled lines** | `rc4-hmac` (`= NT`) and `des-cbc-crc`/`des-cbc-md5` (same key) each emitted with a note — explicit and tool-compatible. |
| 11 | **Specs local** | `MS-ADTS-240610` and `MS-DRSR-171201` downloaded and converted (pandoc) into `tools/`, alongside `MS-SAMR`/`MS-NLMP`. |
| 12 | **Secret-attribute table: LDAP names only** | `ATTk` column ids add little for a generator that never touches the on-disk format. |
| 13 | **Doc set: the five named here** | `00-OBJECTIVE-SCOPE-AND-BACKGROUND.md` confirmed; the old `00–04` research files are retired as the new set is built. |
