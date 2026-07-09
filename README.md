<h1 align="center">AD-SecretGen</h1>

<p align="center"><strong>Derive AD password hashes and Kerberos keys from a password.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/AD-SecretGen/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/AD-SecretGen/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ad-secretgen/"><img src="https://img.shields.io/pypi/v/ad-secretgen.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind1.github.io/AD-SecretGen/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind1.github.io/AD-SecretGen/">Documentation</a> &bull;
  <a href="https://strongwind1.github.io/AD-SecretGen/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind1.github.io/AD-SecretGen/reference/cli/">CLI reference</a>
</p>

`ad-secretgen` takes a **password** (cleartext, or a raw password blob) plus an **account identity** and computes every password-derived secret that Active Directory stores **PEK-encrypted in `NTDS.dit`** for that account - byte-for-byte what a domain controller would store.

It is the **inverse of NTDSWolf**: NTDSWolf decrypts secrets *out of* a database, this derives the same secrets *from* a password. It is a deterministic reference oracle, validated byte-for-byte against real AD via three independent paths (NTDSWolf reading the `.dit`, DSInternals `Get-ADReplAccount` over the wire, and the RFC3961/3962 + MS known-answer vectors).

It is a *hasher*, not a decryptor: it never touches the bootkey/PEK chain, KDS-based gMSA derivation, LAPS, or BitLocker - those are extraction/decryption (NTDSWolf's job).

## Features

- Computes every password-derived secret AD stores PEK-encrypted: NT, LM, RC4-HMAC, Kerberos DES / AES128 / AES256, and all 29 WDigest hashes.
- The inverse of NTDSWolf - derives secrets *from* a password instead of decrypting them *out of* a `.dit`.
- Deterministic reference oracle, validated byte-for-byte against real AD (NTDSWolf, DSInternals, and RFC3961/3962 + MS known-answer vectors).
- Single self-contained PEP 723 file - run it straight from the URL with `uv`, nothing to clone or install.
- Handles user, computer, gMSA / dMSA, and trust accounts, each with the correct Kerberos salt rule.
- Text, JSON, and rich `pretty` output formats.

## What it computes

| Output | Algorithm | Spec |
|--------|-----------|------|
| **NT hash** (NTOWFv1) | `MD4(UTF-16LE(password))` | [MS-NLMP] §3.3.1 |
| **LM hash** (LMOWFv1) | `DES("KGS!@#$%")` over the uppercased OEM-14 password | [MS-NLMP] §3.3.1 |
| **RC4-HMAC** (etype 23) | = the NT hash | [RFC4757] |
| **Kerberos DES** (etype 1 = 3) | `mit_des_string_to_key` | [RFC3961] §6.2 |
| **Kerberos AES128 / AES256** (etype 17 / 18) | `DK(PBKDF2-HMAC-SHA1, "kerberos")`, 4096 iters | [RFC3962] §4 |
| **WDigest** (29 x MD5) | `MD5("name:realm:password")` over 29 identity combinations | [MS-SAMR] §3.1.1.8.11.3.1 |

## Example

```console
$ ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP
[meta]
  account-type : user
  realm        : CORP.LOCAL
  Kerberos salt: CORP.LOCALalice
[ntlm]
  nt : <32-hex NT hash>
  lm : <32-hex LM hash>
[kerberos]
  aes256-cts-hmac-sha1-96 (18) : <64 hex>
  aes128-cts-hmac-sha1-96 (17) : <32 hex>
  rc4-hmac (23)                : <equals ntlm.nt>
[wdigest]
  wdigest[01..29] : <29 x 32-hex>
```

## Installation

Install from [PyPI](https://pypi.org/project/ad-secretgen/) (provides the `ad-secretgen` command and the short alias `adsg`):

```sh
uv tool install ad-secretgen        # recommended
pip install ad-secretgen             # or with pip
```

Or install from source:

```sh
uv tool install git+https://github.com/StrongWind1/AD-SecretGen
```

It's also a single self-contained [PEP 723](https://peps.python.org/pep-0723/) file, so you can run it without installing - `uv` fetches its deps (`pycryptodome` + `rich`) straight from the URL:

```bash
uv run https://raw.githubusercontent.com/StrongWind1/AD-SecretGen/main/ad_secretgen.py \
    --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP
```

## Quick start

```bash
# cleartext user account
ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP

# read the password from stdin (keeps it out of argv / shell history)
ad-secretgen --password - --user alice --realm corp.local

# gMSA: pull the managed password over LDAP with bloodyAD, then derive the keys
B64=$(bloodyAD --host DC -d corp.local -u you -p pw get object 'svc$' --attr msDS-ManagedPassword | sed -n 's/^msDS-ManagedPassword: //p')
ad-secretgen --password-b64 "$B64" --managed-blob --user 'svc$' --realm corp.local --account-type computer

# machine account (raw UTF-16LE password blob as hex)
ad-secretgen --password-hex 4100620063... --user 'WS01$' --realm corp.local --account-type computer

# JSON output (includes a meta block echoing the computed salt)
ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP --format json
```

## Arguments

| Argument | Meaning |
|----------|---------|
| `--password STR` | Cleartext password. `-` reads one line from stdin. |
| `--password-hex HEX` | Raw password **blob** as hex (e.g. a machine account's UTF-16LE password). NT is `MD4(blob)` directly. |
| `--password-b64 B64` | Same, as base64 - the format `bloodyAD` prints for `msDS-ManagedPassword`. |
| `--managed-blob` | Treat the blob as an `MSDS-MANAGEDPASSWORD_BLOB` ([MS-ADTS] §2.2.19) and use its 256-byte `CurrentPassword`. Use this for gMSA/dMSA. |
| `--user SAM` | `sAMAccountName`. **Case matters for the user/trust salt** - see *Casing* below. |
| `--realm DNS` | DNS domain. In AD/Kerberos the domain *is* the **realm** - the two are the same thing. Kerberos uppercases it, so any input case is fine. |
| `--account-type {user,computer,trust}` | Selects the salt rule. **Defaults to `computer`** for `--managed-blob` or a `$`-suffixed `--user` (machine/gMSA); else `user`. Pass it explicitly to override - notably **`trust`** (which also ends in `$`, but uses the krbtgt salt) and any `$`-suffixed *user* account. |
| `--netbios NAME` | NetBIOS domain name. Required to emit the 29 WDigest hashes. |
| `--dns-domain FQDN` | DNS domain FQDN for WDigest (defaults to `--realm`). |
| `--upn UPN` | `userPrincipalName` for WDigest (defaults to `<sam>@<dns-domain>`). |
| `--salt SALT` | Override the computed Kerberos salt **verbatim**. The escape hatch for accounts whose salt isn't derivable from the identity (see *Casing*). |
| `--format {text,json,pretty}` | Output format (default `text`). |

Exactly one of `--password` / `--password-hex` / `--password-b64` is required. Identity inputs are only needed for the secrets that use them: with no `--realm` the Kerberos keys are skipped, with no `--netbios` the WDigest hashes are skipped (each with a stderr note).

## Casing - read this

`NT`, `LM`, and `RC4-HMAC` depend **only on the password** - the casing of `--user`/`--realm` is irrelevant to them. But the **Kerberos keys (DES/AES) are salted**, and the salt's casing rules differ by account type:

| account type | salt | casing behaviour |
|--------------|------|------------------|
| **user** | `UPPER(realm) + sAMAccountName` | `sAMAccountName` is **case-preserved** - you must pass the exact stored case |
| **computer / gMSA** | `UPPER(realm) + "host" + lower(name) + "." + lower(dns)` | name and DNS are **lowercased** - any input case works |
| **trust** | `UPPER(realm) + "krbtgt" + name-without-$` | the partner flat-name is case-preserved (as stored) |

The realm - Kerberos's name for the AD **domain** - is always uppercased, so `--realm corp.local`, `CORP.LOCAL`, and `Corp.Local` are equivalent.

**The footgun:** for **user** and **trust** accounts, passing the wrong `sAMAccountName` case (`ALICE` vs `alice`) produces a *wrong but valid-looking* salt and therefore wrong AES/DES keys - with **no error**. If you don't know the exact stored case, get it from the KDC (next section) and pass it via `--salt`, which skips salt construction entirely.

**WDigest is case-insensitive by design.** The 29 hashes *are* the casing permutations - as-stored, all-lowercase, all-uppercase, and mixed, for the NetBIOS, DNS, and `DOMAIN\user` forms. That is exactly why digest authentication matches a username in any case: AD pre-stores every common casing. (To reproduce the 29 byte-for-byte you still want the as-stored case for hash #1, but the all-lower / all-upper entries match regardless.)

## Finding the casing - let the KDC tell you (CredWolf)

You never have to guess the casing. **The KDC returns the authoritative salt** - which carries the exact realm and username casing - in the `PA-ETYPE-INFO2` pre-auth data of its response to a *bare* AS-REQ. This is **not a login attempt**: it does not increment the bad-password counter and cannot lock the account out, and you only need the **username**, not the password.

[CredWolf](https://github.com/StrongWind1/CredWolf) implements this. When it does Kerberos AES authentication it sends the bare AS-REQ, reads the salt, recovers the correctly-cased username from it, and reports e.g.:

```
[VERBOSE] Username case corrected by KDC: ALICE -> alice
```

Demonstrated against a live KDC - every casing you type comes back as the one stored salt:

```
typed --user ALICE      -> KDC salt = CORP.LOCALalice              corrected username = 'alice'
typed --user Alice      -> KDC salt = CORP.LOCALalice              corrected username = 'alice'
typed --user alice      -> KDC salt = CORP.LOCALalice              (already correct)
```

To use it with `ad-secretgen`:

```bash
# 1) get the salt from the KDC (CredWolf with AES + -v prints the corrected name; or read its salt directly)
# 2) feed it back - either as the corrected username...
ad-secretgen --user alice --realm corp.local --password 'P@ssw0rd!'
#    ...or, most robustly, as the salt verbatim:
ad-secretgen --salt 'CORP.LOCALalice' --password 'P@ssw0rd!' --user alice --realm corp.local
```

The `--salt` route is bulletproof: it also handles accounts whose salt is **not** `REALM+username` at all - most notably the built-in **Administrator** (and **krbtgt**), whose salt is frozen from the DC's *original install-time hostname* (e.g. `WIN-ABC123Administrator`). For those, username-casing recovery can't help - but the raw KDC salt fed to `--salt` is exact.

Caveat (documented by CredWolf): this trick needs **AES** (which is what triggers salt retrieval) and does **not** work for **AS-REP-roastable** accounts - with pre-auth disabled the KDC returns an AS-REP with no `PA-ETYPE-INFO2`, so there is no salt to read. For those, supply the exact case yourself or use RC4 (which has no salt).

## Pulling a gMSA password over LDAP (bloodyAD)

If you can read a gMSA's `msDS-ManagedPassword` (you are in `PrincipalsAllowedToRetrieveManagedPassword`, or you are a Domain Admin), you can construct its Kerberos and NTLM keys entirely offline:

```bash
B64=$(bloodyAD --host DC -d corp.local -u you -p pw get object 'svc$' --attr msDS-ManagedPassword | sed -n 's/^msDS-ManagedPassword: //p')
ad-secretgen --password-b64 "$B64" --managed-blob --user 'svc$' --realm corp.local --account-type computer
```

`--managed-blob` parses the `MSDS-MANAGEDPASSWORD_BLOB`, extracts the 256-byte `CurrentPassword`, and derives `NT = MD4(CurrentPassword)` plus the AES keys with the **computer** (`host/`) salt. Because gMSAs are computer-class, casing of `--user`/`--realm` doesn't matter here. The managed password rotates (~30 days), so re-pull after a rotation. (dMSA is different - its managed password isn't LDAP-retrievable this way.)

## Output formats

All three formats carry the **same information**, organised into the same sections - **meta** (the inputs: account-type, realm/domain, `sAMAccountName`, the echoed **password**, the `Kerberos salt`, and any `--netbios`/`--dns-domain`/`--upn` provided), **ntlm** (`nt`, `lm`), **kerberos** (the enctypes, in etype order with the number in parens: `des-cbc-crc (1)`, `des-cbc-md5 (3)`, `aes128-cts-hmac-sha1-96 (17)`, `aes256-cts-hmac-sha1-96 (18)`, `rc4-hmac (23)`), and **wdigest** (the 29 `wdigest[01..29]` hashes) - followed by any **skipped** entries. Nothing is shown in one format and hidden in another; a row or section is dropped (in every format alike) only when it has no value. They differ only in layout:

- **text** (default) - `[section]` blocks of aligned `label : value` lines, then a trailing `[skipped]` block.
- **json** - each section is a nested object (`meta` / `ntlm` / `kerberos`), with `wdigest` and `skipped` as arrays; machine-readable.
- **pretty** - each section is a grouped `rich` panel (META / NTLM / KERBEROS / WDIGEST).

The PBKDF2 iteration count is a fixed 4096 ([RFC3962] §4) and is documented rather than echoed.

> **Password echo & the hex rule:** `meta` echoes the **password you supplied** (cleartext for `--password`/stdin; the raw blob as hex for `--password-hex`/`-b64`/`--managed-blob`) so the output is a self-documenting record - note it lands in stdout/redirects/scrollback. Any meta value with a character outside **printable ASCII (`0x21`-`0x7E`)** - space, control, or non-ASCII - is **UTF-8 hex-encoded** and its label/key marked `... (hex)` / `..._hex` (e.g. a Cyrillic `sAMAccountName` becomes `sAMAccountName (hex) : d090...`), so a terminal never receives raw bytes and the value is unambiguous.

> **Salt:** the `Kerberos salt` (shown in **meta**) salts **DES (etypes 1, 3) and AES (17, 18)** - all four use the *same* salt. **RC4 (etype 23) is the only saltless enctype**: its key is just the NT hash, so `kerberos.rc4-hmac` equals `ntlm.nt` and is derivable without a realm (which is why it's always present). AES-SHA2 (etypes 19/20) are out of scope - AD's KDC doesn't store them.

## Limitations and notes

- **DES & WDigest of non-ASCII passwords** are locale-dependent: DES uses the DC's ANSI codepage (cp1252), WDigest uses ISO-8859-1. A password outside that codepage (e.g. Cyrillic) or a **binary gMSA blob** can't be reproduced for those two algorithms - NT and AES still are. Such fields are skipped with a stderr note.
- **Administrator / krbtgt** carry frozen install-time salts - use `--salt`.
- **NoLMHash** (the modern default) means AD stores a blank `LM`; this tool emits the *true* LM hash of the password.
- **Out of scope** (by design): AES-SHA2 (etype 19/20), `Primary:CLEARTEXT`, the random `NTLM-Strong-NTOWF`, NetNTLM wire responses, DCC1/DCC2, DPAPI pre-keys.

## Validation

Cross-validated byte-for-byte against real AD: **NTDSWolf** (reading an `ntdsutil` IFM `.dit`) **= DSInternals** (`Get-ADReplAccount` dcsync) **= AD-SecretGen** (from password) across NT, RC4, DES, AES128, AES256, salt, and all 29 WDigest hashes - for user, computer, trust, gMSA, and child-domain accounts. The test suite (`tests/`) pins this with lab fixtures plus the published RFC3961/3962 and NT/LM known-answer vectors.

```bash
make check          # ruff + ty + pytest + docs
# ...or individually:
uv run pytest       # fixtures + KATs
uv run ruff check . && uv run ty check
```

## Credits

Built with [pycryptodome](https://github.com/Legrandin/pycryptodome) and [rich](https://github.com/Textualize/rich). Cross-validated against [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) and [NTDSWolf](https://github.com/StrongWind1/NTDSWolf).

## Related tools

Other projects in this collection:

- [NTDSWolf](https://github.com/StrongWind1/NTDSWolf) - offline NTDS.dit parser and credential extractor
- [CredWolf](https://github.com/StrongWind1/CredWolf) - Active Directory credential validation
- [KerbWolf](https://github.com/StrongWind1/KerbWolf) - Kerberos roasting and hash extraction toolkit
- [Kerberos](https://github.com/StrongWind1/Kerberos) - Kerberos in Active Directory: protocol, security, and attacks

## Disclaimer

AD-SecretGen is intended for authorized security testing, research, and education only. Use it only with credentials and accounts you are authorized to test. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## License

[Apache License 2.0](LICENSE)
