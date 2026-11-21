<h1 align="center">AD-SecretGen</h1>

<p align="center"><strong>Give it a password. Get back every hash and Kerberos key a domain controller would store for it.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/AD-SecretGen/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/AD-SecretGen/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ad-secretgen/"><img src="https://img.shields.io/pypi/v/ad-secretgen.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/AD-SecretGen/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/AD-SecretGen/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind.dev/AD-SecretGen/#quick-start">Quick start</a> &bull;
  <a href="https://strongwind.dev/AD-SecretGen/reference/cli/">CLI reference</a> &bull;
  <a href="https://strongwind.dev/AD-SecretGen/guide/casing/">Salt casing</a> &bull;
  <a href="https://strongwind.dev/AD-SecretGen/">Documentation</a>
</p>

---

AD-SecretGen takes a password (cleartext, or a raw password blob) plus an account identity and computes every password-derived secret that Active Directory stores PEK-encrypted in `NTDS.dit` for that account, byte-for-byte what a domain controller would store. It is the inverse of [NTDSWolf](https://github.com/StrongWind1/NTDSWolf): NTDSWolf decrypts these secrets out of a database, AD-SecretGen derives them from a password. It is a hasher, not a decryptor, so the bootkey/PEK chain, KDS-based gMSA derivation, LAPS, and BitLocker stay NTDSWolf's job.

## Example

```console
$ ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP
[meta]
account-type                 : user
realm (AD domain)            : corp.local
sAMAccountName               : alice
password                     : P@ssw0rd!
Kerberos salt                : CORP.LOCALalice
netbios-domain               : CORP

[ntlm]
nt                           : 217e50203a5aba59cefa863c724bf61b
lm                           : 921988ba001dc8e122c34254e51bff62

[kerberos]
des-cbc-crc (1)              : d05d408f4f2f86fb
des-cbc-md5 (3)              : d05d408f4f2f86fb
aes128-cts-hmac-sha1-96 (17) : 905512bfeea43e146ec5b297982c3833
aes256-cts-hmac-sha1-96 (18) : fcb4290ed558a893ee20e8a55c0a03dbe84787465f245b584b61aaa110f7c663
rc4-hmac (23)                : 217e50203a5aba59cefa863c724bf61b

[wdigest]
wdigest[01]                  : d89dc2486a04381e56bcc621a4b9a0b5
...
```

The `[wdigest]` block continues with all 29 WDigest hashes.

## Features

- **Every password-derived secret**: NT, LM, RC4-HMAC, Kerberos DES / AES128 / AES256, and all 29 WDigest hashes.
- **Deterministic reference oracle**: validated byte-for-byte against real AD, where NTDSWolf (reading an `ntdsutil` IFM `.dit`), DSInternals (`Get-ADReplAccount` over DCSync), and AD-SecretGen (from the password) agree on NT, RC4, DES, AES128, AES256, the salt, and all 29 WDigest hashes for user, computer, trust, gMSA, and child-domain accounts. The test suite (`tests/`) pins this with lab fixtures plus the published RFC3961/3962 and NT/LM known-answer vectors.
- **Every account type**: user, computer, gMSA / dMSA, and trust accounts, each with the correct Kerberos salt rule, plus `--salt` for accounts whose salt cannot be derived from the identity.
- **gMSA keys offline**: `--password-b64` takes `msDS-ManagedPassword` as bloodyAD prints it, and `--managed-blob` extracts its `CurrentPassword` and derives the NT hash and AES keys ([gMSA / dMSA](https://strongwind.dev/AD-SecretGen/guide/gmsa/)).
- **Single file**: one self-contained PEP 723 script, so `uv` can run it straight from its URL with nothing to clone or install.
- **Three output formats**: text (default), JSON, and rich `pretty`, all carrying the same information ([Output formats](https://strongwind.dev/AD-SecretGen/guide/output-formats/)).

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

Or run the single [PEP 723](https://peps.python.org/pep-0723/) file without installing; `uv` fetches its dependencies (`pycryptodome` and `rich`) itself:

```sh
uv run https://raw.githubusercontent.com/StrongWind1/AD-SecretGen/main/ad_secretgen.py \
    --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP
```

## Quick start

```sh
# read the password from stdin (keeps it out of argv / shell history)
ad-secretgen --password - --user alice --realm corp.local

# gMSA: pull the managed password over LDAP with bloodyAD, then derive the keys
B64=$(bloodyAD --host DC -d corp.local -u you -p pw get object 'svc$' --attr msDS-ManagedPassword | sed -n 's/^msDS-ManagedPassword: //p')
ad-secretgen --password-b64 "$B64" --managed-blob --user 'svc$' --realm corp.local --account-type computer

# machine account (raw UTF-16LE password blob as hex)
ad-secretgen --password-hex 4100620063... --user 'WS01$' --realm corp.local --account-type computer

# account with a non-standard salt (e.g. the built-in Administrator)
ad-secretgen --password 'P@ssw0rd!' --user Administrator --realm corp.local --salt 'WIN-ABC123Administrator'

# JSON output (includes a meta block echoing the computed salt)
ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP --format json
```

Every argument, and the limits on non-ASCII passwords and LM under NoLMHash: [CLI reference](https://strongwind.dev/AD-SecretGen/reference/cli/).

## What it computes

| Output | Algorithm | Spec |
| --- | --- | --- |
| **NT hash** (NTOWFv1) | `MD4(UTF-16LE(password))` | [MS-NLMP] §3.3.1 |
| **LM hash** (LMOWFv1) | `DES("KGS!@#$%")` over the uppercased OEM-14 password | [MS-NLMP] §3.3.1 |
| **RC4-HMAC** (etype 23) | = the NT hash | [RFC4757] |
| **Kerberos DES** (etype 1 = 3) | `mit_des_string_to_key` | [RFC3961] §6.2 |
| **Kerberos AES128 / AES256** (etype 17 / 18) | `DK(PBKDF2-HMAC-SHA1, "kerberos")`, 4096 iters | [RFC3962] §4 |
| **WDigest** (29 x MD5) | `MD5("name:realm:password")` over 29 identity combinations | [MS-SAMR] §3.1.1.8.11.3.1 |

## Casing and the Kerberos salt

NT, LM, and RC4-HMAC depend only on the password. The DES and AES keys are salted, and for user and trust accounts the salt keeps the `sAMAccountName` case as stored: pass `ALICE` when AD stores `alice` and you get a wrong but valid-looking salt, so wrong AES/DES keys, with no error. Computer and gMSA salts lowercase the name and DNS domain, and the realm is always uppercased, so their input case does not matter. `--account-type` defaults to `computer` for `--managed-blob` or a `$`-suffixed `--user`, else `user`; pass `trust` for a trust account and `user` for a user account whose name ends in `$`.

WDigest is case-insensitive by design: the 29 hashes are the casing permutations. To reproduce all 29 byte-for-byte you still want the as-stored case for hash #1; the all-lower and all-upper entries match regardless.

If you don't know the stored case, ask the KDC. It returns the authoritative salt in `PA-ETYPE-INFO2` in reply to a bare AS-REQ, which is not a login attempt and cannot lock the account out. [CredWolf](https://github.com/StrongWind1/CredWolf) does this when it authenticates with Kerberos AES and prints `[VERBOSE] Username case corrected by KDC: ALICE -> alice`. Against a live KDC, every casing comes back as the one stored salt:

```text
typed --user ALICE      -> KDC salt = CORP.LOCALalice              corrected username = 'alice'
typed --user Alice      -> KDC salt = CORP.LOCALalice              corrected username = 'alice'
typed --user alice      -> KDC salt = CORP.LOCALalice              (already correct)
```

Feed the salt back verbatim with `--salt`, which also covers Administrator and krbtgt, whose salts are frozen from the DC's install-time hostname:

```sh
ad-secretgen --salt 'CORP.LOCALalice' --password 'P@ssw0rd!' --user alice --realm corp.local
```

The full salt rules and the caveat for AS-REP-roastable accounts: [Casing and the Kerberos salt](https://strongwind.dev/AD-SecretGen/guide/casing/).

## Development

```sh
git clone https://github.com/StrongWind1/AD-SecretGen.git && cd AD-SecretGen
uv sync                                    # install dev dependencies
make check                                 # ruff + ty + pytest + docs
uv run pytest                              # fixtures + KATs only
uv run ruff check . && uv run ty check     # lint + typecheck only
```

## Credits

Built with [pycryptodome](https://github.com/Legrandin/pycryptodome) and [rich](https://github.com/Textualize/rich). Cross-validated against [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) and [NTDSWolf](https://github.com/StrongWind1/NTDSWolf).

## Related tools

- [**CredWolf**](https://github.com/StrongWind1/CredWolf): Validate AD passwords, hashes, keys, and tickets over NTLM and Kerberos
- [**KerbWolf**](https://github.com/StrongWind1/KerbWolf): Kerberos roasting and TGT attack toolkit for Active Directory
- [**NTDSWolf**](https://github.com/StrongWind1/NTDSWolf): Offline NTDS.dit parser and credential extractor for NT/LM hashes, Kerberos keys, LAPS, and gMSA
- [**PassWolf**](https://github.com/StrongWind1/PassWolf): Spec-compliant AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, LDAP
- [**ntcompress**](https://github.com/StrongWind1/ntcompress): Pure-Python ESE record compression and ntdll RtlCompressBuffer/RtlDecompressBuffer formats
- [**Kerberos**](https://github.com/StrongWind1/Kerberos): Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

AD-SecretGen is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
