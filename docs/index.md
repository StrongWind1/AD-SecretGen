# AD-SecretGen

**AD-SecretGen** takes a **password** (cleartext, or a raw password blob) plus an **account identity** and derives every password-derived secret that Active Directory stores **PEK-encrypted in `NTDS.dit`** for that account — byte-for-byte what a domain controller would store.

It is the **inverse of [NTDSWolf](https://github.com/StrongWind1/NTDSWolf)**: NTDSWolf decrypts secrets *out of* a database; AD-SecretGen derives the same secrets *from* a password. It's a deterministic reference oracle, validated byte-for-byte against real AD (DSInternals `Get-ADReplAccount`, cross-checked with secretsdump) and against the published RFC3961/3962 + Microsoft known-answer vectors.

It is a *deriver*, not a decryptor: it never touches the bootkey/PEK chain, the KDS-based gMSA key derivation, LAPS, or BitLocker — those are extraction (NTDSWolf's job).

## What it computes

| Output | Algorithm | Spec |
|--------|-----------|------|
| **NT hash** (NTOWFv1) | `MD4(UTF-16LE(password))` | [MS-NLMP] §3.3.1 |
| **LM hash** (LMOWFv1) | `DES("KGS!@#$%")` over the uppercased OEM-14 password | [MS-NLMP] §3.3.1 |
| **RC4-HMAC** (etype 23) | = the NT hash | [RFC4757] |
| **Kerberos DES** (etype 1 = 3) | `mit_des_string_to_key` | [RFC3961] §6.2 |
| **Kerberos AES128 / AES256** (etype 17 / 18) | `DK(PBKDF2-HMAC-SHA1, "kerberos")`, 4096 iters | [RFC3962] §4 |
| **WDigest** (29 × MD5) | `MD5("name:realm:password")` over 29 identity combinations | [MS-SAMR] §3.1.1.8.11.3.1 |

## Quick start

```bash
# cleartext user account
ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP

# read the password from stdin (keeps it out of argv / shell history)
ad-secretgen --password - --user alice --realm corp.local

# JSON output
ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP --format json
```

See **[Installation](getting-started/installation.md)** to get the `ad-secretgen` command, the **[CLI Reference](reference/cli.md)** for every flag, and **[Casing & the Kerberos Salt](guide/casing.md)** for the one footgun that silently produces wrong Kerberos keys.
