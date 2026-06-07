# CLI Reference

```
ad-secretgen (--password STR | --password-hex HEX | --password-b64 B64) [--managed-blob]
             [--user SAM] [--realm DNS] [--account-type {user,computer,trust}]
             [--netbios NAME] [--dns-domain FQDN] [--upn UPN] [--salt SALT]
             [--format {text,json,pretty}]
```

Exactly one of `--password` / `--password-hex` / `--password-b64` is required. Identity inputs are only needed for the secrets that use them: with no `--realm` the Kerberos keys are skipped, with no `--netbios` the WDigest hashes are skipped (each with a stderr note).

## Password source

| Argument | Meaning |
|----------|---------|
| `--password STR` | Cleartext password. `-` reads one line from stdin. |
| `--password-hex HEX` | Raw password **blob** as hex (e.g. a machine account's UTF-16LE password). NT is `MD4(blob)` directly. |
| `--password-b64 B64` | Same, as base64 — the format `bloodyAD` prints for `msDS-ManagedPassword`. |
| `--managed-blob` | Treat the blob as an `MSDS-MANAGEDPASSWORD_BLOB` ([MS-ADTS] §2.2.19) and use its 256-byte `CurrentPassword`. Use this for gMSA/dMSA. |

## Identity

| Argument | Meaning |
|----------|---------|
| `--user SAM` | `sAMAccountName`. **Case matters for the user/trust salt** — see [Casing](../guide/casing.md). |
| `--realm DNS` | DNS domain — AD's Kerberos *realm*. Kerberos uppercases it, so any input case is fine. |
| `--account-type {user,computer,trust}` | Selects the salt rule. **Defaults to `computer`** for `--managed-blob` or a `$`-suffixed `--user`; else `user`. Pass it explicitly to override — notably **`trust`** (which also ends in `$`, but uses the krbtgt salt). |
| `--netbios NAME` | NetBIOS domain name. Required to emit the 29 WDigest hashes. |
| `--dns-domain FQDN` | DNS domain FQDN for WDigest (defaults to `--realm`). |
| `--upn UPN` | `userPrincipalName` for WDigest (defaults to `<sam>@<dns-domain>`). |
| `--salt SALT` | Override the computed Kerberos salt **verbatim** — the escape hatch for accounts whose salt isn't derivable from the identity (Administrator, krbtgt). |

## Output

| Argument | Meaning |
|----------|---------|
| `--format {text,json,pretty}` | Output format (default `text`). See [Output Formats](../guide/output-formats.md). |

## Limitations & notes

- **DES & WDigest of non-ASCII passwords** are locale-dependent: DES uses the DC's ANSI codepage (cp1252), WDigest uses ISO-8859-1. A password outside that codepage (e.g. Cyrillic) or a **binary gMSA blob** can't be reproduced for those two algorithms — NT and AES still are. Such fields are skipped with a stderr note.
- **Administrator / krbtgt** carry frozen install-time salts — use `--salt`.
- **NoLMHash** (the modern default) means AD stores a blank `LM`; this tool emits the *true* LM hash of the password.
- **Out of scope** (by design): AES-SHA2 (etype 19/20), `Primary:CLEARTEXT`, the random `NTLM-Strong-NTOWF`, NetNTLM wire responses, DCC1/DCC2, DPAPI pre-keys.
