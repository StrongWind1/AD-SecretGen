# gMSA / dMSA

If you can read a gMSA's `msDS-ManagedPassword` (you are in `PrincipalsAllowedToRetrieveManagedPassword`, or you are a Domain Admin), you can construct its Kerberos and NTLM keys entirely offline.

## Pulling the managed password over LDAP (bloodyAD)

```bash
B64=$(bloodyAD --host DC -d corp.local -u you -p pw \
        get object 'svc$' --attr msDS-ManagedPassword | sed -n 's/^msDS-ManagedPassword: //p')
ad-secretgen --password-b64 "$B64" --managed-blob --user 'svc$' --realm corp.local
```

`--managed-blob` parses the `MSDS-MANAGEDPASSWORD_BLOB` ([MS-ADTS] §2.2.19), extracts the 256-byte `CurrentPassword`, and derives `NT = MD4(CurrentPassword)` plus the AES keys with the **computer** (`host/`) salt.

!!! tip "Account type is automatic here"
    `--managed-blob` (and a `$`-suffixed `--user`) default `--account-type` to **computer**, so you don't need to pass it. Because gMSAs are computer-class, the casing of `--user`/`--realm` doesn't matter either.

## Notes

- The `sed -n 's/^msDS-ManagedPassword: //p'` filter is important: `bloodyAD` also prints a `distinguishedName:` line, and a naive `sed 's/^[^:]*: *//'` would fold it into the base64 and corrupt the blob (`Incorrect padding`).
- The managed password **rotates** (~30 days by default), so re-pull after a rotation.
- **dMSA** is different — its managed password isn't retrievable over LDAP this way.

## Verifying against netexec

`ad-secretgen` reproduces `nxc ldap <dc> --gmsa` exactly. Given the same managed-password blob, the NT hash and `aes128`/`aes256` keys are byte-identical — provided you keep `--managed-blob` (so the 256-byte `CurrentPassword` is hashed, not the whole struct) and the computer salt (the default for a `$` name).
