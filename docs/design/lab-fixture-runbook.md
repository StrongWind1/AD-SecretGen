# Lab Fixture Runbook — golden test cases for `gen_secrets.py`

Companion to [03 References & Test Vectors](03-REFERENCES-AND-TEST-VECTORS.md). Run on a DC / domain-joined Windows host with **RSAT** + **DSInternals** (`Install-Module DSInternals`), as a **Domain Admin**. Produces one JSON per account; the `nxc --ntds` cross-check is run separately (from the Linux box that reaches the DCs). Fixtures are committed genericized — **fill the variables below; never commit the real domain/IPs**.

```powershell
# --- fill these in (kept out of the committed fixtures) ---
$Realm   = 'YOURREALM'          # DNS realm, e.g. used as UPPER() in salts
$DnsRoot = 'yourrealm.tld'      # DNS domain (FQDN)
$NB      = 'YOURNB'             # NetBIOS domain
$DC2022  = 'dc2022.yourrealm.tld'
$DC2025  = 'dc2025.yourrealm.tld'
```

## Locked generation decisions (03 §7)

- Oracle = **DSInternals primary** (WDigest 29 + salt) **+ nxc `--ntds` cross-check** (NT/LM/Kerberos), **hard-fail** on any overlap disagreement.
- Whole-DC `--ntds` once per DC, sliced per account.
- gMSA: **pull the real managed-password blob**.
- Two unicode accounts: one **0x80–0xFF** (Latin-1-vs-UTF-8 WDigest decider), one **>0xFF** (Latin-1 encode-failure path).
- Extra accounts: **reversible-encryption** (proves CLEARTEXT omitted), **second realm/child domain**, snapshot on **both 2022 + 2025 DCs**.
- Fixtures committed, genericized (realm → `<REALM>`), throwaway accounts, hashes only.

## Account matrix & known passwords (throwaway)

| sAMAccountName | --account-type | Password | Pins |
|---|---|---|---|
| `svc_ascii` | user | `Passw0rdDemo13` | NT/RC4/DES/AES + WDigest(user) |
| `svc_long` | user | `ThisIsAVeryLongTestPassword2025!` (>14) | NT of long; LM placeholder |
| `svc_uni1` | user | `Paßwörd-Demo9` (ß=U+00DF, ö=U+00F6 → 0x80–0xFF) | **WDigest Latin-1 vs UTF-8 decider** |
| `svc_uni2` | user | `Парол-Demo9Ω` (>U+00FF) | Latin-1 encode-failure path |
| `svc_revenc` | user | `RevEncDemo13` (+reversible) | CLEARTEXT omitted (FR-SEC-9) |
| `WSGOLD$` | computer | `MachineDemoPass13` | computer (`host/`) salt |
| `nw_gmsa1$` (existing) | user-salt | managed blob | gMSA NT/Kerberos via `--managed-blob` |
| trust `<NB>$` (existing) | trust | (salt readout) | trust salt = user rule + `$` |

## Part A — create the user accounts (run on $DC2022)

```powershell
$users = @{
  'svc_ascii'  = 'Passw0rdDemo13'
  'svc_long'   = 'ThisIsAVeryLongTestPassword2025!'
  'svc_uni1'   = "Pa$([char]0x00DF)w$([char]0x00F6)rd-Demo9"   # Paßwörd-Demo9
  'svc_uni2'   = "$([char]0x041F)$([char]0x0430)$([char]0x0440)$([char]0x043E)$([char]0x043B)-Demo9$([char]0x03A9)"  # Парол-Demo9Ω
  'svc_revenc' = 'RevEncDemo13'
}
foreach ($u in $users.Keys) {
  New-ADUser -Name $u -SamAccountName $u -AccountPassword (ConvertTo-SecureString $users[$u] -AsPlainText -Force) `
             -Enabled $true -Server $DC2022 -ErrorAction SilentlyContinue
  Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $users[$u] -AsPlainText -Force) -Server $DC2022
}
# reversible encryption -> populates Primary:CLEARTEXT (must reset pw AFTER enabling)
Set-ADUser svc_revenc -AllowReversiblePasswordEncryption $true -Server $DC2022
Set-ADAccountPassword svc_revenc -Reset -NewPassword (ConvertTo-SecureString $users['svc_revenc'] -AsPlainText -Force) -Server $DC2022
```

## Part B — computer account with a known password (run on $DC2022)

```powershell
New-ADComputer -Name 'WSGOLD' -SamAccountName 'WSGOLD$' -Enabled $true -Server $DC2022 -ErrorAction SilentlyContinue
Set-ADAccountPassword 'WSGOLD$' -Reset -NewPassword (ConvertTo-SecureString 'MachineDemoPass13' -AsPlainText -Force) -Server $DC2022
```

## Part C — gMSA managed-password blob (existing nw_gmsa1$)

```powershell
Set-ADServiceAccount nw_gmsa1 -PrincipalsAllowedToRetrieveManagedPassword 'Domain Admins' -Server $DC2022
$mp = (Get-ADServiceAccount nw_gmsa1 -Properties 'msDS-ManagedPassword' -Server $DC2022).'msDS-ManagedPassword'
$blob = ([DSInternals.Common.Data.ManagedPasswordBlob]$mp)  # or raw; we need the 240-byte CurrentPassword
# Emit raw blob hex (we hash blob[:256] with --managed-blob):
-join ($mp | ForEach-Object { $_.ToString('x2') })   # paste this as managed_blob_hex
```

## Part D — trust salt readout (existing interdomain trust account)

```powershell
# find the trust account ($NB-of-the-PARTNER + '$'); read the salt DSInternals shows:
$t = Get-ADReplAccount -SamAccountName '<PARTNER_NB>$' -Server $DC2022
$t.SupplementalCredentials.KerberosNew.DefaultSalt    # expect: <UPPER REALM><PARTNER_NB>$
```

## Part E — DSInternals export (run per account, both DCs)

```powershell
function Export-Gold {
  param($Sam, $Server)
  $a = Get-ADReplAccount -SamAccountName $Sam -Server $Server
  $hex = { param($b) if ($b) { (($b | ForEach-Object { $_.ToString('x2') }) -join '') } else { $null } }
  $kn = $a.SupplementalCredentials.KerberosNew
  $ker = @{ salt = $kn.DefaultSalt }
  if ($kn) { foreach ($c in $kn.Credentials)      { $ker[[string]$c.KeyType] = (& $hex $c.Key) } }
  if ($kn) { foreach ($c in $kn.OldCredentials)   { } }   # ignore history
  $wd = @(); if ($a.SupplementalCredentials.WDigest) { $wd = $a.SupplementalCredentials.WDigest.Hashes | ForEach-Object { & $hex $_ } }
  [pscustomobject]@{
    sam=$Sam; server=$Server
    nt=(& $hex $a.NTHash); lm=(& $hex $a.LMHash)
    kerberos=$ker; wdigest=$wd
    has_cleartext = [bool]$a.SupplementalCredentials.ClearText
  } | ConvertTo-Json -Depth 6 -Compress
}
'svc_ascii','svc_long','svc_uni1','svc_uni2','svc_revenc','WSGOLD$','nw_gmsa1$' | ForEach-Object {
  Export-Gold $_ $DC2022; "----"
}
# repeat with $DC2025 to catch per-OS differences
```

> If a property name differs in your DSInternals version (e.g. `KerberosNew.Credentials[].KeyType`/`.Key`/`.DefaultSalt`, `WDigest.Hashes`), paste the error and we adjust — these are the documented `DSAccount` members but the exact path can vary by release.

## Part F — nxc cross-check (run from the Linux box, or via `! nxc …`)

```bash
nxc smb $DC2022 -u <DA> -p '<pw>' --ntds | tee /tmp/verify/ntds_2022.txt
nxc smb $DC2025 -u <DA> -p '<pw>' --ntds | tee /tmp/verify/ntds_2025.txt
```

Each `--ntds` line gives `domain\sam:rid:lm:nt:::` plus `domain\sam:aes256-cts-hmac-sha1-96:<key>` / `aes128…` / `des-cbc-md5:<key>`. We slice the matrix accounts and **assert equality with the DSInternals export** (hard-fail on mismatch), then write `tests/fixtures/secrets/<account>.json` per [03 §3.4].

## Part G — second realm

Repeat Part A's `svc_ascii` (only) in the **child domain** (its own `$Realm`/`$NB`), export with `Get-ADReplAccount -Server <childDC>`, to exercise the salt builder with a different realm string.
