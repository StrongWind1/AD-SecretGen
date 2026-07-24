# SPDX-License-Identifier: Apache-2.0
"""Property / invariant tests that need no lab oracle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import ad_secretgen as g


def _id(sam="user1", realm="SNOW.LAB", **kw):
    return g.Identity(sam_account_name=sam, realm_dns=realm, netbios_domain="SNOW", dns_domain="snow.lab", **kw)


def test_determinism():
    idn = _id()
    assert g.compute_secrets(idn, "Passw0rd!") == g.compute_secrets(idn, "Passw0rd!")


def test_rc4_equals_nt():
    s = g.compute_secrets(_id(), "Passw0rd!")
    assert s.rc4_hmac == s.nt


def test_empty_password_canonical():
    assert g.compute_nt_hash("").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert g.compute_lm_hash("").hex() == "aad3b435b51404eeaad3b435b51404ee"


def test_no_realm_skips_kerberos():
    s = g.compute_secrets(g.Identity(sam_account_name="user1", realm_dns=""), "Passw0rd!")
    assert s.des is None
    assert s.aes128 is None
    assert s.aes256 is None
    assert any("kerberos" in r for r in s.skipped)


def test_validation_rejects_forbidden_char():
    with pytest.raises(ValueError, match="rule 10"):
        g.validate(g.Identity(sam_account_name="bad:name", realm_dns="x"))


def test_validation_rejects_long_user():
    with pytest.raises(ValueError, match="rule 12"):
        g.validate(g.Identity(sam_account_name="u" * 21, realm_dns="x"))


def test_validation_requires_dollar_for_trust():
    with pytest.raises(ValueError, match="rule 11"):
        g.validate(g.Identity(sam_account_name="notrust", realm_dns="x", account_type=g.AccountType.TRUST))


def test_no_forbidden_imports():
    src = Path(g.__file__).read_text(encoding="utf-8")
    assert "import impacket" not in src
    assert "import ntdswolf" not in src
    assert "from ntdswolf" not in src
    # rich must be lazy: every rich import is indented (inside format_pretty)
    for line in src.splitlines():
        if "import rich" in line or "from rich" in line:
            assert line.startswith(" "), line


def test_output_allowlist():
    idn = _id()
    payload = json.loads(g.format_json(idn, g.compute_secrets(idn, "Passw0rd!")))
    keys = set(payload)
    for section in ("meta", "ntlm", "kerberos"):
        keys |= set(payload.get(section, {}))
    for forbidden in ("sha256", "sha384", "cleartext", "ntlm_strong", "netntlm", "ntowfv2"):
        assert not any(forbidden in key for key in keys)


def test_json_is_sectioned():
    # meta / ntlm / kerberos / wdigest sections, each grouping its own keys (FR-OUT-2).
    idn = _id()
    payload = json.loads(g.format_json(idn, g.compute_secrets(idn, "Passw0rd!")))
    assert set(payload) == {"meta", "ntlm", "kerberos", "wdigest", "skipped"}
    assert next(iter(payload["meta"])) == "account_type"  # account-type first in meta
    assert payload["meta"]["kerberos_salt"] == g.compute_kerberos_salt(idn)  # salt lives in meta now
    assert set(payload["ntlm"]) == {"nt_hash", "lm_hash"}
    assert "salt" not in payload["kerberos"]  # salt moved to meta
    assert list(payload["kerberos"]) == ["des_cbc_crc", "des_cbc_md5", "aes128_cts_hmac_sha1_96", "aes256_cts_hmac_sha1_96", "rc4_hmac"]  # etype order 1,3,17,18,23
    assert payload["kerberos"]["rc4_hmac"] == payload["ntlm"]["nt_hash"]  # etype 23 is the NT hash
    assert "kerberos_iterations" not in payload["meta"]  # hardcoded 4096, not echoed
    assert len(payload["wdigest"]) == 29


def test_managed_blob_extracts_current_password():
    current = bytes(range(256))
    blob = b"\x01\x00\x00\x00\x00\x00\x00\x00" + (16).to_bytes(2, "little") + b"\x00\x00\x00\x00\x00\x00" + current
    assert g.PasswordMaterial.from_managed_blob(blob).nt_preimage == current


def test_raw_blob_nt_is_md4_of_bytes():
    # a clean UTF-16LE blob round-trips, so a raw-blob NT equals the cleartext NT
    blob = "secret".encode("utf-16-le")
    idn = g.Identity(sam_account_name="m$", realm_dns="")
    assert g.compute_secrets(idn, g.PasswordMaterial.from_blob(blob)).nt == g.compute_nt_hash("secret")


def test_trust_salt_is_krbtgt_principal():
    # a real interdomain trust account is salted krbtgt/<partner>, confirmed vs AD (TEST$ -> SNOW.LABkrbtgtTEST)
    idn = g.Identity(sam_account_name="TEST$", realm_dns="snow.lab", account_type=g.AccountType.TRUST)
    assert g.compute_kerberos_salt(idn) == "SNOW.LABkrbtgtTEST"


def test_computer_and_user_salts():
    assert g.compute_kerberos_salt(g.Identity(sam_account_name="svc_dollar$", realm_dns="snow.lab")) == "SNOW.LABsvc_dollar$"
    wsg = g.Identity(sam_account_name="WSGOLD$", realm_dns="snow.lab", account_type=g.AccountType.COMPUTER, dns_domain="snow.lab")
    assert g.compute_kerberos_salt(wsg) == "SNOW.LABhostwsgold.snow.lab"


def _info_atoms(idn, s):
    """Every distinct piece of information the three formats must all carry (FR-OUT-6)."""
    atoms = {idn.sam_account_name, str(idn.account_type), s.nt.hex(), s.lm.hex(), s.rc4_hmac.hex(), *s.skipped}
    for value in (idn.realm_dns, idn.netbios_domain, idn.dns_domain, idn.upn):
        if value:
            atoms.add(value)
    if s.salt is not None:
        atoms.add(s.salt)
    atoms.update(v.hex() for v in (s.des, s.aes128, s.aes256) if v is not None)
    atoms.update(h.hex() for h in s.wdigest)
    return atoms


@pytest.mark.parametrize(
    "idn",
    [_id(), g.Identity(sam_account_name="user1", realm_dns="")],
    ids=["full", "no-realm"],
)
def test_all_formats_carry_identical_info(idn):
    # No format may show a field another hides: every information atom appears in all three.
    s = g.compute_secrets(idn, "Passw0rd!")
    renders = {"text": g.format_text(idn, s), "json": g.format_json(idn, s), "pretty": g.format_pretty(idn, s)}
    for atom in _info_atoms(idn, s):
        for name, rendered in renders.items():
            assert atom in rendered, f"{name} is missing {atom!r}"


def test_meta_hex_encodes_non_ascii():
    # User rule: meta values outside printable ASCII 0x21-0x7E are UTF-8 hex-encoded and key-marked.
    idn = g.Identity(sam_account_name="naïve", realm_dns="café.local", netbios_domain="CAF")
    payload = json.loads(g.format_json(idn, g.compute_secrets(idn, "Passw0rd!")))
    assert payload["meta"]["sam_account_name_hex"] == "naïve".encode().hex()
    assert payload["meta"]["realm_hex"] == "café.local".encode().hex()
    assert "sam_account_name" not in payload["meta"]
    assert payload["meta"]["account_type"] == "user"  # plain ASCII stays verbatim
    assert payload["meta"]["netbios_domain"] == "CAF"


def test_meta_row_hex_rule():
    assert g._meta_row("password", "password", "P@ssw0rd!") == ("password", "password", "P@ssw0rd!")
    assert g._meta_row("password", "password", "café") == ("password (hex)", "password_hex", "636166c3a9")
    assert g._meta_row("x", "x", " ")[1] == "x_hex"  # space (0x20) is not in 0x21-0x7E


def test_resolve_account_type_defaults():
    resolve, at = g._resolve_account_type, g.AccountType
    assert resolve(None, managed_blob=False, sam="alice") is at.USER  # plain name -> user
    assert resolve(None, managed_blob=False, sam="WS01$") is at.COMPUTER  # '$' name -> computer
    assert resolve(None, managed_blob=True, sam="svc") is at.COMPUTER  # managed blob -> computer
    assert resolve("trust", managed_blob=False, sam="TEST$") is at.TRUST  # explicit wins (trust also ends in $)
    assert resolve("user", managed_blob=True, sam="WS01$") is at.USER  # explicit overrides the default


def test_password_row_blob_is_hex():
    args = argparse.Namespace(password=None, password_hex="deadbeef", password_b64=None, managed_blob=False)
    material = g.PasswordMaterial.from_blob(bytes.fromhex("deadbeef"))
    assert g._password_row(args, material) == ("password (hex)", "password_hex", "deadbeef")


def test_password_echoed_in_all_formats():
    idn = _id()
    s = g.compute_secrets(idn, "Passw0rd!")
    row = ("password", "password", "Passw0rd!")
    for fmt in (g.format_text, g.format_json, g.format_pretty):
        assert "Passw0rd!" in fmt(idn, s, row)
