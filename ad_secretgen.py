#!/usr/bin/env -S uv run --script
# SPDX-License-Identifier: Apache-2.0
# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome", "rich"]
# ///
"""AD-SecretGen — derive the AD password hashes and Kerberos keys a domain controller stores.

Given a cleartext password (or a raw password blob) plus an account identity, this
single, self-contained file derives every password-derived secret AD stores
PEK-encrypted in NTDS.dit, byte-for-byte: the NT hash, the LM hash, the Kerberos
keys (RC4-HMAC, DES, AES128, AES256) and the 29 WDigest hashes. The inverse of
NTDSWolf — an independent reference oracle whose output is validated against real
AD (DSInternals + secretsdump) and the published RFC vectors.

Run it without installing anything:

    uv run ad_secretgen.py --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP

It is a *deriver*, not a decryptor: it never touches the bootkey/PEK chain, the
per-RID DES layer, KDS-derived gMSA passwords, LAPS, or BitLocker.

Spec basis (every function cites its section):
    NT/LM .................. [MS-NLMP] 3.3.1 (NTOWFv1 / LMOWFv1)
    RC4-HMAC = NT .......... [RFC4757]
    DES string-to-key ...... [RFC3961] 6.2
    AES string-to-key ...... [RFC3962] 4 / [RFC3961] 5.1
    Kerberos salt .......... [MS-KILE] 3.1.1.2
    WDigest (29 hashes) .... [MS-SAMR] 3.1.1.8.11.3.1 / [RFC2617]

Lab-confirmed deviations from a naive reading (see docs/design):
    - DES encodes the password in the ANSI codepage (cp1252), AES in UTF-8.
    - WDigest encodes in ISO-8859-1; hashes 15-20 use an EMPTY realm
      (``principal::password``); the implicit UPN is ``sAMAccountName@dnsdomain``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import sys
from dataclasses import dataclass
from enum import StrEnum
from math import gcd
from typing import TYPE_CHECKING

try:  # MD4/DES/AES are unavailable in the stdlib on OpenSSL 3; pycryptodome supplies them.
    from Crypto.Cipher import AES, DES
    from Crypto.Hash import MD4
except ImportError:  # pragma: no cover - pycryptodome is a declared dependency
    sys.exit("ad-secretgen requires pycryptodome — run with `uv run ad_secretgen.py` (PEP 723 deps) or `uv sync`.")

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

__version__ = "0.3.0"

# --- Constants ---

# LM hash: the fixed plaintext DES-encrypted under each 7-byte password half ([MS-NLMP] 3.3.1).
_LM_MAGIC: bytes = b"KGS!@#$%"
# The "all-blank LM" value AD stores when LM is disabled or the password is unrepresentable.
_LM_BLANK: bytes = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
# DK constant for the Kerberos string-to-key derivation ([RFC3961] 5.1 / [RFC3962]).
_KERBEROS_CONSTANT: bytes = b"kerberos"
# AD's default PBKDF2 iteration count for AES keys ([MS-SAMR] 3.1.1.8.11.6).
_DEFAULT_ITERATIONS: int = 4096
# AES block / enctype key sizes (bytes).
_AES_BLOCK: int = 16
AES128_KEY_SIZE: int = 16
AES256_KEY_SIZE: int = 32
# MSDS-MANAGEDPASSWORD_BLOB ([MS-ADTS] 2.2.19): 16-byte header before the 256-byte CurrentPassword.
_MANAGED_HEADER: int = 16
_MANAGED_PASSWORD_LEN: int = 256
# n-fold rotates each successive replica of the input right by 13 bits ([RFC3961] 5.1).
_NFOLD_ROTATE: int = 13
# Password codepages confirmed against real AD: DES uses the ANSI page, LM the OEM page.
_DES_CODEPAGE: str = "cp1252"
_LM_CODEPAGE: str = "cp437"
# LM is defined only over the first 14 OEM bytes ([MS-NLMP] 3.3.1).
_LM_MAX_OEM: int = 14
# The 16 weak / semi-weak DES keys (64-bit, odd parity) — string-to-key perturbs these ([RFC3961] 6.2).
_WEAK_DES_KEYS: frozenset[bytes] = frozenset(
    bytes.fromhex(h)
    for h in (
        "0101010101010101",
        "fefefefefefefefe",
        "e0e0e0e0f1f1f1f1",
        "1f1f1f1f0e0e0e0e",
        "011f011f010e010e",
        "1f011f010e010e01",
        "01e001e001f101f1",
        "e001e001f101f101",
        "01fe01fe01fe01fe",
        "fe01fe01fe01fe01",
        "1fe01fe00ef10ef1",
        "e01fe01ff10ef10e",
        "1ffe1ffe0efe0efe",
        "fe1ffe1ffe0efe0e",
        "011f011f010e010e",
        "1f1f1f1f0e0e0e0e",
    )
)


# --- Account model ---


class AccountType(StrEnum):
    """Selects the Kerberos salt rule ([MS-KILE] 3.1.1.2).

    The CLI defaults this to ``computer`` for --managed-blob or a ``$``-suffixed name; pass
    --account-type to override (notably ``trust``, which also ends in ``$``).
    """

    USER = "user"
    COMPUTER = "computer"
    TRUST = "trust"  # user-class interdomain trust account -> krbtgt salt, "$" retained


@dataclass(frozen=True, slots=True)
class Identity:
    """The account identity needed to salt and label the derived secrets."""

    sam_account_name: str
    realm_dns: str
    account_type: AccountType = AccountType.USER
    netbios_domain: str | None = None
    dns_domain: str | None = None
    upn: str | None = None


@dataclass(frozen=True, slots=True)
class Secrets:
    """The derived secret set. ``None`` / empty marks "not computable from the given inputs"."""

    nt: bytes
    lm: bytes
    rc4_hmac: bytes
    des: bytes | None
    aes128: bytes | None
    aes256: bytes | None
    wdigest: tuple[bytes, ...]
    salt: str | None
    skipped: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PasswordMaterial:
    """A resolved password: the exact bytes MD4'd for NT, and the text form used for Kerberos/WDigest."""

    nt_preimage: bytes  # MD4'd directly to produce the NT hash
    text: str  # the password as text (cleartext, or a raw blob re-read as UTF-16LE)

    @classmethod
    def from_cleartext(cls, password: str) -> PasswordMaterial:
        """Typed cleartext password — NT = MD4(UTF-16LE(password))."""
        return cls(nt_preimage=password.encode("utf-16-le"), text=password)

    @classmethod
    def from_blob(cls, blob: bytes) -> PasswordMaterial:
        """Raw password blob (machine/managed) — NT = MD4(blob); Kerberos re-reads it as UTF-16LE."""
        return cls(nt_preimage=blob, text=blob.decode("utf-16-le", errors="replace"))

    @classmethod
    def from_managed_blob(cls, blob: bytes) -> PasswordMaterial:
        """Parse an MSDS-MANAGEDPASSWORD_BLOB ([MS-ADTS] 2.2.19) and take its CurrentPassword."""
        return cls.from_blob(_managed_current_password(blob))


# --- Encodings ---


def _utf16le(password: str) -> bytes:
    """UTF-16LE encoding — the pre-image for the NT hash ([MS-NLMP] 3.3.1)."""
    return password.encode("utf-16-le")


def _aes_pwd(password: str) -> bytes:
    """UTF-8 encoding — the AES string-to-key pre-image ([MS-KILE] 3.1.1.2, lab-confirmed)."""
    return password.encode("utf-8")


def _des_pwd(password: str) -> bytes:
    """ANSI (cp1252) encoding — the DES string-to-key pre-image (lab-confirmed; AES uses UTF-8)."""
    return password.encode(_DES_CODEPAGE)


def _wdigest_bytes(text: str) -> bytes:
    """ISO-8859-1 encoding — the WDigest MD5 pre-image ([MS-SAMR] 3.1.1.8.11.3.1, lab-confirmed)."""
    return text.encode("iso-8859-1")


# --- NT / LM ([MS-NLMP] 3.3.1) ---


def compute_nt_hash(password: str) -> bytes:
    """NTOWFv1 = MD4(UTF-16LE(password)) ([MS-NLMP] 3.3.1); also the RC4-HMAC key ([RFC4757])."""
    return MD4.new(_utf16le(password)).digest()


def compute_lm_hash(password: str) -> bytes:
    """LMOWFv1 ([MS-NLMP] 3.3.1): DES("KGS!@#$%") under each 7-byte half of the OEM-uppercased password.

    Returns the blank placeholder when the password exceeds 14 bytes or is not
    representable in the OEM codepage — the value AD stores for such accounts.
    """
    try:
        oem = password.upper().encode(_LM_CODEPAGE)
    except UnicodeEncodeError:
        return _LM_BLANK
    if len(oem) > _LM_MAX_OEM:
        return _LM_BLANK
    oem = oem.ljust(_LM_MAX_OEM, b"\x00")
    return _lm_half(oem[:7]) + _lm_half(oem[7:14])


def _lm_half(key7: bytes) -> bytes:
    """Encrypt the fixed LM plaintext under the DES key spread from a 7-byte password half."""
    return DES.new(_expand_des_key(key7), DES.MODE_ECB).encrypt(_LM_MAGIC)


def _expand_des_key(key7: bytes) -> bytes:
    """Spread 7 key bytes to an 8-byte DES key, inserting a (zero) parity bit after every 7 bits."""
    k = int.from_bytes(key7, "big")
    out = bytes((k >> (49 - 7 * i)) & 0x7F for i in range(8))
    return bytes((b << 1) & 0xFE for b in out)


# --- Kerberos DES string-to-key ([RFC3961] 6.2) ---


def compute_kerberos_des_key(password: str, salt: bytes) -> bytes:
    """DES (etype 1 / 3) key via mit_des_string_to_key over the ANSI-encoded password ([RFC3961] 6.2).

    etypes ``des-cbc-crc`` (1) and ``des-cbc-md5`` (3) share this 8-byte key.
    """
    data = _des_pwd(password) + salt
    data += b"\x00" * (-len(data) % 8)

    # Fan-fold: XOR the 56-bit (7-bits-per-byte) blocks, reversing every other block.
    acc = [0] * 8
    for index, start in enumerate(range(0, len(data), 8)):
        seven = [byte & 0x7F for byte in data[start : start + 8]]
        if index % 2 == 1:
            bits = "".join(format(b, "07b") for b in seven)[::-1]
            seven = [int(bits[j : j + 7], 2) for j in range(0, 56, 7)]
        acc = [(a ^ b) & 0x7F for a, b in zip(acc, seven, strict=True)]

    tempkey = _des_fix_weak(bytes(_add_parity(b) for b in acc))
    checksum = DES.new(tempkey, DES.MODE_CBC, tempkey).encrypt(data)[-8:]
    return _des_fix_weak(_des_fix_parity(checksum))


def _add_parity(seven_bit: int) -> int:
    """Shift a 7-bit value left into a byte and set the LSB to give the byte odd parity."""
    shifted = seven_bit << 1
    return shifted | 1 if seven_bit.bit_count() % 2 == 0 else shifted & 0xFE


def _des_fix_parity(key: bytes) -> bytes:
    """Recompute the odd-parity LSB of each byte, preserving the top 7 bits."""
    return bytes(_add_parity(byte >> 1) for byte in key)


def _des_fix_weak(key: bytes) -> bytes:
    """Perturb a weak / semi-weak DES key by XOR-ing 0xF0 into its last byte ([RFC3961] 6.2)."""
    if key in _WEAK_DES_KEYS:
        return key[:7] + bytes([key[7] ^ 0xF0])
    return key


# --- Kerberos AES string-to-key ([RFC3962] 4 / [RFC3961] 5.1) ---


def compute_kerberos_aes_key(password: str, salt: bytes, key_size: int, iterations: int = _DEFAULT_ITERATIONS) -> bytes:
    """AES (etype 17 / 18) key: ``DK(PBKDF2-HMAC-SHA1(UTF-8(pw), salt, iters, key_size), "kerberos")``.

    ``key_size`` is 16 (AES-128 / etype 17) or 32 (AES-256 / etype 18). ``iterations``
    is exposed for the RFC3962 test vectors; the CLI always uses AD's 4096 default.
    """
    tkey = hashlib.pbkdf2_hmac("sha1", _aes_pwd(password), salt, iterations, key_size)
    return _derive_key(tkey, _KERBEROS_CONSTANT, key_size)


def _derive_key(key: bytes, constant: bytes, key_size: int) -> bytes:
    """DK(key, constant) for AES ([RFC3961] 5.1): n-fold the constant, then iterate AES-CBC feedback."""
    block = _nfold(constant, _AES_BLOCK)
    output = bytearray()
    while len(output) < key_size:
        block = AES.new(key, AES.MODE_CBC, b"\x00" * _AES_BLOCK).encrypt(block)
        output += block
    return bytes(output[:key_size])


def _nfold(data: bytes, out_len: int) -> bytes:
    """N-fold ``data`` to ``out_len`` bytes with rotate-and-ones'-complement-add ([RFC3961] 5.1)."""
    in_len = len(data)
    buffer = bytearray()
    chunk = data
    for _ in range(in_len * out_len // gcd(in_len, out_len) // in_len):
        buffer += chunk
        chunk = _rotate_right(chunk, _NFOLD_ROTATE)
    result = [0] * out_len
    carry = 0
    for i in range(out_len - 1, -1, -1):
        total = carry + sum(buffer[j] for j in range(i, len(buffer), out_len))
        result[i] = total & 0xFF
        carry = total >> 8
    while carry:
        for i in range(out_len - 1, -1, -1):
            carry += result[i]
            result[i] = carry & 0xFF
            carry >>= 8
    return bytes(result)


def _rotate_right(data: bytes, bits: int) -> bytes:
    """Rotate the big-endian bit string ``data`` right by ``bits``, preserving its length."""
    width = len(data) * 8
    shift = bits % width
    value = int.from_bytes(data, "big")
    return (((value >> shift) | (value << (width - shift))) & ((1 << width) - 1)).to_bytes(len(data), "big")


# --- Kerberos salt ([MS-KILE] 3.1.1.2) ---


def compute_kerberos_salt(identity: Identity) -> str:
    """Build the Kerberos salt: user/computer per [MS-KILE] 3.1.1.2, trust = krbtgt salt (lab-confirmed).

    A real interdomain trust account ``<PARTNER>$`` is salted as the principal
    ``krbtgt/<partner flat name>`` in the local realm — ``UPPER(realm) + "krbtgt" +
    sAMAccountName-without-$`` — confirmed against AD (``TEST$`` -> ``SNOW.LABkrbtgtTEST``),
    *not* the user rule. (A plain user account whose name merely ends in ``$`` uses the user rule.)
    """
    realm_upper = identity.realm_dns.upper()
    if identity.account_type is AccountType.COMPUTER:
        host = identity.sam_account_name.rstrip("$").lower()
        domain = (identity.dns_domain or identity.realm_dns).lower()
        return f"{realm_upper}host{host}.{domain}"
    if identity.account_type is AccountType.TRUST:
        return f"{realm_upper}krbtgt{identity.sam_account_name.rstrip('$')}"
    return realm_upper + identity.sam_account_name


# --- WDigest (29 hashes) ([MS-SAMR] 3.1.1.8.11.3.1) ---


def _wdigest_combos(identity: Identity) -> list[tuple[str, str]]:
    """Build the 29 ``(username, realm)`` pre-image pairs; 15-20 use an empty realm (lab-confirmed)."""
    s = identity.sam_account_name
    n = identity.netbios_domain or ""
    d = identity.dns_domain or identity.realm_dns
    u = identity.upn or f"{s}@{d}"  # implicit UPN when unset (lab-confirmed)
    lo, up = str.lower, str.upper
    nbs = f"{n}\\{s}"
    return [
        (s, n),
        (lo(s), lo(n)),
        (up(s), up(n)),
        (s, up(n)),
        (s, lo(n)),
        (up(s), lo(n)),
        (lo(s), up(n)),
        (s, d),
        (lo(s), lo(d)),
        (up(s), up(d)),
        (s, up(d)),
        (s, lo(d)),
        (up(s), lo(d)),
        (lo(s), up(d)),
        (u, ""),
        (lo(u), ""),
        (up(u), ""),
        (nbs, ""),
        (f"{lo(n)}\\{lo(s)}", ""),
        (f"{up(n)}\\{up(s)}", ""),
        (s, "Digest"),
        (lo(s), "Digest"),
        (up(s), "Digest"),
        (u, "Digest"),
        (lo(u), "Digest"),
        (up(u), "Digest"),
        (nbs, "Digest"),
        (f"{lo(n)}\\{lo(s)}", "Digest"),
        (f"{up(n)}\\{up(s)}", "Digest"),
    ]


def compute_wdigest_hashes(identity: Identity, password: str) -> tuple[bytes, ...]:
    """Compute the 29 WDigest hashes — ``MD5(latin-1("username:realm:password"))`` ([MS-SAMR] 3.1.1.8.11.3.1)."""
    return tuple(hashlib.md5(_wdigest_bytes(f"{name}:{realm}:{password}")).digest() for name, realm in _wdigest_combos(identity))


# --- Dispatch ---


def compute_secrets(identity: Identity, password: str | PasswordMaterial, salt_override: str | None = None) -> Secrets:
    """Compute every in-scope secret derivable from ``password`` + ``identity``.

    ``password`` is either a cleartext string or a resolved :class:`PasswordMaterial`
    (e.g. a machine/managed-password blob). ``salt_override`` forces the Kerberos
    salt — needed for accounts whose salt is not derivable from the identity, e.g.
    the built-in Administrator's frozen install-time salt (``<original-host>Administrator``).
    Secrets whose inputs are absent or unrepresentable are left ``None`` / empty and
    named in ``Secrets.skipped``.
    """
    material = password if isinstance(password, PasswordMaterial) else PasswordMaterial.from_cleartext(password)
    text = material.text
    nt = MD4.new(material.nt_preimage).digest()
    skipped: list[str] = []

    des: bytes | None = None
    aes128: bytes | None = None
    aes256: bytes | None = None
    salt: str | None = None
    if salt_override or identity.realm_dns:
        salt = salt_override or compute_kerberos_salt(identity)
        salt_bytes = salt.encode("utf-8")
        aes128 = compute_kerberos_aes_key(text, salt_bytes, AES128_KEY_SIZE)
        aes256 = compute_kerberos_aes_key(text, salt_bytes, AES256_KEY_SIZE)
        try:
            des = compute_kerberos_des_key(text, salt_bytes)
        except UnicodeEncodeError:
            skipped.append("des-cbc-md5/crc (password not representable in the DES ANSI codepage)")
    else:
        skipped.append("kerberos des/aes (no --realm)")

    wdigest: tuple[bytes, ...] = ()
    if identity.netbios_domain and (identity.dns_domain or identity.realm_dns):
        try:
            wdigest = compute_wdigest_hashes(identity, text)
        except UnicodeEncodeError:
            skipped.append("wdigest (password not representable in ISO-8859-1)")
    else:
        skipped.append("wdigest (needs --netbios and a dns domain)")

    return Secrets(
        nt=nt,
        lm=compute_lm_hash(text),
        rc4_hmac=nt,
        des=des,
        aes128=aes128,
        aes256=aes256,
        wdigest=wdigest,
        salt=salt,
        skipped=tuple(skipped),
    )


def _managed_current_password(blob: bytes) -> bytes:
    """Extract the 256-byte CurrentPassword from an MSDS-MANAGEDPASSWORD_BLOB ([MS-ADTS] 2.2.19).

    Layout: Version(2)=1, Reserved(2), Length(4), CurrentPasswordOffset(2 @ byte 8), ...
    """
    if len(blob) < _MANAGED_HEADER or int.from_bytes(blob[0:2], "little") != 1:
        msg = "--managed-blob input is not an MSDS-MANAGEDPASSWORD_BLOB (Version field != 1)"
        raise ValueError(msg)
    offset = int.from_bytes(blob[8:10], "little")
    return blob[offset : offset + _MANAGED_PASSWORD_LEN]


# --- Output ---
#
# Every format renders the SAME sections (meta / ntlm / kerberos / wdigest) from
# one source of truth, ``_sections``. Each row is (display-label, json-key, value)
# so the human and machine formats stay in lock-step; they differ only in layout.

# (display-label, json-key | None, hex-or-text value); json-key is None for the wdigest list.
_Row = tuple[str, str | None, str]
_Section = tuple[str, list[_Row]]

# Printable-ASCII range for meta values: '!' (0x21) through '~' (0x7E). Anything outside it
# (space, control, or non-ASCII) is hex-encoded so a terminal never receives raw bytes.
_ASCII_PRINTABLE_MIN = 0x21
_ASCII_PRINTABLE_MAX = 0x7E


def _meta_row(label: str, key: str, value: str) -> _Row:
    """Hex-encode a meta value unless it is pure printable ASCII.

    Values with any character outside 0x21-0x7E (space, control, or non-ASCII) are UTF-8
    hex-encoded and the label/key marked (``… (hex)`` / ``…_hex``), keeping output terminal-safe.
    """
    if all(_ASCII_PRINTABLE_MIN <= ord(ch) <= _ASCII_PRINTABLE_MAX for ch in value):
        return (label, key, value)
    return (f"{label} (hex)", f"{key}_hex", value.encode("utf-8").hex())


def _meta_rows(identity: Identity, secrets: Secrets, password_row: _Row | None) -> list[_Row]:
    """Build the meta rows: inputs in order (account-type, domain, username, password, salt, params).

    Non-printable values are hex-encoded (_meta_row); the salt salts DES+AES alike (only RC4 is saltless).
    """
    rows: list[_Row] = [_meta_row("account-type", "account_type", str(identity.account_type))]
    if identity.realm_dns:
        rows.append(_meta_row("realm (AD domain)", "realm", identity.realm_dns))
    rows.append(_meta_row("sAMAccountName", "sam_account_name", identity.sam_account_name or "(none)"))
    if password_row is not None:
        rows.append(password_row)
    if secrets.salt is not None:
        rows.append(_meta_row("Kerberos salt", "kerberos_salt", secrets.salt))
    if identity.netbios_domain:
        rows.append(_meta_row("netbios-domain", "netbios_domain", identity.netbios_domain))
    if identity.dns_domain:
        rows.append(_meta_row("dns-domain", "dns_domain", identity.dns_domain))
    if identity.upn:
        rows.append(_meta_row("upn", "upn", identity.upn))
    return rows


def _kerberos_rows(secrets: Secrets) -> list[_Row]:
    """Build the kerberos enctype rows, ordered by etype number (shown in parens).

    des (1/3) and aes (17/18) use the meta Kerberos salt; rc4-hmac (23) is the unsalted NT hash, so
    it's always present. des-cbc-crc (1) and des-cbc-md5 (3) share one key.
    """
    rows: list[_Row] = []
    if secrets.des is not None:
        rows.append(("des-cbc-crc (1)", "des_cbc_crc", secrets.des.hex()))
        rows.append(("des-cbc-md5 (3)", "des_cbc_md5", secrets.des.hex()))
    if secrets.aes128 is not None:
        rows.append(("aes128-cts-hmac-sha1-96 (17)", "aes128_cts_hmac_sha1_96", secrets.aes128.hex()))
    if secrets.aes256 is not None:
        rows.append(("aes256-cts-hmac-sha1-96 (18)", "aes256_cts_hmac_sha1_96", secrets.aes256.hex()))
    rows.append(("rc4-hmac (23)", "rc4_hmac", secrets.rc4_hmac.hex()))
    return rows


def _sections(identity: Identity, secrets: Secrets, password_row: _Row | None = None) -> list[_Section]:
    """Assemble the ordered sections. meta / ntlm / kerberos are always present (rc4-hmac guarantees a Kerberos key); wdigest is conditional."""
    ntlm: list[_Row] = [("nt", "nt_hash", secrets.nt.hex()), ("lm", "lm_hash", secrets.lm.hex())]
    sections: list[_Section] = [
        ("meta", _meta_rows(identity, secrets, password_row)),
        ("ntlm", ntlm),
        ("kerberos", _kerberos_rows(secrets)),
    ]
    wdigest: list[_Row] = [(f"wdigest[{i:02d}]", None, h.hex()) for i, h in enumerate(secrets.wdigest, 1)]
    if wdigest:
        sections.append(("wdigest", wdigest))
    return sections


def format_text(identity: Identity, secrets: Secrets, password_row: _Row | None = None) -> str:
    """Render ``[section]`` blocks of aligned ``label : value`` lines, then a ``[skipped]`` block."""
    sections = _sections(identity, secrets, password_row)
    width = max((len(label) for _name, rows in sections for label, _key, _value in rows), default=1)
    blocks = [f"[{name}]\n" + "\n".join(f"{label:<{width}} : {value}" for label, _key, value in rows) for name, rows in sections]
    if secrets.skipped:
        blocks.append("[skipped]\n" + "\n".join(secrets.skipped))
    return "\n\n".join(blocks)


def format_json(identity: Identity, secrets: Secrets, password_row: _Row | None = None) -> str:
    """Render the same sections as nested objects (``meta``/``ntlm``/``kerberos``), plus ``wdigest``/``skipped`` lists."""
    payload: dict[str, object] = {}
    for name, rows in _sections(identity, secrets, password_row):
        if name == "wdigest":
            payload[name] = [value for _label, _key, value in rows]
        else:
            payload[name] = {key: value for _label, key, value in rows if key is not None}
    payload["skipped"] = list(secrets.skipped)
    return json.dumps(payload, indent=2)


def format_pretty(identity: Identity, secrets: Secrets, password_row: _Row | None = None) -> str:
    """Render the same sections as grouped rich panels; rich is imported only here."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    # Record into an in-memory buffer (not stdout) so .print() only captures;
    # main() prints the single export_text() result, avoiding a double render.
    console = Console(record=True, width=100, file=io.StringIO())
    for name, rows in _sections(identity, secrets, password_row):
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column(style="cyan", no_wrap=True)
        table.add_column(style="white")
        for label, _key, value in rows:
            table.add_row(label, value)
        console.print(Panel(table, title=name.upper(), title_align="left"))
    for reason in secrets.skipped:
        console.print(f"[yellow]skipped:[/yellow] {reason}")
    return console.export_text()


_FORMATTERS: dict[str, Callable[[Identity, Secrets, _Row | None], str]] = {
    "text": format_text,
    "json": format_json,
    "pretty": format_pretty,
}


# --- Input resolution ---


def resolve_password(args: argparse.Namespace) -> PasswordMaterial:
    """Resolve the password source into typed material (cleartext, raw blob, or managed blob)."""
    if args.password_hex is not None or args.password_b64 is not None:
        blob = bytes.fromhex(args.password_hex) if args.password_hex is not None else base64.b64decode(args.password_b64)
        return PasswordMaterial.from_managed_blob(blob) if args.managed_blob else PasswordMaterial.from_blob(blob)
    if args.password == "-":
        return PasswordMaterial.from_cleartext(sys.stdin.readline().rstrip("\n"))
    return PasswordMaterial.from_cleartext(args.password)


def _password_row(args: argparse.Namespace, material: PasswordMaterial) -> _Row:
    """Build the meta ``password`` row from the resolved input.

    Typed/stdin passwords echo as cleartext (hex-encoded if non-ASCII); ``--password-hex``/``-b64``/
    ``--managed-blob`` have no cleartext, so the raw blob is shown as hex.
    """
    if args.password_hex is not None or args.password_b64 is not None:
        return ("password (hex)", "password_hex", material.nt_preimage.hex())
    return _meta_row("password", "password", material.text)


def _resolve_account_type(explicit: str | None, *, managed_blob: bool, sam: str) -> AccountType:
    """Resolve the salt-rule account type.

    Explicit ``--account-type`` always wins. Otherwise default to **computer** for a managed blob
    (gMSA/dMSA) or a ``$``-suffixed name (machine/gMSA) — both computer-class — else **user**. Trust
    accounts also end in ``$``, so they require an explicit ``--account-type trust``.
    """
    if explicit:
        return AccountType(explicit)
    if managed_blob or sam.endswith("$"):
        return AccountType.COMPUTER
    return AccountType.USER


# --- Validation (FR-VAL — [MS-SAMR] 3.1.1.8.4) ---

# Characters forbidden in a sAMAccountName ([MS-SAMR] 3.1.1.8.4 rule 10), plus U+0000-001F.
_SAM_FORBIDDEN: frozenset[str] = frozenset('"/\\[]:|<>+=;?,*')
_SAM_USER_MAX: int = 20  # rule 12: <= 20 chars for user objects


def validate(identity: Identity) -> None:
    """Validate identity inputs against [MS-SAMR] 3.1.1.8.4; raise ``ValueError`` citing the rule."""
    sam = identity.sam_account_name
    if not sam.strip():
        msg = "sAMAccountName must contain a non-blank character ([MS-SAMR] 3.1.1.8.4 rule 8)"
        raise ValueError(msg)
    if sam.endswith("."):
        msg = "sAMAccountName must not end with '.' ([MS-SAMR] 3.1.1.8.4 rule 9)"
        raise ValueError(msg)
    if any(c in _SAM_FORBIDDEN or ord(c) < 0x20 for c in sam):  # noqa: PLR2004 - U+0000-001F per rule 10
        msg = "sAMAccountName contains a forbidden character ([MS-SAMR] 3.1.1.8.4 rule 10)"
        raise ValueError(msg)
    if identity.account_type in {AccountType.COMPUTER, AccountType.TRUST} and not sam.endswith("$"):
        msg = "computer/trust sAMAccountName must end with '$' ([MS-SAMR] 3.1.1.8.4 rule 11)"
        raise ValueError(msg)
    if identity.account_type is AccountType.USER and len(sam) > _SAM_USER_MAX:
        msg = f"user sAMAccountName must be <= 20 characters ([MS-SAMR] 3.1.1.8.4 rule 12); got {len(sam)}"
        raise ValueError(msg)


# --- CLI ---


_DESCRIPTION = "Derive the password-derived secrets AD stores PEK-encrypted in NTDS.dit\n(NT, LM, RC4-HMAC, Kerberos DES / AES128 / AES256, and the 29 WDigest hashes) from a cleartext\npassword or a raw password blob. The inverse of NTDSWolf."

_EPILOG = """\
examples:
  # cleartext user account
  ad-secretgen --password 'P@ssw0rd!' --user alice --realm corp.local --netbios CORP

  # gMSA: pull the managed password over LDAP with bloodyAD, then derive the keys
  # (a '$' name + --managed-blob default to the computer salt automatically)
  B64=$(bloodyAD --host DC -d corp.local -u you -p pw \\
          get object 'svc$' --attr msDS-ManagedPassword | sed -n 's/^msDS-ManagedPassword: //p')
  ad-secretgen --password-b64 "$B64" --managed-blob --user 'svc$' --realm corp.local

  # account with a non-standard salt (e.g. the built-in Administrator)
  ad-secretgen --password 'P@ssw0rd!' --user Administrator --realm corp.local \\
          --salt 'WIN-ABC123Administrator'

casing affects the Kerberos salt:
  user / trust     the salt PRESERVES the sAMAccountName case — pass the EXACT stored case (or --salt)
  computer / gMSA  the machine name is lowercased — any input case works
  realm            always uppercased — any input case works
  Unsure of the case? Ask the KDC — a bare AS-REQ returns the salt (see the docs, "Finding the casing").
"""


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI: a required password source, identity inputs, and the output format."""
    parser = argparse.ArgumentParser(
        prog="ad-secretgen",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=36, width=100),
        description=_DESCRIPTION,
        epilog=_EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    src = parser.add_argument_group("password source", "exactly one of these is required")
    one = src.add_mutually_exclusive_group(required=True)
    one.add_argument("--password", metavar="STR", help="cleartext password ('-' reads one line from stdin)")
    one.add_argument("--password-hex", metavar="HEX", help="raw password blob as hex (e.g. a machine password)")
    one.add_argument("--password-b64", metavar="B64", help="raw password blob as base64 (e.g. bloodyAD's msDS-ManagedPassword)")
    src.add_argument("--managed-blob", action="store_true", help="parse the blob as an MSDS-MANAGEDPASSWORD_BLOB (gMSA/dMSA) and use its CurrentPassword")

    ident = parser.add_argument_group("identity", "builds the Kerberos salt and the WDigest hashes")
    ident.add_argument("--user", default="", metavar="SAM", help="sAMAccountName (case-sensitive for the user/trust salt — see the docs)")
    ident.add_argument("--realm", default="", metavar="DNS", help="DNS domain — AD's Kerberos 'realm' (Kerberos uppercases it; any input case works)")
    ident.add_argument("--account-type", choices=[t.value for t in AccountType], default=None, metavar="{user,computer,trust}", help="salt rule (default: user; computer for --managed-blob or a '$' name)")
    ident.add_argument("--netbios", metavar="NAME", help="NetBIOS domain name (required for WDigest)")
    ident.add_argument("--dns-domain", metavar="FQDN", help="DNS domain FQDN for WDigest (defaults to --realm)")
    ident.add_argument("--upn", metavar="UPN", help="userPrincipalName for WDigest (defaults to <sam>@<dns-domain>)")
    ident.add_argument("--salt", metavar="SALT", help="override the computed Kerberos salt verbatim (e.g. an install-time Administrator salt)")

    out = parser.add_argument_group("output")
    out.add_argument("--format", choices=list(_FORMATTERS), default="text", metavar="{text,json,pretty}", help="output format (default: text)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, validate, compute, and print — exit 2 on bad input, 0 otherwise."""
    args = build_parser().parse_args(argv)
    if args.managed_blob and args.password_hex is None and args.password_b64 is None:
        build_parser().error("--managed-blob requires --password-hex or --password-b64")

    identity = Identity(
        sam_account_name=args.user,
        realm_dns=args.realm,
        account_type=_resolve_account_type(args.account_type, managed_blob=args.managed_blob, sam=args.user),
        netbios_domain=args.netbios,
        dns_domain=args.dns_domain,
        upn=args.upn,
    )
    try:
        if identity.sam_account_name:
            validate(identity)
        password = resolve_password(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    secrets = compute_secrets(identity, password, salt_override=args.salt)
    for reason in secrets.skipped:
        print(f"warning: skipped {reason}", file=sys.stderr)
    print(_FORMATTERS[args.format](identity, secrets, _password_row(args, password)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
