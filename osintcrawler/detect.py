"""Indicator type detection, refanging and normalisation."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import phonenumbers

from .models import Indicator, IType

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[/\]"), "/"),
]

RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
RE_ASN = re.compile(r"^AS(\d{1,10})$", re.I)
RE_HEX = re.compile(r"^[a-fA-F0-9]+$")
RE_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
RE_BTC_LEGACY = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
RE_BTC_BECH32 = re.compile(r"^bc1[ac-hj-np-z02-9]{11,71}$", re.I)
RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)
RE_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{2,64}$")
RE_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
RE_PHONE_CHARS = re.compile(r"^\+?[\d\s().-]{7,25}$")

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


class DetectionError(ValueError):
    pass


def refang(value: str) -> str:
    v = value.strip().strip("\"'`<>")
    for pattern, repl in _REFANG:
        v = pattern.sub(repl, v)
    return v


def _norm_domain(v: str) -> str | None:
    v = v.strip().rstrip(".").lower()
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return v if RE_DOMAIN.match(v) else None


PHONE_HINT = "include the country code, e.g. +254712345678 or 254712345678"


def _parse_phone(text: str, region: str | None, *, strict: bool) -> str | None:
    try:
        num = phonenumbers.parse(text, region)
    except phonenumbers.NumberParseException:
        return None
    ok = phonenumbers.is_valid_number(num) if strict else phonenumbers.is_possible_number(num)
    return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164) if ok else None


def _norm_phone(v: str, region: str | None) -> str | None:
    """Normalise to E.164. Accepts '+<cc>...', '<cc>...' (no plus), '00<cc>...',
    or a national number when DEFAULT_PHONE_REGION is set."""
    if not RE_PHONE_CHARS.match(v):
        return None
    if v.startswith("+"):
        return _parse_phone(v, None, strict=False)
    digits = re.sub(r"\D", "", v)
    if digits.startswith("00"):  # international dialling prefix
        return _parse_phone("+" + digits[2:], None, strict=False)
    if region and (p := _parse_phone(v, region, strict=True)):
        return p
    # Country code without '+': require a fully valid number so national-format
    # input (e.g. 0712...) isn't silently reinterpreted as another country.
    return _parse_phone("+" + digits, None, strict=True)


def _build(value: str, itype: IType, original: str, region: str | None) -> Indicator:
    """Normalise ``value`` as ``itype`` or raise DetectionError."""
    v = value.strip()
    meta: dict = {}
    if itype is IType.IP:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as e:
            raise DetectionError(f"not a valid IP address: {v}") from e
        v = str(ip)
        meta = {"version": ip.version, "is_private": ip.is_private or ip.is_reserved or ip.is_loopback}
    elif itype is IType.CIDR:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise DetectionError(f"not a valid CIDR: {v}") from e
        v = str(net)
        meta = {"version": net.version, "num_addresses": net.num_addresses}
    elif itype is IType.ASN:
        m = RE_ASN.match(v) or re.match(r"^(\d{1,10})$", v)
        if not m:
            raise DetectionError(f"not a valid ASN: {v}")
        v = f"AS{int(m.group(1))}"
    elif itype is IType.CVE:
        if not RE_CVE.match(v):
            raise DetectionError(f"not a valid CVE id: {v}")
        v = v.upper()
    elif itype is IType.HASH:
        if not (RE_HEX.match(v) and len(v) in HASH_LENGTHS):
            raise DetectionError(f"not an MD5/SHA1/SHA256 hash: {v}")
        v = v.lower()
        meta = {"hash_type": HASH_LENGTHS[len(v)]}
    elif itype is IType.ETH:
        if not RE_ETH.match(v):
            raise DetectionError(f"not an Ethereum address: {v}")
        v = v.lower()
    elif itype is IType.BTC:
        if not (RE_BTC_LEGACY.match(v) or RE_BTC_BECH32.match(v)):
            raise DetectionError(f"not a Bitcoin address: {v}")
        if v.lower().startswith("bc1"):
            v = v.lower()
    elif itype is IType.EMAIL:
        if not RE_EMAIL.match(v):
            raise DetectionError(f"not a valid email address: {v}")
        local, _, dom = v.rpartition("@")
        d = _norm_domain(dom)
        if not d:
            raise DetectionError(f"invalid email domain: {v}")
        v = f"{local.lower()}@{d}"
        meta = {"domain": d}
    elif itype is IType.URL:
        if not RE_SCHEME.match(v):
            v = "http://" + v
        parts = urlsplit(v)
        if not parts.hostname:
            raise DetectionError(f"not a valid URL: {value}")
        meta = {"host": parts.hostname.lower(), "scheme": parts.scheme.lower(), "port": parts.port}
    elif itype is IType.DOMAIN:
        d = _norm_domain(v)
        if not d:
            raise DetectionError(f"not a valid domain: {v}")
        v = d
    elif itype is IType.PHONE:
        p = _norm_phone(v, region)
        if not p:
            raise DetectionError(f"invalid phone number {v!r}: {PHONE_HINT}")
        v = p
    elif itype is IType.USERNAME:
        v = v.lstrip("@")
        if not RE_USERNAME.match(v):
            raise DetectionError(f"usernames may only contain letters, digits, '_', '.', '-': {v}")
    elif itype is IType.ADDRESS:
        v = re.sub(r"\s+", " ", v)
        if len(v) < 4:
            raise DetectionError(f"address too short: {v}")
    return Indicator(value=v, type=itype, original=original, meta=meta)


def detect(raw: str, forced: IType | None = None, phone_region: str | None = None) -> Indicator:
    """Detect the type of ``raw`` and return a normalised Indicator.

    Supports explicit prefixes such as ``phone:0712...``, ``user:alice`` or
    ``address:10 Downing St``, and ``@alice`` for usernames.
    """
    original = raw.strip()
    if not original:
        raise DetectionError("empty indicator")

    # Explicit "type:value" prefix (but never treat "http:"/"https:" as a prefix).
    prefix, sep, rest = original.partition(":")
    aliases = {"user": IType.USERNAME, "addr": IType.ADDRESS, "tel": IType.PHONE, "mail": IType.EMAIL}
    if sep and not forced and not rest.startswith("//"):
        p = prefix.strip().lower()
        if p in aliases:
            forced = aliases[p]
            original = rest.strip()
        elif p in {t.value for t in IType}:
            forced = IType(p)
            original = rest.strip()

    if forced:
        value = original if forced is IType.ADDRESS else refang(original)
        return _build(value, forced, raw.strip(), phone_region)

    v = refang(original)

    if RE_CVE.match(v):
        return _build(v, IType.CVE, original, phone_region)
    if RE_SCHEME.match(v):
        return _build(v, IType.URL, original, phone_region)
    try:
        ipaddress.ip_address(v)
        return _build(v, IType.IP, original, phone_region)
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return _build(v, IType.CIDR, original, phone_region)
        except ValueError:
            pass
    if RE_ASN.match(v):
        return _build(v, IType.ASN, original, phone_region)
    if RE_HEX.match(v) and len(v) in HASH_LENGTHS:
        return _build(v, IType.HASH, original, phone_region)
    if RE_ETH.match(v):
        return _build(v, IType.ETH, original, phone_region)
    if RE_BTC_BECH32.match(v) or (RE_BTC_LEGACY.match(v) and not v.isdigit()):
        return _build(v, IType.BTC, original, phone_region)
    if RE_EMAIL.match(v):
        return _build(v, IType.EMAIL, original, phone_region)
    if v.startswith("@") and RE_USERNAME.match(v[1:]):
        return _build(v, IType.USERNAME, original, phone_region)
    if RE_PHONE_CHARS.match(v):
        if _norm_phone(v, phone_region):
            return _build(v, IType.PHONE, original, phone_region)
        raise DetectionError(
            f"invalid phone number {original!r}: {PHONE_HINT}"
        )
    # domain/path without scheme -> URL
    head, slash, _ = v.partition("/")
    if slash and _norm_domain(head):
        return _build(v, IType.URL, original, phone_region)
    if _norm_domain(v):
        return _build(v, IType.DOMAIN, original, phone_region)
    if re.search(r"[\s,]", original):
        return _build(original, IType.ADDRESS, original, phone_region)
    if RE_USERNAME.match(v):
        return _build(v, IType.USERNAME, original, phone_region)
    raise DetectionError(f"could not determine indicator type for: {original!r} (use a prefix like 'phone:' or --type)")
