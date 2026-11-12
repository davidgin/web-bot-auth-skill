# SPDX-License-Identifier: Apache-2.0
"""Reference verifier for Web Bot Auth (HTTP Message Signatures for automated traffic).

Implements, for requests:
  * RFC 8941 structured-field parsing/serialization (the subset signatures need)
  * RFC 9421 signature base construction and Ed25519 verification
  * RFC 9530 Content-Digest checking (sha-256, sha-512)
  * RFC 8037 / RFC 7638 JWK thumbprints for Ed25519 keys
  * Replay protection with a pluggable nonce store

Targets draft-meunier-web-bot-auth-architecture-05 and also accepts the legacy
sf-string form of Signature-Agent that many deployed agents still send.

Single file, one dependency (``cryptography``). Copy it into a project as-is and
keep this header; write a thin adapter from your framework's request object to
``Request`` rather than editing the verification logic.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Mapping, Optional, Protocol, Sequence, Union
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "Request", "Policy", "Outcome", "Result", "Verifier",
    "NonceStore", "InMemoryNonceStore", "NonceStoreError",
    "KeyResolver", "ResolvedKey", "StaticKeyResolver", "DirectoryKeyResolver",
    "jwk_thumbprint", "public_jwk", "safe_fetch_directory", "sign_request",
    "Token", "StructuredFieldError", "TEST_KEY_THUMBPRINTS",
]

TAG = "web-bot-auth"
WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


# --- RFC 8941 structured fields (subset) ---

class StructuredFieldError(ValueError):
    pass


class Token(str):
    """An RFC 8941 token (unquoted), distinct from a string."""


BareItem = Union[int, float, str, Token, bytes, bool]
Params = dict  # str -> BareItem, insertion-ordered


@dataclass
class Item:
    value: BareItem
    params: Params = field(default_factory=dict)


@dataclass
class InnerList:
    items: list  # list[Item]
    params: Params = field(default_factory=dict)


_LCALPHA = "abcdefghijklmnopqrstuvwxyz"
_DIGIT = "0123456789"
_KEY_CHARS = set(_LCALPHA + _DIGIT + "_-.*")
_TCHAR = set("!#$%&'*+-.^_`|~" + _DIGIT + _LCALPHA + _LCALPHA.upper())
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def skip_sp(self):
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self):
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def fail(self, msg: str):
        raise StructuredFieldError(f"{msg} at offset {self.i}")

    def key(self) -> str:
        c = self.peek()
        if not c or (c not in _LCALPHA and c != "*"):
            self.fail("invalid key")
        start = self.i
        while self.peek() and self.peek() in _KEY_CHARS:
            self.i += 1
        return self.s[start:self.i]

    def params(self) -> Params:
        out: Params = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            k = self.key()
            v: BareItem = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare_item()
            out[k] = v
        return out

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == "-" or (c and c in _DIGIT):
            return self.number()
        if c == '"':
            return self.string()
        if c == ":":
            return self.byte_seq()
        if c == "?":
            return self.boolean()
        if c and (c.isalpha() or c == "*"):
            return self.token()
        self.fail("invalid bare item")

    def number(self):
        start = self.i
        if self.peek() == "-":
            self.i += 1
        if not (self.peek() and self.peek() in _DIGIT):
            self.fail("invalid number")
        is_decimal = False
        while self.peek() and (self.peek() in _DIGIT or self.peek() == "."):
            if self.peek() == ".":
                if is_decimal:
                    self.fail("invalid decimal")
                is_decimal = True
            self.i += 1
        text = self.s[start:self.i]
        digits = text.lstrip("-")
        if is_decimal:
            whole, _, frac = digits.partition(".")
            if len(whole) > 12 or not frac or len(frac) > 3:
                self.fail("decimal out of range")
            return float(text)
        if len(digits) > 15:
            self.fail("integer out of range")
        return int(text)

    def string(self) -> str:
        self.i += 1
        out = []
        while True:
            c = self.peek()
            if not c:
                self.fail("unterminated string")
            self.i += 1
            if c == "\\":
                n = self.peek()
                if n not in ('"', "\\"):
                    self.fail("invalid escape")
                out.append(n)
                self.i += 1
            elif c == '"':
                return "".join(out)
            elif not (0x20 <= ord(c) <= 0x7E):
                self.fail("invalid string character")
            else:
                out.append(c)

    def token(self) -> Token:
        start = self.i
        self.i += 1
        while self.peek() and (self.peek() in _TCHAR or self.peek() in ":/"):
            self.i += 1
        return Token(self.s[start:self.i])

    def byte_seq(self) -> bytes:
        self.i += 1
        end = self.s.find(":", self.i)
        if end < 0:
            self.fail("unterminated byte sequence")
        b64 = self.s[self.i:end]
        if any(ch not in _B64_CHARS for ch in b64):
            self.fail("invalid base64")
        self.i = end + 1
        try:
            return base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
        except Exception:
            self.fail("invalid base64")

    def boolean(self) -> bool:
        self.i += 1
        c = self.peek()
        if c not in ("0", "1"):
            self.fail("invalid boolean")
        self.i += 1
        return c == "1"

    def item_or_inner_list(self):
        if self.peek() == "(":
            return self.inner_list()
        v = self.bare_item()
        return Item(v, self.params())

    def inner_list(self) -> InnerList:
        self.i += 1
        items = []
        while True:
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return InnerList(items, self.params())
            items.append(Item(self.bare_item(), self.params()))
            if self.peek() not in (" ", ")"):
                self.fail("invalid inner list")

    def done(self):
        self.skip_sp()
        if self.i != len(self.s):
            self.fail("trailing characters")


def parse_item(text: str) -> Item:
    p = _Parser(text.strip(" "))
    v = p.bare_item()
    it = Item(v, p.params())
    p.done()
    return it


def parse_dictionary(text: str) -> dict:
    p = _Parser(text.strip(" "))
    out: dict = {}
    if not p.s:
        return out
    while True:
        k = p.key()
        if p.peek() == "=":
            p.i += 1
            out[k] = p.item_or_inner_list()
        else:
            out[k] = Item(True, p.params())
        p.skip_ows()
        if p.i >= len(p.s):
            return out
        if p.peek() != ",":
            p.fail("expected comma")
        p.i += 1
        p.skip_ows()
        if p.i >= len(p.s):
            p.fail("trailing comma")


def serialize_bare_item(v: BareItem) -> str:
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, Token):
        return str(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        s = f"{v:.3f}".rstrip("0")
        return s + "0" if s.endswith(".") else s
    if isinstance(v, bytes):
        return ":" + base64.b64encode(v).decode() + ":"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise StructuredFieldError(f"cannot serialize {type(v).__name__}")


def serialize_params(params: Params) -> str:
    out = []
    for k, v in params.items():
        out.append(";" + k if v is True else f";{k}={serialize_bare_item(v)}")
    return "".join(out)


def serialize_item(it: Item) -> str:
    return serialize_bare_item(it.value) + serialize_params(it.params)


def serialize_inner_list(il: InnerList) -> str:
    return "(" + " ".join(serialize_item(i) for i in il.items) + ")" + serialize_params(il.params)


def serialize_member(m) -> str:
    return serialize_inner_list(m) if isinstance(m, InnerList) else serialize_item(m)


def serialize_dictionary(d: dict) -> str:
    parts = []
    for k, m in d.items():
        if isinstance(m, Item) and m.value is True:
            parts.append(k + serialize_params(m.params))
        else:
            parts.append(f"{k}={serialize_member(m)}")
    return ", ".join(parts)


# --- Requests and signature base (RFC 9421) ---

@dataclass
class Request:
    """A request as received. Build this in a framework adapter.

    ``url`` must be the absolute URL the client requested (scheme, host, path,
    query exactly as received). ``body`` must be the raw bytes before any
    parsing or decompression. ``headers`` keeps repeated fields as separate
    entries.
    """

    method: str
    url: str
    headers: Union[Sequence[tuple], Mapping[str, str]] = ()
    body: bytes = b""

    def __post_init__(self):
        items = self.headers.items() if isinstance(self.headers, Mapping) else self.headers
        self._headers = [(str(k).lower(), str(v)) for k, v in items]

    def header_values(self, name: str) -> list:
        name = name.lower()
        return [v for k, v in self._headers if k == name]

    def header(self, name: str) -> Optional[str]:
        vals = self.header_values(name)
        if not vals:
            return None
        return ", ".join(v.strip(" \t") for v in vals)


class SignatureBaseError(ValueError):
    pass


def _authority(url) -> str:
    host = (url.hostname or "").lower()
    if ":" in host:  # IPv6
        host = f"[{host}]"
    port = url.port
    default = {"https": 443, "http": 80}.get(url.scheme.lower())
    return host if port is None or port == default else f"{host}:{port}"


def _derived(name: str, req: Request) -> str:
    u = urlsplit(req.url)
    if name == "@method":
        return req.method
    if name == "@target-uri":
        return req.url
    if name == "@authority":
        return _authority(u)
    if name == "@scheme":
        return u.scheme.lower()
    if name == "@path":
        return u.path or "/"
    if name == "@query":
        return "?" + u.query
    if name == "@request-target":
        return (u.path or "/") + ("?" + u.query if u.query else "")
    raise SignatureBaseError(f"unsupported derived component {name}")


def _component_value(comp: Item, req: Request) -> str:
    name = comp.value
    if not isinstance(name, str) or isinstance(name, Token):
        raise SignatureBaseError("component identifiers must be strings")
    params = dict(comp.params)
    if name.startswith("@"):
        if params:
            raise SignatureBaseError(f"unsupported parameters on {name}")
        return _derived(name, req)
    if name != name.lower():
        raise SignatureBaseError("field names must be lowercase")
    raw = req.header(name)
    if raw is None:
        raise SignatureBaseError(f"covered field {name} is absent")
    key = params.pop("key", None)
    sf = params.pop("sf", None)
    if params:
        raise SignatureBaseError(f"unsupported parameters on {name}: {sorted(params)}")
    if key is not None:
        if not isinstance(key, str):
            raise SignatureBaseError("key parameter must be a string")
        try:
            d = parse_dictionary(raw)
        except StructuredFieldError as e:
            raise SignatureBaseError(f"{name} is not a dictionary: {e}")
        if key not in d:
            raise SignatureBaseError(f"{name} has no member {key}")
        return serialize_member(d[key])
    if sf:
        try:
            return serialize_dictionary(parse_dictionary(raw))
        except StructuredFieldError as e:
            raise SignatureBaseError(f"{name} could not be re-serialized: {e}")
    return raw


def signature_base(req: Request, covered: InnerList) -> bytes:
    lines = []
    seen = set()
    for comp in covered.items:
        ident = serialize_item(comp)
        if ident in seen:
            raise SignatureBaseError(f"duplicate component {ident}")
        seen.add(ident)
        value = _component_value(comp, req)
        if "\n" in value or "\r" in value:
            raise SignatureBaseError("component value contains a newline")
        lines.append(f"{ident}: {value}")
    lines.append(f'"@signature-params": {serialize_inner_list(covered)}')
    return "\n".join(lines).encode("ascii", errors="strict")


# --- Content-Digest (RFC 9530) ---

_DIGESTS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}


def content_digest_matches(header_value: str, body: bytes) -> bool:
    """True if at least one supported algorithm is present and all supported ones match."""
    try:
        d = parse_dictionary(header_value)
    except StructuredFieldError:
        return False
    checked = False
    for alg, member in d.items():
        fn = _DIGESTS.get(alg)
        if fn is None:
            continue
        if not isinstance(member, Item) or not isinstance(member.value, bytes):
            return False
        if not hmac.compare_digest(member.value, fn(body).digest()):
            return False
        checked = True
    return checked


# --- Keys ---

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_thumbprint(jwk: Mapping) -> str:
    """RFC 7638 thumbprint for an Ed25519 OKP key (RFC 8037 Appendix A.3)."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("not an Ed25519 OKP JWK")
    canon = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": jwk["x"]},
                       separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canon.encode()).digest())


def public_jwk(key: Union[Ed25519PrivateKey, Ed25519PublicKey]) -> dict:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


@dataclass
class _DirKey:
    key: Ed25519PublicKey
    nbf: Optional[int] = None
    exp: Optional[int] = None

    def usable(self, now: float) -> bool:
        return (self.nbf is None or now >= self.nbf) and (self.exp is None or now < self.exp)


# Published example keys (-01 section 6.8 says "including": the list is not exhaustive).
TEST_KEY_THUMBPRINTS = frozenset({
    "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",  # RFC 9421 B.1.4; -01 E.2 and 5.5.1 examples
    "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",  # RFC 8037 A.1
    "CaJn8r1wQ6jaeqa0H9w0Xw4n2xguAKi6vziTdPQqqFs",  # this skill's generate_vectors.KEY
    "UBQJjBYkCFLaFgwMbZIQWpA2VRag2Y4CVF51WNWQS-s",  # this skill's generate_vectors.OTHER
})


def parse_directory(data: Union[bytes, str, Mapping], max_keys: int = 64,
                    allow_test_keys: bool = False) -> dict:
    """Parse a JWKS key directory into {thumbprint: _DirKey}, skipping non-Ed25519 keys.

    Raises ValueError (a discovery failure, so a resolver keeps its last good copy) when the
    document is not a JWKS or has more than ``max_keys`` entries (counted before filtering).
    Keys in ``TEST_KEY_THUMBPRINTS`` are dropped unless ``allow_test_keys``.
    """
    doc = json.loads(data) if isinstance(data, (bytes, str)) else data
    # A 200 that is not a JWKS is not evidence about the keys (-01 section 6.10);
    # raising lets the caller keep its last good copy instead of caching {}.
    if not isinstance(doc, Mapping) or not isinstance(doc.get("keys"), list):
        raise ValueError("not a JWKS: expected an object with a keys array")
    out = {}
    if len(doc["keys"]) > max_keys:
        raise ValueError(f"directory has more than {max_keys} keys")
    for jwk in doc["keys"]:
        if not isinstance(jwk, Mapping) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        try:
            raw = _b64url_decode(jwk["x"])
            key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception:
            continue
        nbf, exp = jwk.get("nbf"), jwk.get("exp")
        kid = jwk_thumbprint(jwk)
        if kid in TEST_KEY_THUMBPRINTS and not allow_test_keys:
            continue
        out[kid] = _DirKey(
            key,
            nbf if isinstance(nbf, int) and not isinstance(nbf, bool) else None,
            exp if isinstance(exp, int) and not isinstance(exp, bool) else None,
        )
    return out


def normalize_origin(url: str) -> str:
    u = urlsplit(url)
    if u.scheme.lower() != "https" or not u.hostname:
        raise ValueError("operator must be an https URL")
    return "https://" + _authority(u)


def directory_url(signature_agent: str) -> str:
    """Resolve a server-configured allowlist entry, never a request header."""
    u = urlsplit(signature_agent)
    origin = normalize_origin(signature_agent)
    if u.fragment or u.username is not None or u.password is not None:
        raise ValueError("directory URL must not contain a fragment or userinfo")
    path = u.path if u.path and u.path != "/" else WELL_KNOWN_DIRECTORY
    return origin + path + ("?" + u.query if u.query else "")


@dataclass
class ResolvedKey:
    key: Ed25519PublicKey
    trusted: bool  # True only for allowlisted operators


class KeyResolver(Protocol):
    # Optional ``directory_unavailable(operator, now) -> bool``: side-effect free, read only after
    # resolve() returned None; True maps that miss to UNKNOWN_OPERATOR. Never yields a key or trust.
    def resolve(self, keyid: str, operator: Optional[str], now: float) -> Optional[ResolvedKey]: ...

    def is_allowlisted(self, operator: Optional[str]) -> bool: ...


class StaticKeyResolver:
    """Keys configured in code or config, e.g. for tests or out-of-band registered agents.

    ``keys`` maps operator origin (or None for agents that send no
    Signature-Agent, or only an ignored member) to a JWKS dict or list of JWKs.
    """

    def __init__(self, keys: Mapping, trusted: bool = True, allow_test_keys: bool = False):
        self.trusted = trusted
        self._keys = {}
        for op, jwks in keys.items():
            doc = jwks if isinstance(jwks, Mapping) else {"keys": list(jwks)}
            parsed = parse_directory(doc, allow_test_keys=True)
            bad = TEST_KEY_THUMBPRINTS.intersection(parsed)
            if bad and not allow_test_keys:  # fail fast: a published key must not be configured
                raise ValueError(f"configuration contains a known test key: {sorted(bad)[0]}")
            self._keys[normalize_origin(op) if op else None] = parsed

    def is_allowlisted(self, operator):
        return self.trusted and operator in self._keys

    def resolve(self, keyid, operator, now):
        k = self._keys.get(operator, {}).get(keyid)
        if k is None or not k.usable(now):
            return None
        return ResolvedKey(k.key, self.trusted)


class DirectoryKeyResolver:
    """Fetches and caches key directories for allowlisted operators only.

    Never fetches for an operator outside ``allowlist``: a request header must
    not be able to make the server fetch an arbitrary URL (SSRF). Directories
    for other operators can be added by a background job via
    ``add_untrusted_directory``; keys from those resolve as untrusted.
    """

    def __init__(self, allowlist: Iterable[str], fetch: Callable[[str], tuple] = None,
                 min_ttl: int = 300, max_ttl: int = 86400, refetch_interval: int = 60,
                 max_keys: int = 64, allow_test_keys: bool = False):
        self._directory_urls = {}
        for entry in allowlist:
            origin, url = normalize_origin(entry), directory_url(entry)
            if origin in self._directory_urls and self._directory_urls[origin] != url:
                raise ValueError(f"conflicting directory URLs for origin {origin}")
            self._directory_urls[origin] = url
        self.allowlist = set(self._directory_urls)
        self.fetch = fetch or safe_fetch_directory
        self.min_ttl, self.max_ttl, self.refetch_interval = min_ttl, max_ttl, refetch_interval
        self.max_keys, self.allow_test_keys = max_keys, allow_test_keys
        self._cache = {}  # origin -> (keys, expires_at, trusted)
        self._last_fetch = {}
        self._lock = threading.Lock()

    def is_allowlisted(self, operator):
        return operator in self.allowlist

    def add_untrusted_directory(self, operator: str, data, ttl: int = 3600, now: float = None):
        now = time.time() if now is None else now
        op = normalize_origin(operator)
        if op in self.allowlist:
            raise ValueError("operator is allowlisted; it is fetched, not added")
        with self._lock:
            self._cache[op] = (parse_directory(data, self.max_keys, self.allow_test_keys), now + ttl, False)

    def _refresh(self, op: str, now: float, force: bool) -> None:
        with self._lock:
            cached = self._cache.get(op)
            if cached and not force and cached[1] > now:
                return
            if now - self._last_fetch.get(op, -1e18) < self.refetch_interval:
                return
            # Reserve the attempt before I/O, including failures and cold starts.
            self._last_fetch[op] = now
            url = self._directory_urls.get(op)
            if url is None:
                url = directory_url(op)
        body, max_age = self.fetch(url)
        ttl = min(max(max_age if max_age is not None else self.min_ttl, self.min_ttl), self.max_ttl)
        keys = parse_directory(body, self.max_keys, self.allow_test_keys)
        with self._lock:
            self._cache[op] = (keys, now + ttl, True)

    def resolve(self, keyid, operator, now):
        if operator is None:
            return None
        if operator in self.allowlist:
            try:
                self._refresh(operator, now, force=False)
                cached = self._cache.get(operator)
                if cached and keyid not in cached[0]:
                    self._refresh(operator, now, force=True)  # rotation; rate-limited
            except Exception:
                pass  # keep serving the last good copy if there is one
        cached = self._cache.get(operator)
        if not cached:
            return None
        keys, expires_at, trusted = cached
        # Re-read after any fetch: removal from the allowlist mid-fetch revokes trust.
        trusted = trusted and operator in self.allowlist
        if not trusted and expires_at <= now:
            return None
        k = keys.get(keyid)
        return ResolvedKey(k.key, trusted) if k is not None and k.usable(now) else None

    def directory_unavailable(self, operator, now) -> bool:
        """True if an allowlisted operator has no fresh cached directory (read-only, no fetch).

        Called only after resolve() found no key; see references/policy-decisions.md section 6.
        """
        if operator not in self.allowlist:
            return False
        with self._lock:
            cached = self._cache.get(operator)
        return cached is None or cached[1] <= now


def safe_fetch_directory(url: str, timeout: float = 2.0, max_bytes: int = 65536) -> tuple:
    """Fetch a key directory with SSRF guards. Returns (body, max_age or None).

    Guards: https only, every resolved address must be public, no redirects,
    size cap, short timeout. Residual risk: DNS can change between this check
    and the connection (rebinding). For high-assurance deployments, pin the
    resolved IP in your HTTP client or fetch through an egress proxy.
    """
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise ValueError("directory URL must be https")
    for info in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError(f"directory host resolves to non-public address {ip}")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={
        "Accept": "application/http-message-signatures-directory+json, application/json"})
    with opener.open(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError(f"directory fetch returned {resp.status}")
        body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("directory too large")
        max_age = None
        for part in (resp.headers.get("Cache-Control") or "").split(","):
            k, _, v = part.strip().partition("=")
            if k.lower() == "max-age" and v.isdigit():
                max_age = int(v)
        return body, max_age


# --- Nonce stores ---

class NonceStoreError(RuntimeError):
    pass


class NonceStore(Protocol):
    def add_if_absent(self, key: str, ttl_seconds: int) -> bool:
        """Atomically record key; return False if it was already present."""


class InMemoryNonceStore:
    """Single-process store for tests and development.

    Do not use behind more than one process or node: a replay sent to a
    different worker would not be detected.
    """

    def __init__(self, clock: Callable[[], float] = time.time):
        self._seen = {}
        self._lock = threading.Lock()
        self._clock = clock

    def add_if_absent(self, key, ttl_seconds):
        now = self._clock()
        with self._lock:
            if len(self._seen) > 10000:
                self._seen = {k: e for k, e in self._seen.items() if e > now}
            exp = self._seen.get(key)
            if exp is not None and exp > now:
                return False
            self._seen[key] = now + ttl_seconds
            return True


# --- Verification ---

class Outcome(str, Enum):
    UNSIGNED = "unsigned"                  # no web-bot-auth signature: score as normal traffic
    VERIFIED = "verified"                  # valid signature from an allowlisted operator
    SIGNED_UNTRUSTED = "signed_untrusted"  # valid signature, operator known but not allowlisted
    UNKNOWN_OPERATOR = "unknown_operator"  # well-formed, but no key available: treat as unsigned
    INVALID = "invalid"                    # present and wrong: block
    EXPIRED = "expired"                    # outside its validity window: block
    REPLAY = "replay"                      # nonce already seen: block


HOSTILE = frozenset({Outcome.INVALID, Outcome.EXPIRED, Outcome.REPLAY})


@dataclass
class Result:
    outcome: Outcome
    reason: str = ""
    operator: Optional[str] = None
    keyid: Optional[str] = None
    label: Optional[str] = None
    binds_request: bool = False     # method, path, query and body are all covered
    replay_protected: bool = False  # nonce present and recorded

    @property
    def hostile(self) -> bool:
        return self.outcome in HOSTILE


@dataclass
class Policy:
    """Verification policy. Defaults favour interoperability with deployed agents;
    see references/policy-decisions.md before changing them."""

    max_age: int = 300                 # reject if created is older than this (s)
    max_lifetime: Optional[int] = 86400  # reject if expires - created exceeds this (draft: <= 24h)
    clock_skew: int = 5
    require_binding: bool = False      # INVALID unless method/path/query/body are covered
    require_nonce: bool = False        # INVALID if no nonce
    min_nonce_length: int = 16
    fail_closed_methods: frozenset = frozenset({"POST", "PUT", "PATCH", "DELETE"})


_PATH_COVERING = {"@path", "@target-uri", "@request-target"}
_QUERY_COVERING = {"@query", "@target-uri", "@request-target"}


class Verifier:
    def __init__(self, keys: KeyResolver, nonces: Optional[NonceStore] = None,
                 policy: Optional[Policy] = None, clock: Callable[[], float] = time.time):
        self.keys = keys
        self.nonces = nonces
        self.policy = policy or Policy()
        self.clock = clock

    def verify(self, req: Request) -> Result:
        try:
            return self._verify(req)
        except (StructuredFieldError, SignatureBaseError, UnicodeError) as e:
            return Result(Outcome.INVALID, f"malformed: {e}")

    def _verify(self, req: Request) -> Result:
        selected = self._select(req)
        if isinstance(selected, Result):
            return selected
        label, covered, signature = selected

        params = covered.params
        keyid, created, expires = params.get("keyid"), params.get("created"), params.get("expires")
        nonce = params.get("nonce")
        res = Result(Outcome.INVALID, label=label, keyid=keyid if isinstance(keyid, str) else None)
        # Cheap checks before any crypto or key fetching.
        now = self.clock()
        stop = (self._check_params(covered, res) or self._check_times(created, expires, now, res)
                or self._identity(req, covered, label, res))
        if stop is not None:
            return stop

        names = {c.value for c in covered.items}
        if "content-digest" in names:
            cd = req.header("content-digest")
            if cd is None or not content_digest_matches(cd, req.body):
                res.reason = "content-digest does not match body"; return res

        resolved = self._resolve_key(res, keyid, res.operator, now)
        if resolved is None:
            return res

        base = signature_base(req, covered)
        try:
            resolved.key.verify(signature, base)
        except InvalidSignature:
            res.reason = "signature does not verify"; return res

        # Coverage: is this signature bound to this specific request?
        res.binds_request = (
            "@method" in names
            and bool(names & _PATH_COVERING)
            and (not urlsplit(req.url).query or bool(names & _QUERY_COVERING))
            and (not req.body or "content-digest" in names)
        )
        if self.policy.require_binding and not res.binds_request:
            res.reason = "signature does not cover method, path, query and body"; return res

        stop = self._check_nonce(req, keyid, nonce, created, expires, now, res)
        if stop is not None:
            return stop

        res.outcome = Outcome.VERIFIED if resolved.trusted else Outcome.SIGNED_UNTRUSTED
        res.reason = "ok"
        return res

    @staticmethod
    def _select(req: Request):
        """Return ``(label, covered, signature)``, or a Result when nothing is left to verify."""
        sig_header, input_header = req.header("signature"), req.header("signature-input")
        if sig_header is None and input_header is None:
            return Result(Outcome.UNSIGNED, "no signature")
        if sig_header is None or input_header is None:
            return Result(Outcome.INVALID, "Signature and Signature-Input must both be present")

        inputs, sigs = parse_dictionary(input_header), parse_dictionary(sig_header)
        label = next((k for k, v in inputs.items()
                      if isinstance(v, InnerList) and v.params.get("tag") == TAG), None)
        if label is None:
            return Result(Outcome.UNSIGNED, "no web-bot-auth signature")
        sig_member = sigs.get(label)
        if not isinstance(sig_member, Item) or not isinstance(sig_member.value, bytes):
            return Result(Outcome.INVALID, "no signature value for label", label=label)
        return label, inputs[label], sig_member.value

    @staticmethod
    def _check_params(covered: InnerList, res: Result) -> Optional[Result]:
        params = covered.params
        keyid, created, expires = params.get("keyid"), params.get("created"), params.get("expires")
        nonce, alg = params.get("nonce"), params.get("alg")
        if not isinstance(keyid, str) or isinstance(keyid, Token):
            res.reason = "keyid missing"; return res
        if not isinstance(created, int) or isinstance(created, bool) \
                or not isinstance(expires, int) or isinstance(expires, bool):
            res.reason = "created and expires are required integers"; return res
        if alg is not None and alg != "ed25519":
            res.reason = f"unsupported alg {alg!r}"; return res
        if nonce is not None and (not isinstance(nonce, str) or isinstance(nonce, Token)):
            res.reason = "nonce must be a string"; return res
        return None

    def _check_times(self, created: int, expires: int, now: float, res: Result) -> Optional[Result]:
        p = self.policy
        if created > now + p.clock_skew:
            res.reason = "created is in the future"; return res
        if expires <= created:
            res.reason = "expires must be after created"; return res
        if p.max_lifetime is not None and expires - created > p.max_lifetime:
            res.reason = "validity period too long"; return res
        if now > expires + p.clock_skew or now - created > p.max_age + p.clock_skew:
            res.outcome, res.reason = Outcome.EXPIRED, "signature expired"; return res
        return None

    def _identity(self, req: Request, covered: InnerList, label: str, res: Result) -> Optional[Result]:
        names = {c.value for c in covered.items}
        if not names & {"@authority", "@target-uri"}:
            res.reason = "@authority or @target-uri must be covered"; return res

        # Operator identity from Signature-Agent (must be signed if present).
        operator = None
        agent_header = req.header("signature-agent")
        if agent_header is not None:
            agent_url, error = self._agent_member(agent_header, covered, label)
            if error is not None:
                res.reason = error; return res
            try:  # None: the member is ignored and the key is looked up as for no header
                operator = None if agent_url is None else normalize_origin(agent_url)
            except ValueError as e:
                res.reason = str(e); return res
        res.operator = operator
        return None

    def _check_nonce(self, req: Request, keyid: str, nonce: Optional[str], created: int,
                     expires: int, now: float, res: Result) -> Optional[Result]:
        # Run only after the signature verifies, so unsigned junk cannot fill the store.
        p = self.policy
        if nonce is None:
            if p.require_nonce:
                res.reason = "nonce required"; return res
        elif len(nonce) < p.min_nonce_length:
            res.reason = "nonce too short"; return res
        elif self.nonces is not None:
            ttl = max(1, int(min(expires, created + p.max_age) - now + p.clock_skew) + 1)
            try:
                fresh = self.nonces.add_if_absent(f"{keyid}:{nonce}", ttl)
            except NonceStoreError as e:
                if req.method.upper() in p.fail_closed_methods:
                    res.reason = f"nonce store unavailable: {e}"; return res
                fresh = None
            if fresh is False:
                res.outcome, res.reason = Outcome.REPLAY, "nonce already used"; return res
            res.replay_protected = fresh is True
        return None

    def _resolve_key(self, res: Result, keyid: str, operator, now: float) -> Optional[ResolvedKey]:
        """Return the key, or None after setting ``res.outcome``/``res.reason``."""
        keys = self.keys
        resolved = keys.resolve(keyid, operator, now)
        if resolved is not None:
            return resolved
        # Asked only after resolve() found nothing, so it cannot affect key or trust.
        check = getattr(keys, "directory_unavailable", None)
        unavailable = callable(check) and check(operator, now) is True
        if unavailable:
            # A transient fetch failure must not read as a hostile signature.
            res.outcome, res.reason = Outcome.UNKNOWN_OPERATOR, "key directory unavailable"
        elif keys.is_allowlisted(operator):
            known = keyid in TEST_KEY_THUMBPRINTS  # outcome unchanged; only the reason is clearer
            res.reason = "known test key rejected" if known else "unknown keyid for allowlisted operator"
        else:
            res.outcome, res.reason = Outcome.UNKNOWN_OPERATOR, "no key for this operator"
        return None

    @staticmethod
    def _agent_member(header: str, covered: InnerList, label: str) -> tuple:
        """Return ``(url, error)`` for the member of ``label`` (spec section 3.4).

        ``(None, None)`` means ignored: covered only under another label's key
        (an intermediary may relabel the signature, not the covered key), or
        the member has parameters (-01 section 5.2.1)."""
        keys = [c.params.get("key") for c in covered.items if c.value == "signature-agent"]
        if not keys:
            return None, "Signature-Agent present but not covered"
        if label not in keys and None not in keys:
            return None, None
        member = None
        if label not in keys:  # bare component: a legacy sf-string stands for {label: value}
            try:
                member = parse_item(header)
            except StructuredFieldError:
                pass
        if not (isinstance(member, Item) and isinstance(member.value, str)):
            try:
                member = parse_dictionary(header).get(label)
            except StructuredFieldError:
                member = None
        if isinstance(member, Item) and member.params:
            return None, None
        if isinstance(member, Item) and isinstance(member.value, str) and not isinstance(member.value, Token):
            return member.value, None
        return None, "cannot determine Signature-Agent value"


# --- Signing (for tests, examples and agent operators) ---

def sign_request(req: Request, private_key: Ed25519PrivateKey, *, agent: str,
                 components: Sequence[str] = ("@method", "@authority", "@path", "signature-agent"),
                 created: Optional[int] = None, expires: Optional[int] = None,
                 nonce: Optional[str] = None, label: str = "sig1",
                 keyid: Optional[str] = None, include_alg: bool = True) -> Request:
    """Return a copy of ``req`` with ``Signature-Agent: <label>="<agent>"``, Content-Digest
    (if covered), Signature-Input and Signature headers added (-01 section 5.2)."""
    normalize_origin(agent)  # raises ValueError for a non-https agent
    if "signature-agent" not in components or not {"@authority", "@target-uri"} & set(components):
        raise ValueError('components must include "signature-agent" and "@authority" or "@target-uri"')
    created = int(time.time()) if created is None else created
    expires = created + 60 if expires is None else expires
    keyid = keyid or jwk_thumbprint(public_jwk(private_key))
    headers = [(k, v) for k, v in req._headers
               if k not in ("signature", "signature-input", "signature-agent")]
    headers.append(("signature-agent", f"{label}={serialize_bare_item(agent)}"))
    comps = [Item(c, {"key": label} if c == "signature-agent" else {}) for c in components]
    if "content-digest" in components and not any(k == "content-digest" for k, _ in headers):
        headers.append(("content-digest", f"sha-256=:{base64.b64encode(hashlib.sha256(req.body).digest()).decode()}:"))
    params: Params = {"created": created, "expires": expires, "keyid": keyid}
    if include_alg:
        params["alg"] = "ed25519"
    if nonce is not None:
        params["nonce"] = nonce
    params["tag"] = TAG
    return _sign(Request(req.method, req.url, headers, req.body), private_key,
                 InnerList(comps, params), label)


def _sign(req: Request, private_key: Ed25519PrivateKey, covered: InnerList, label: str) -> Request:
    """Sign ``req`` as given, with no header or coverage checks (tests and vectors)."""
    sig = private_key.sign(signature_base(req, covered))
    return Request(req.method, req.url, req._headers + [
        ("signature-input", f"{label}={serialize_inner_list(covered)}"),
        ("signature", f"{label}=:{base64.b64encode(sig).decode()}:")], req.body)
