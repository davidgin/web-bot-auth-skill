# SPDX-License-Identifier: Apache-2.0
"""Generate assets/test-vectors.json: deterministic requests with expected outcomes.

Ports to other languages should load the JSON, verify each request at the given
`now` with the given keys and a fresh nonce store per vector (except where
`sequence` groups vectors), and compare `expected.outcome` and the flags.

    python generate_vectors.py > ../assets/test-vectors.json
"""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from web_bot_auth import (InMemoryNonceStore, Policy, Request, StaticKeyResolver,
                          Verifier, public_jwk, sign_request)

NOW = 1_800_000_000
AGENT = "https://agent.example"
NONCE = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2U="
# TEST ONLY. Deterministic keys so vectors are reproducible; never use in production.
KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"web-bot-auth test key").digest())
OTHER = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"web-bot-auth other key").digest())


def req(method="GET", url="https://shop.example/items/42", body=b"", key=KEY, **kw):
    kw.setdefault("components", ("@method", "@authority", "@path", "signature-agent")
                  + (("content-digest",) if body else ()))
    kw.setdefault("created", NOW - 1)
    kw.setdefault("expires", NOW + 59)
    kw.setdefault("nonce", NONCE)
    kw.setdefault("agent", AGENT)
    return sign_request(Request(method, url, [("host", urlhost(url))], body), key, **kw)


def urlhost(url):
    return url.split("/")[2]


def mutate(r, method=None, url=None, body=None, header=None):
    h = list(r._headers)
    if header:
        name, fn = header
        h = [(k, fn(v) if k == name else v) for k, v in h]
    return Request(method or r.method, url or r.url, h, r.body if body is None else body)


def cases():
    base = req()
    post = req("POST", body=b'{"qty": 2}')
    yield "verified_bound", req(), {}
    yield "verified_post_body", post, {}
    yield "verified_dictionary_agent", req(agent_as_dictionary=True), {}
    yield "verified_minimal_coverage_unbound", req(components=("@authority", "signature-agent")), {}
    yield "verified_without_nonce", req(nonce=None), {}
    yield "unsigned", Request("GET", "https://shop.example/", [("host", "shop.example")]), {}
    yield "invalid_tampered_body", mutate(post, body=b'{"qty": 200}'), {}
    yield "invalid_method_swap", mutate(base, method="DELETE"), {}
    yield "invalid_path_swap", mutate(base, url="https://shop.example/admin"), {}
    yield "invalid_wrong_key", req(key=OTHER, keyid=public_kid(KEY)), {}
    yield "invalid_bad_alg", mutate(base, header=("signature-input",
                                     lambda v: v.replace('"ed25519"', '"rsa-pss-sha512"'))), {}
    yield "invalid_created_in_future", req(created=NOW + 60, expires=NOW + 120), {}
    yield "invalid_lifetime_too_long", req(created=NOW - 1, expires=NOW + 2 * 86400), {}
    yield "invalid_short_nonce", req(nonce="abc"), {}
    yield "expired", req(created=NOW - 120, expires=NOW - 60), {}
    yield "expired_created_too_old", req(created=NOW - 3600, expires=NOW + 3600), {}
    yield "unknown_operator", req(agent="https://stranger.example"), {}
    yield "invalid_require_binding", req(components=("@authority", "signature-agent")), {"require_binding": True}
    yield "invalid_require_nonce", req(nonce=None), {"require_nonce": True}


def public_kid(k):
    from web_bot_auth import jwk_thumbprint
    return jwk_thumbprint(public_jwk(k))


def build():
    vectors = []
    for name, r, policy in cases():
        v = Verifier(StaticKeyResolver({AGENT: {"keys": [public_jwk(KEY)]}}, allow_test_keys=True),
                     InMemoryNonceStore(clock=lambda: NOW), Policy(**policy), clock=lambda: NOW)
        res = v.verify(r)
        vectors.append(vector(name, r, policy, res))
    # Replay: the same request twice against one nonce store.
    r = req()
    v = Verifier(StaticKeyResolver({AGENT: {"keys": [public_jwk(KEY)]}}, allow_test_keys=True),
                 InMemoryNonceStore(clock=lambda: NOW), clock=lambda: NOW)
    for name in ("replay_first", "replay_second"):
        vectors.append(vector(name, r, {}, v.verify(r), sequence="replay"))
    return {
        "description": "Web Bot Auth verifier vectors. TEST KEYS ONLY: their thumbprints are on the verifier denylist, so ports must enable their equivalent of allow_test_keys=True to run these vectors. Flags are given only for accepted outcomes.",
        "now": NOW,
        "trusted_keys": {AGENT: {"keys": [public_jwk(KEY)]}},
        "default_policy": {"max_age": 300, "max_lifetime": 86400, "clock_skew": 5,
                           "min_nonce_length": 16},
        "vectors": vectors,
    }


def main():
    print(json.dumps(build(), indent=2))


def vector(name, r, policy, res, sequence=None):
    out = {
        "name": name,
        "request": {"method": r.method, "url": r.url,
                    "headers": [[k, v] for k, v in r._headers],
                    "body_base64": base64.b64encode(r.body).decode()},
        "policy_overrides": policy,
        "expected": {"outcome": res.outcome.value},
    }
    if res.outcome.value in ("verified", "signed_untrusted"):
        out["expected"].update(binds_request=res.binds_request,
                               replay_protected=res.replay_protected)
    if sequence:
        out["sequence"] = sequence
    return out


if __name__ == "__main__":
    main()
