# SPDX-License-Identifier: Apache-2.0
"""Generate assets/test-vectors.json: deterministic requests with expected outcomes.

Ports to other languages should load the JSON, verify each request at the given
`now` with the given keys and a fresh nonce store per vector (except where
`sequence` groups vectors), and compare `expected.outcome` and the flags. Operators
are normalized URLs (the identifiers of the -01 Signature-Agent URL), accepted
outcomes also give `expected.operator` and `expected.claimed_agent`, and ports must
pass their equivalent of `allow_test_keys=True`. The `normalization` section
(input -> identifier, or null for reject) is the cross-language identity contract:
a port's normalizer must reproduce it exactly.

    python generate_vectors.py > ../assets/test-vectors.json
"""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from web_bot_auth import (InMemoryNonceStore, Policy, Request, StaticKeyResolver,
                          Verifier, _sign, normalize_agent_url, parse_dictionary, public_jwk,
                          sign_request)

NOW = 1_800_000_000
AGENT = "https://agent.example"
AGENT_ID = normalize_agent_url(AGENT)  # resolvers and trusted_keys are keyed by identifier
LONG_PATH = "https://a.example/" + "k" * (2048 - len("https://a.example/"))
# Spec section 3.1 table, written out by hand (not computed from the implementation): this is
# the cross-language contract. test_web_bot_auth.NORMALIZATION_CASES is the second, intentional
# copy; an equality test catches drift between the two.
NORMALIZATION_CASES = (
    ("HTTPS://Agent.EXAMPLE/K", "https://agent.example/K"),
    ("https://agent.example:443", "https://agent.example/"),
    ("https://a.example:/", "https://a.example/"),
    ("https://a.example:8443/x", "https://a.example:8443/x"),
    ("https://Agent.Example:443/a/./b/../%7euser/k%2fs.json?v=3", "https://agent.example/a/~user/k%2Fs.json"),
    ("https://a.example/a/..", "https://a.example/"),
    ("https://a.example/a/.", "https://a.example/a/"),
    ("https://a.example/%2E%2E/x", "https://a.example/x"),
    ("https://%61.example/", "https://a.example/"),
    ("https://[2001:DB8::1]/", "https://[2001:db8::1]/"),
    ("https://agent.example.", "https://agent.example./"),
    ("https://a.example?x=1", "https://a.example/"),
    ("https://a.example:65535/", "https://a.example:65535/"),
    (LONG_PATH, LONG_PATH),
    ("", None), ("agent.example", None), ("http://a.example", None), ("data:x", None),
    ("https:///k", None), ("https://u@a.example/", None), ("https://a.example/#f", None),
    ("https://a.example#", None), ("https://a.example:x/", None), ("https://a.example:0/", None),
    ("https://a.example:0443/", None), ("https://a.example:65536/", None),
    ("https://a.example:+443/", None), ("https://a.example/%zz", None), ("https://a.example/%4", None),
    ("https://\u00e4.example/", None), ("https://a.example/a b", None), ("https://a.example/a\tb", None),
    ("https://a.example/a\x7fb", None), ("https://a.example/a\\b", None), ('https://a.example/a"b', None),
    ("https://a.example/a{b", None), ("https://a.example/a|b", None), ("https://a.example/a^b", None),
    ("https://[v1.x]/", None), ("https://[fe80::1%25eth0]/", None), ("https://a.example/[", None),
    ("https://a.example/k?[", None), ("https://a.ex%2Fample/", None), ("https://a!.example/", None),
    (LONG_PATH + "k", None),
)
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


def hand_signed(agent_header, components, label="sig1", key=KEY):
    """Sign headers exactly as given (legacy and ignored-member shapes the signer never emits)."""
    covered = parse_dictionary(
        f'{label}=({components});created={NOW - 1};expires={NOW + 59};'
        f'keyid="{public_kid(key)}";alg="ed25519";nonce="{NONCE}";tag="web-bot-auth"')[label]
    return _sign(Request("GET", "https://shop.example/items/42", [("host", "shop.example"), ("signature-agent", agent_header)]),
                 key, covered, label)


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
    yield "verified_custom_label", req(label="agent"), {}
    yield "verified_target_uri_only", req(components=("@target-uri", "signature-agent")), {}
    # The only legacy vector: an sf-string Signature-Agent, which -01 5.2.1 lets verifiers accept.
    yield "verified_legacy_string_agent", hand_signed(f'"{AGENT}"', '"@authority" "signature-agent"'), {}
    yield "verified_query_ignored_in_identifier", req(agent=AGENT + "/?v=3"), {}
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
    yield "unknown_operator_path_mismatch", req(agent=AGENT + "/other/path"), {}
    yield "ignored_parameterized_member", hand_signed(
        f'sig1="{AGENT}";x=1', '"@authority" "signature-agent";key="sig1"'), {}
    yield "ignored_member_key_not_label", hand_signed(
        f'agent2="{AGENT}"', '"@authority" "signature-agent";key="agent2"', "sig2"), {}
    yield "invalid_require_binding", req(components=("@authority", "signature-agent")), {"require_binding": True}
    yield "invalid_require_nonce", req(nonce=None), {"require_nonce": True}


def public_kid(k):
    from web_bot_auth import jwk_thumbprint
    return jwk_thumbprint(public_jwk(k))


def build():
    vectors = []
    for name, r, policy in cases():
        v = Verifier(StaticKeyResolver({AGENT_ID: {"keys": [public_jwk(KEY)]}}, allow_test_keys=True),
                     InMemoryNonceStore(clock=lambda: NOW), Policy(**policy), clock=lambda: NOW)
        res = v.verify(r)
        vectors.append(vector(name, r, policy, res))
    # Replay: the same request twice against one nonce store.
    r = req()
    v = Verifier(StaticKeyResolver({AGENT_ID: {"keys": [public_jwk(KEY)]}}, allow_test_keys=True),
                 InMemoryNonceStore(clock=lambda: NOW), clock=lambda: NOW)
    for name in ("replay_first", "replay_second"):
        vectors.append(vector(name, r, {}, v.verify(r), sequence="replay"))
    return {
        "description": "Web Bot Auth verifier vectors. TEST KEYS ONLY: their thumbprints are on the verifier denylist, so ports must enable their equivalent of allow_test_keys=True to run these vectors. Operators are normalized URLs (the -01 Signature-Agent identifier). Operator, claimed_agent and the flags are given only for accepted outcomes. The normalization section (input to identifier, null for reject) is the cross-language identity contract.",
        "now": NOW,
        "trusted_keys": {AGENT_ID: {"keys": [public_jwk(KEY)]}},
        "default_policy": {"max_age": 300, "max_lifetime": 86400, "clock_skew": 5,
                           "min_nonce_length": 16},
        "vectors": vectors,
        "normalization": [{"input": i, "identifier": o} for i, o in NORMALIZATION_CASES],
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
                               replay_protected=res.replay_protected,
                               operator=res.operator, claimed_agent=res.claimed_agent)
    if sequence:
        out["sequence"] = sequence
    return out


if __name__ == "__main__":
    main()
