# SPDX-License-Identifier: Apache-2.0
"""Run with: python -m unittest -v test_web_bot_auth  (from this directory)."""

import base64
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from web_bot_auth import (
    DirectoryKeyResolver, InMemoryNonceStore, NonceStoreError, Outcome, Policy,
    Request, StaticKeyResolver, Verifier, jwk_thumbprint, parse_dictionary,
    public_jwk, sign_request, signature_base,
)

NOW = 1_800_000_000
AGENT = "https://agent.example"
NONCE = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2U="


def clock():
    return NOW


class Fixture(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.jwks = {"keys": [public_jwk(self.key)]}
        self.nonces = InMemoryNonceStore(clock=clock)
        self.verifier = Verifier(StaticKeyResolver({AGENT: self.jwks}), self.nonces, clock=clock)

    def signed(self, method="GET", url="https://shop.example/items/42", body=b"", **kw):
        kw.setdefault("components", ("@method", "@authority", "@path", "signature-agent")
                      + (("content-digest",) if body else ()))
        kw.setdefault("created", NOW - 1)
        kw.setdefault("expires", NOW + 59)
        kw.setdefault("nonce", NONCE)
        kw.setdefault("agent", AGENT)
        return sign_request(Request(method, url, [("host", "shop.example")], body), self.key, **kw)

    def outcome(self, req, verifier=None):
        return (verifier or self.verifier).verify(req)


class Accepts(Fixture):
    def test_verified_and_bound(self):
        r = self.outcome(self.signed())
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertTrue(r.binds_request)
        self.assertTrue(r.replay_protected)
        self.assertEqual(r.operator, AGENT)

    def test_post_with_body(self):
        r = self.outcome(self.signed("POST", body=b'{"qty": 2}'))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertTrue(r.binds_request)

    def test_draft05_dictionary_signature_agent(self):
        r = self.outcome(self.signed(agent_as_dictionary=True))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)

    def test_minimal_draft_coverage_verifies_but_is_unbound(self):
        r = self.outcome(self.signed(components=("@authority", "signature-agent")))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertFalse(r.binds_request)

    def test_no_nonce_verifies_but_is_unprotected(self):
        r = self.outcome(self.signed(nonce=None))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertFalse(r.replay_protected)

    def test_unsigned(self):
        r = self.outcome(Request("GET", "https://shop.example/", [("user-agent", "x")]))
        self.assertEqual(r.outcome, Outcome.UNSIGNED)

    def test_untrusted_operator(self):
        v = Verifier(StaticKeyResolver({AGENT: self.jwks}, trusted=False), self.nonces, clock=clock)
        self.assertEqual(self.outcome(self.signed(), v).outcome, Outcome.SIGNED_UNTRUSTED)


class Rejects(Fixture):
    def assertOutcome(self, req, expected, verifier=None):
        r = self.outcome(req, verifier)
        self.assertEqual(r.outcome, expected, r.reason)
        return r

    def test_replay(self):
        req = self.signed()
        self.assertOutcome(req, Outcome.VERIFIED)
        self.assertOutcome(req, Outcome.REPLAY)

    def test_tampered_body(self):
        req = self.signed("POST", body=b'{"qty": 2}')
        req = Request(req.method, req.url, req._headers, b'{"qty": 200}')
        self.assertOutcome(req, Outcome.INVALID)

    def test_method_swap(self):
        req = self.signed("GET")
        self.assertOutcome(Request("DELETE", req.url, req._headers), Outcome.INVALID)

    def test_path_swap(self):
        req = self.signed()
        self.assertOutcome(Request("GET", "https://shop.example/admin", req._headers), Outcome.INVALID)

    def test_host_swap(self):
        req = self.signed()
        self.assertOutcome(Request("GET", "https://other.example/items/42", req._headers), Outcome.INVALID)

    def test_signature_agent_swap(self):
        req = self.signed()
        h = [(k, '"https://evil.example"' if k == "signature-agent" else v) for k, v in req._headers]
        r = self.outcome(Request(req.method, req.url, h))
        self.assertNotEqual(r.outcome, Outcome.VERIFIED)

    def test_uncovered_signature_agent(self):
        req = self.signed(components=("@method", "@authority", "@path"))
        req = Request(req.method, req.url, req._headers + [("signature-agent", f'"{AGENT}"')])
        self.assertOutcome(req, Outcome.INVALID)

    def test_expired(self):
        self.assertOutcome(self.signed(created=NOW - 120, expires=NOW - 60), Outcome.EXPIRED)

    def test_created_too_old_even_if_expires_late(self):
        self.assertOutcome(self.signed(created=NOW - 3600, expires=NOW + 3600), Outcome.EXPIRED)

    def test_created_in_future(self):
        self.assertOutcome(self.signed(created=NOW + 60, expires=NOW + 120), Outcome.INVALID)

    def test_lifetime_too_long(self):
        self.assertOutcome(self.signed(created=NOW - 1, expires=NOW + 2 * 86400), Outcome.INVALID)

    def test_clock_skew_tolerated(self):
        self.assertOutcome(self.signed(created=NOW + 3, expires=NOW + 60), Outcome.VERIFIED)

    def test_wrong_key(self):
        other = Ed25519PrivateKey.generate()
        req = self.signed(keyid=jwk_thumbprint(public_jwk(self.key)))
        forged = sign_request(Request("GET", req.url, [("host", "shop.example")]), other,
                              created=NOW - 1, expires=NOW + 59, nonce=NONCE, agent=AGENT,
                              keyid=jwk_thumbprint(public_jwk(self.key)))
        self.assertOutcome(forged, Outcome.INVALID)

    def test_unknown_keyid_from_allowlisted_operator(self):
        other = Ed25519PrivateKey.generate()
        req = sign_request(Request("GET", "https://shop.example/", []), other,
                           created=NOW - 1, expires=NOW + 59, nonce=NONCE, agent=AGENT)
        self.assertOutcome(req, Outcome.INVALID)

    def test_unknown_operator_is_not_hostile(self):
        req = self.signed(agent="https://stranger.example")
        r = self.assertOutcome(req, Outcome.UNKNOWN_OPERATOR)
        self.assertFalse(r.hostile)

    def test_bad_alg(self):
        req = self.signed()
        h = [(k, v.replace('alg="ed25519"', 'alg="rsa-pss-sha512"') if k == "signature-input" else v)
             for k, v in req._headers]
        self.assertOutcome(Request(req.method, req.url, h), Outcome.INVALID)

    def test_malformed_headers(self):
        req = Request("GET", "https://shop.example/", [
            ("signature-input", 'sig1=("@authority";tag="web-bot-auth"'), ("signature", "sig1=:AAAA:")])
        self.assertOutcome(req, Outcome.INVALID)

    def test_only_one_of_signature_headers(self):
        req = Request("GET", "https://shop.example/", [("signature", "sig1=:AAAA:")])
        self.assertOutcome(req, Outcome.INVALID)

    def test_short_nonce(self):
        self.assertOutcome(self.signed(nonce="abc"), Outcome.INVALID)

    def test_query_not_covered_is_unbound(self):
        r = self.outcome(self.signed(url="https://shop.example/items?id=1"))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertFalse(r.binds_request)

    def test_require_binding(self):
        v = Verifier(StaticKeyResolver({AGENT: self.jwks}), self.nonces,
                     Policy(require_binding=True), clock=clock)
        self.assertOutcome(self.signed(components=("@authority", "signature-agent")), Outcome.INVALID, v)

    def test_require_nonce(self):
        v = Verifier(StaticKeyResolver({AGENT: self.jwks}), self.nonces,
                     Policy(require_nonce=True), clock=clock)
        self.assertOutcome(self.signed(nonce=None), Outcome.INVALID, v)


class NonceStoreFailure(Fixture):
    class Broken:
        def add_if_absent(self, key, ttl):
            raise NonceStoreError("down")

    def test_fail_closed_for_unsafe_methods(self):
        v = Verifier(StaticKeyResolver({AGENT: self.jwks}), self.Broken(), clock=clock)
        r = self.outcome(self.signed("POST", body=b"x"), v)
        self.assertEqual(r.outcome, Outcome.INVALID)

    def test_fail_open_for_safe_methods(self):
        v = Verifier(StaticKeyResolver({AGENT: self.jwks}), self.Broken(), clock=clock)
        r = self.outcome(self.signed("GET"), v)
        self.assertEqual(r.outcome, Outcome.VERIFIED)
        self.assertFalse(r.replay_protected)


class Directory(Fixture):
    def test_fetches_only_allowlisted(self):
        fetched = []

        def fetch(url):
            fetched.append(url)
            return (b'{"keys": [%s]}' % str(public_jwk(self.key)).replace("'", '"').encode(), 600)

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        v = Verifier(res, self.nonces, clock=clock)
        self.assertEqual(v.verify(self.signed()).outcome, Outcome.VERIFIED)
        self.assertEqual(fetched, [AGENT + "/.well-known/http-message-signatures-directory"])
        v.verify(self.signed(agent="https://attacker.example", nonce=NONCE + "x"))
        self.assertEqual(len(fetched), 1)  # no fetch for a non-allowlisted operator

    def test_rotation_refetch_is_rate_limited(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return (b'{"keys": []}', 600)

        res = DirectoryKeyResolver([AGENT], fetch=fetch, refetch_interval=60)
        for i in range(5):
            res.resolve("unknown", AGENT, NOW + i)
        self.assertEqual(len(calls), 1)


class Conformance(unittest.TestCase):
    """RFC 9421 Appendix B.2.6 (Ed25519) test vector."""

    PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----"""
    SIG = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="

    def test_rfc9421_b26(self):
        key = load_pem_private_key(self.PEM, None)
        req = Request("POST", "https://example.com/foo?param=Value&Pet=dog", [
            ("Host", "example.com"), ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"), ("Content-Length", "18")], b'{"hello": "world"}')
        covered = parse_dictionary(
            'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")'
            ';created=1618884473;keyid="test-key-ed25519"')["sig-b26"]
        base = signature_base(req, covered)
        key.public_key().verify(base64.b64decode(self.SIG), base)


class Vectors(unittest.TestCase):
    def test_vectors_file_is_current(self):
        import json, os
        import generate_vectors
        path = os.path.join(os.path.dirname(__file__), "..", "assets", "test-vectors.json")
        with open(path) as f:
            self.assertEqual(json.load(f), generate_vectors.build(),
                             "regenerate: python generate_vectors.py > ../assets/test-vectors.json")


if __name__ == "__main__":
    unittest.main()
