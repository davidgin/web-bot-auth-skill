# SPDX-License-Identifier: Apache-2.0
"""Run with: python -m unittest -v test_web_bot_auth  (from this directory)."""

import base64
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from web_bot_auth import (
    DirectoryKeyResolver, InMemoryNonceStore, NonceStoreError, Outcome, Policy,
    Request, StaticKeyResolver, Verifier, jwk_thumbprint, parse_dictionary,
    public_jwk, sign_request, signature_base, WELL_KNOWN_DIRECTORY,
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


class DirectoryConfiguration(Fixture):
    def test_configured_directory_path_and_query_override_request(self):
        for suffix in ("/operator/keys.json", "/operator/keys.json?version=2"):
            with self.subTest(suffix=suffix):
                configured = AGENT + suffix
                fetched = []

                def fetch(url):
                    fetched.append(url)
                    return json.dumps(self.jwks).encode(), 600

                res = DirectoryKeyResolver([configured], fetch=fetch)
                verifier = Verifier(res, clock=clock)
                result = verifier.verify(self.signed(agent=AGENT + "/untrusted?evil=1"))
                self.assertEqual(result.outcome, Outcome.VERIFIED, result.reason)
                self.assertEqual(result.operator, AGENT)
                self.assertEqual(res.allowlist, {AGENT})
                self.assertEqual(fetched, [configured])

    def test_origin_entries_use_normalized_well_known_location(self):
        for entry in (AGENT, AGENT + "/", "https://AGENT.example:443"):
            with self.subTest(entry=entry):
                fetched = []
                res = DirectoryKeyResolver([entry], fetch=lambda url: (
                    fetched.append(url) or json.dumps(self.jwks).encode(), 600))
                result = Verifier(res, clock=clock).verify(self.signed())
                self.assertEqual(result.outcome, Outcome.VERIFIED)
                self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_configured_root_query_uses_well_known_path(self):
        fetched = []
        res = DirectoryKeyResolver([AGENT + "/?version=2"], fetch=lambda url: (
            fetched.append(url) or json.dumps(self.jwks).encode(), 600))
        self.assertEqual(Verifier(res, clock=clock).verify(self.signed()).outcome, Outcome.VERIFIED)
        self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY + "?version=2"])

    def test_invalid_directory_configuration_rejected(self):
        for entry in ("", "agent.example", "http://agent.example/keys", "https:///keys",
                      AGENT + "/keys#fragment", "https://user@agent.example/keys",
                      "https://agent.example:bad/keys"):
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError):
                    DirectoryKeyResolver([entry])


class DirectorySecurity(Fixture):
    def setUp(self):
        super().setUp()
        self.now = NOW
        self.attacker = Ed25519PrivateKey.generate()
        self.fetched = []
        self.evil_url = AGENT + "/~mallory/keys.json"
        self.resolver = DirectoryKeyResolver([AGENT], fetch=self.fetch)
        self.verifier = Verifier(self.resolver, clock=lambda: self.now)

    def fetch(self, url):
        self.fetched.append(url)
        key = self.key if url == AGENT + WELL_KNOWN_DIRECTORY else self.attacker
        return json.dumps({"keys": [public_jwk(key)]}).encode(), 86400

    def attack(self, agent=None, forged=False, **kw):
        req = sign_request(Request("GET", "https://shop.example/x", []), self.attacker,
                           created=self.now - 1, expires=self.now + 59, nonce=NONCE,
                           agent=agent or self.evil_url, **kw)
        if forged:
            bad = "sig1=:" + base64.b64encode(b"\0" * 64).decode() + ":"
            req = Request(req.method, req.url,
                          [(k, bad if k == "signature" else v) for k, v in req._headers])
        return req

    def warm(self):
        self.assertEqual(self.outcome(self.signed()).outcome, Outcome.VERIFIED)
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY])
        self.now += 61

    def test_forged_request_cannot_choose_directory(self):
        self.warm()
        result = self.outcome(self.attack(forged=True))
        self.assertEqual(result.outcome, Outcome.INVALID)
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY] * 2)

    def test_attacker_path_cannot_impersonate_warm_operator(self):
        self.warm()
        result = self.outcome(self.attack())
        self.assertEqual(result.outcome, Outcome.INVALID)
        self.assertEqual(result.reason, "unknown keyid for allowlisted operator")

    def test_attacker_path_cannot_impersonate_cold_operator(self):
        for dictionary in (False, True):
            with self.subTest(dictionary=dictionary):
                self.resolver = DirectoryKeyResolver([AGENT], fetch=self.fetch)
                self.verifier = Verifier(self.resolver, clock=lambda: self.now)
                result = self.outcome(self.attack(agent_as_dictionary=dictionary))
                self.assertEqual(result.outcome, Outcome.INVALID)
                self.assertEqual(result.operator, AGENT)
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY] * 2)

    def test_poison_attempt_does_not_lock_out_operator(self):
        self.warm()
        self.outcome(self.attack(forged=True))
        self.assertEqual(self.outcome(self.signed()).outcome, Outcome.VERIFIED)

    def test_request_paths_and_queries_do_not_change_configured_location(self):
        for agent in (self.evil_url + "?key=evil#fragment", AGENT + "/?evil=1"):
            with self.subTest(agent=agent):
                self.resolver = DirectoryKeyResolver([AGENT], fetch=self.fetch)
                self.verifier = Verifier(self.resolver, clock=lambda: self.now)
                self.assertEqual(self.outcome(self.signed(agent=agent)).outcome, Outcome.VERIFIED)
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY] * 2)

    def test_untrusted_spam_does_not_accumulate_resolver_state(self):
        before = {k: dict(v) for k, v in vars(self.resolver).items() if isinstance(v, dict)}
        for i in range(100):
            agent = f"https://stranger{i}.example/keys?i={i}"
            unsigned = Request("GET", "https://shop.example/", [("signature-agent", f'"{agent}"')])
            self.assertEqual(self.outcome(unsigned).outcome, Outcome.UNSIGNED)
            self.assertEqual(self.outcome(self.attack(agent, forged=True)).outcome,
                             Outcome.UNKNOWN_OPERATOR)
        after = {k: dict(v) for k, v in vars(self.resolver).items() if isinstance(v, dict)}
        self.assertEqual(after, before)
        self.assertEqual(self.fetched, [])

    def test_bad_digest_does_not_mutate_resolver_state(self):
        req = self.signed("POST", body=b"original", agent=self.evil_url)
        before = {k: dict(v) for k, v in vars(self.resolver).items() if isinstance(v, dict)}
        result = self.outcome(Request(req.method, req.url, req._headers, b"tampered"))
        self.assertEqual(result.reason, "content-digest does not match body")
        self.assertEqual({k: dict(v) for k, v in vars(self.resolver).items()
                          if isinstance(v, dict)}, before)
        self.assertEqual(self.fetched, [])

    def test_malformed_agent_does_not_fetch_or_change_state(self):
        req = self.attack()
        before = {k: dict(v) for k, v in vars(self.resolver).items() if isinstance(v, dict)}
        for header in ('""', '" "', 'sig1="unterminated', 'sig1=?1',
                       '"http://agent.example"', '"not a URL"', '"https://agent.example:bad"'):
            with self.subTest(header=header):
                headers = [(k, header if k == "signature-agent" else v) for k, v in req._headers]
                self.assertEqual(self.outcome(Request(req.method, req.url, headers)).outcome,
                                 Outcome.INVALID)
                self.assertEqual(self.fetched, [])
                self.assertEqual({k: dict(v) for k, v in vars(self.resolver).items()
                                  if isinstance(v, dict)}, before)

    def test_missing_agent_with_empty_allowlist_does_not_fetch(self):
        self.resolver = DirectoryKeyResolver([], fetch=self.fetch)
        self.verifier = Verifier(self.resolver, clock=clock)
        self.assertEqual(self.outcome(self.signed(agent=None)).outcome, Outcome.UNKNOWN_OPERATOR)
        self.assertEqual(self.fetched, [])
        self.assertEqual(self.resolver._cache, {})
        self.assertEqual(self.resolver._last_fetch, {})

    def test_bad_signature_spam_is_bounded_for_allowlisted_origin(self):
        kid = jwk_thumbprint(public_jwk(self.key))
        for i in range(100):
            result = self.outcome(self.attack(self.evil_url + f"?key={i}", forged=True, keyid=kid))
            self.assertEqual(result.outcome, Outcome.INVALID)
            self.assertEqual(result.reason, "signature does not verify")
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY])
        self.assertEqual(set(self.resolver._cache), {AGENT})
        self.assertEqual(set(self.resolver._last_fetch), {AGENT})
        self.assertFalse(hasattr(self.resolver, "_agent_urls"))
        self.assertFalse(hasattr(self.resolver, "register_agent_url"))


class DirectoryRefetch(Fixture):
    def test_failed_cold_fetches_are_rate_limited_and_recover_at_boundary(self):
        for error in (TimeoutError("timeout"), OSError("offline"), ValueError("bad JSON")):
            with self.subTest(error=error):
                calls = []

                def fetch(url):
                    calls.append(url)
                    if len(calls) == 1:
                        if isinstance(error, ValueError):
                            return b"not JSON", 600
                        raise error
                    return json.dumps(self.jwks).encode(), 600

                res = DirectoryKeyResolver([AGENT], fetch=fetch)
                kid = jwk_thumbprint(public_jwk(self.key))
                for offset in (0, 0, 1, 59.999):
                    self.assertIsNone(res.resolve(kid, AGENT, NOW + offset))
                self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])
                self.assertTrue(res.resolve(kid, AGENT, NOW + 60).trusted)
                self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY] * 2)

    def test_failed_fetch_limit_is_per_operator(self):
        calls = []

        def fetch(url):
            calls.append(url)
            raise TimeoutError("offline")

        other = "https://other.example"
        res = DirectoryKeyResolver([AGENT, other], fetch=fetch)
        for operator in (AGENT, other, AGENT, other):
            self.assertIsNone(res.resolve("unknown", operator, NOW))
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY, other + WELL_KNOWN_DIRECTORY])

    def test_concurrent_cold_requests_share_one_fetch_attempt(self):
        for fails in (False, True):
            with self.subTest(fails=fails):
                entered, release = threading.Event(), threading.Event()
                calls, lock = [], threading.Lock()

                def fetch(url):
                    with lock:
                        calls.append(url)
                        first = len(calls) == 1
                    if first:
                        entered.set()
                        if not release.wait(5):
                            raise TimeoutError("test did not release fetch")
                    if fails:
                        raise TimeoutError("directory timeout")
                    return json.dumps(self.jwks).encode(), 600

                res = DirectoryKeyResolver([AGENT], fetch=fetch)
                verifier = Verifier(res, clock=clock)
                request = self.signed()
                with ThreadPoolExecutor(max_workers=8) as pool:
                    first = pool.submit(verifier.verify, request)
                    try:
                        self.assertTrue(entered.wait(2))
                        others = [pool.submit(verifier.verify, request) for _ in range(7)]
                        results = [future.result(timeout=2) for future in others]
                        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])
                        self.assertTrue(all(r.outcome == Outcome.INVALID for r in results))
                    finally:
                        release.set()
                    result = first.result(timeout=2)
                expected = Outcome.INVALID if fails else Outcome.VERIFIED
                self.assertEqual(result.outcome, expected)

    def test_warm_cache_survives_failed_rotation_and_limits_unknown_keyids(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if len(calls) > 1:
                raise TimeoutError("offline")
            return json.dumps(self.jwks).encode(), 300

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT, NOW).trusted)
        for i in range(20):
            self.assertIsNone(res.resolve(f"unknown-{i}", AGENT, NOW + 61))
        self.assertTrue(res.resolve(kid, AGENT, NOW + 301).trusted)
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY] * 3)


class DirectoryTrust(Fixture):
    def test_removed_operator_cached_key_is_untrusted(self):
        calls = []
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (
            calls.append(url) or json.dumps(self.jwks).encode(), 600))
        verifier = Verifier(res, clock=clock)
        request = self.signed()
        self.assertEqual(verifier.verify(request).outcome, Outcome.VERIFIED)
        res.allowlist.discard(AGENT)
        self.assertFalse(res.is_allowlisted(AGENT))
        self.assertEqual(verifier.verify(request).outcome, Outcome.SIGNED_UNTRUSTED)
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])
        res.allowlist.add(AGENT)
        self.assertEqual(verifier.verify(request).outcome, Outcome.VERIFIED)
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_removed_operator_expired_cache_cannot_be_used(self):
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 300))
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT, NOW).trusted)
        res.allowlist.clear()
        self.assertFalse(res.resolve(kid, AGENT, NOW + 299.999).trusted)
        self.assertIsNone(res.resolve(kid, AGENT, NOW + 300))

    def test_operator_removed_during_fetch_is_not_trusted(self):
        def fetch(url):
            res.allowlist.discard(AGENT)
            return json.dumps(self.jwks).encode(), 600

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        result = Verifier(res, clock=clock).verify(self.signed())
        self.assertEqual(result.outcome, Outcome.SIGNED_UNTRUSTED)

    def test_background_directory_stays_untrusted_and_expires(self):
        res = DirectoryKeyResolver([])
        res.add_untrusted_directory(AGENT, self.jwks, ttl=60, now=NOW)
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertFalse(res.resolve(kid, AGENT, NOW).trusted)
        self.assertIsNone(res.resolve("unknown", AGENT, NOW))
        self.assertIsNone(res.resolve(kid, AGENT, NOW + 60))


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
