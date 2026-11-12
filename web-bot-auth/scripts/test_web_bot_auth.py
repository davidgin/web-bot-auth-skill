# SPDX-License-Identifier: Apache-2.0
"""Run with: python -m unittest -v test_web_bot_auth  (from this directory)."""

import base64
import dataclasses
import functools
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from web_bot_auth import (
    DirectoryKeyResolver, InMemoryNonceStore, content_digest_matches, NonceStoreError, Outcome, Policy,
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

    def test_target_uri_without_authority_verifies(self):
        r = self.outcome(self.signed(components=("@method", "@target-uri", "signature-agent")))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertTrue(r.binds_request)

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

    def test_target_uri_host_swap_is_invalid(self):
        req = self.signed(components=("@method", "@target-uri", "signature-agent"))
        self.assertOutcome(Request("GET", "https://other.example/items/42", req._headers), Outcome.INVALID)

    def test_neither_authority_nor_target_uri_is_invalid(self):
        req = self.signed(components=("@method", "@path", "signature-agent"))
        r = self.assertOutcome(req, Outcome.INVALID)
        self.assertEqual(r.reason, "@authority or @target-uri must be covered")

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

    def test_conflicting_custom_directories_rejected_in_any_order(self):
        entries = [AGENT + "/a/keys.json", AGENT + "/b/keys.json"]
        for allowlist in (set(entries), entries, entries[::-1]):
            with self.subTest(allowlist=allowlist):
                with self.assertRaisesRegex(ValueError, "https://agent[.]example"):
                    DirectoryKeyResolver(allowlist)

    def test_origin_and_custom_directory_conflict_in_any_order(self):
        entries = [AGENT, AGENT + "/tenant/keys.json"]
        for allowlist in (entries, entries[::-1]):
            with self.subTest(allowlist=allowlist):
                with self.assertRaisesRegex(ValueError, "https://agent[.]example"):
                    DirectoryKeyResolver(allowlist)

    def test_identical_normalized_directories_are_allowed(self):
        entries = ["https://AGENT.example", AGENT]
        for allowlist in (entries, entries[::-1]):
            with self.subTest(allowlist=allowlist):
                fetched = []
                res = DirectoryKeyResolver(allowlist, fetch=lambda url: (
                    fetched.append(url) or json.dumps(self.jwks).encode(), 600))
                result = Verifier(res, clock=clock).verify(self.signed())
                self.assertEqual(result.outcome, Outcome.VERIFIED)
                self.assertEqual(res.allowlist, {AGENT})
                self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_runtime_added_normalized_origin_uses_well_known_directory(self):
        fetched = []
        res = DirectoryKeyResolver([], fetch=lambda url: (
            fetched.append(url) or json.dumps(self.jwks).encode(), 600))
        verifier = Verifier(res, clock=clock)
        request = self.signed(agent=AGENT + "/request/keys.json?evil=1")
        self.assertEqual(verifier.verify(request).outcome, Outcome.UNKNOWN_OPERATOR)
        self.assertEqual(fetched, [])
        res.allowlist.add(AGENT)
        self.assertEqual(verifier.verify(request).outcome, Outcome.VERIFIED)
        self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])

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
                        # No keys yet is "directory unavailable", never hostile.
                        self.assertTrue(all(r.outcome == Outcome.UNKNOWN_OPERATOR for r in results))
                        self.assertFalse(any(r.hostile for r in results))
                        self.assertEqual({r.reason for r in results}, {"key directory unavailable"})
                    finally:
                        release.set()
                    result = first.result(timeout=2)
                expected = Outcome.UNKNOWN_OPERATOR if fails else Outcome.VERIFIED
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


class DirectoryUnavailable(Fixture):
    """No usable keys for an allowlisted operator is not evidence of a bad signature."""

    def setUp(self):
        super().setUp()
        self.now = NOW
        self.calls = []
        self.fail = True

    def fetch(self, url):
        self.calls.append(self.now)
        if self.fail:
            raise TimeoutError("directory timeout")
        return json.dumps(self.jwks).encode(), 300

    def verifier_for(self, resolver):
        return Verifier(resolver, InMemoryNonceStore(clock=lambda: self.now), clock=lambda: self.now)

    def request(self, key=None, nonce=NONCE):
        return sign_request(
            Request("GET", "https://shop.example/items/42", [("host", "shop.example")]),
            key or self.key, components=("@method", "@authority", "@path", "signature-agent"),
            created=self.now - 1, expires=self.now + 59, nonce=nonce, agent=AGENT)

    def assert_unavailable(self, result):
        self.assertEqual(result.outcome, Outcome.UNKNOWN_OPERATOR, result.reason)
        self.assertEqual(result.reason, "key directory unavailable")
        self.assertFalse(result.hostile)
        self.assertEqual(result.operator, AGENT)

    def test_failed_cold_fetch_is_not_hostile_and_stays_rate_limited(self):
        v = self.verifier_for(DirectoryKeyResolver([AGENT], fetch=self.fetch))
        for offset in (0, 1, 59):
            self.now = NOW + offset
            self.assert_unavailable(v.verify(self.request(nonce=f"bm9uY2Utbm9uY2Utbm9uY2Ux{offset:02d}==")))
        self.assertEqual(self.calls, [NOW])
        self.fail, self.now = False, NOW + 60
        self.assertEqual(v.verify(self.request()).outcome, Outcome.VERIFIED)
        self.assertEqual(self.calls, [NOW, NOW + 60])

    def test_expired_cache_with_failed_refresh_is_not_hostile(self):
        res = DirectoryKeyResolver([AGENT], fetch=self.fetch)
        v = self.verifier_for(res)
        self.fail = False
        self.assertEqual(v.verify(self.request()).outcome, Outcome.VERIFIED)
        self.fail, self.now = True, NOW + 400  # past the 300 s ttl; refresh fails
        rotated = Ed25519PrivateKey.generate()
        self.assert_unavailable(v.verify(self.request(rotated)))
        self.assertEqual(self.calls, [NOW, NOW + 400])
        # Last good copy still serves keys it holds (stale-on-error is kept).
        self.assertEqual(v.verify(self.request(nonce=NONCE[:-3] + "xy=")).outcome, Outcome.VERIFIED)
        self.assertEqual(len(self.calls), 2)

    def test_warm_cache_with_unknown_keyid_stays_invalid(self):
        self.fail = False
        v = self.verifier_for(DirectoryKeyResolver([AGENT], fetch=self.fetch))
        self.assertEqual(v.verify(self.request()).outcome, Outcome.VERIFIED)
        self.now = NOW + 61
        r = v.verify(self.request(Ed25519PrivateKey.generate()))
        self.assertEqual(r.outcome, Outcome.INVALID)
        self.assertEqual(r.reason, "unknown keyid for allowlisted operator")
        self.assertTrue(r.hostile)
        self.assertEqual(self.calls, [NOW, NOW + 61])  # one rate-limited rotation refetch

    def test_warm_cache_unknown_keyid_while_refetch_fails_stays_invalid(self):
        self.fail = False
        v = self.verifier_for(DirectoryKeyResolver([AGENT], fetch=self.fetch))
        v.verify(self.request())
        self.fail, self.now = True, NOW + 61
        r = v.verify(self.request(Ed25519PrivateKey.generate()))
        self.assertEqual(r.outcome, Outcome.INVALID)

    def test_non_allowlisted_operator_still_unknown_without_fetch(self):
        v = self.verifier_for(DirectoryKeyResolver([AGENT], fetch=self.fetch))
        req = sign_request(
            Request("GET", "https://shop.example/", [("host", "shop.example")]), self.key,
            components=("@method", "@authority", "@path", "signature-agent"),
            created=NOW - 1, expires=NOW + 59, nonce=NONCE, agent="https://stranger.example")
        r = v.verify(req)
        self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "no key for this operator"))
        self.assertEqual(self.calls, [])


class ResolverExtensionPoints(Fixture):
    """Key and trust come only from resolve(); directory_unavailable() only picks the failure kind."""

    def directory(self):
        return DirectoryKeyResolver([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 600))

    def test_subclass_overriding_resolve_can_revoke_a_key(self):
        kid = jwk_thumbprint(public_jwk(self.key))

        class Revoking(DirectoryKeyResolver):
            def resolve(self, keyid, operator, now):
                return None if keyid == kid else super().resolve(keyid, operator, now)

        res = Revoking([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 600))
        res.resolve("warm-the-cache", AGENT, NOW)  # a cold cache would read as unavailable
        r = Verifier(res, clock=clock).verify(self.signed())
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "unknown keyid for allowlisted operator"))

    def test_getattr_wrapper_resolve_is_used(self):
        class Downgrade:
            def __init__(self, inner):
                self.inner = inner

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def resolve(self, keyid, operator, now):
                r = self.inner.resolve(keyid, operator, now)
                return r and dataclasses.replace(r, trusted=False)

        r = Verifier(Downgrade(self.directory()), clock=clock).verify(self.signed())
        self.assertEqual(r.outcome, Outcome.SIGNED_UNTRUSTED)

    def test_pure_getattr_wrapper_without_resolve_still_delegates(self):
        class Passthrough:
            def __init__(self, inner):
                self.inner = inner

            def __getattr__(self, name):
                return getattr(self.inner, name)

        r = Verifier(Passthrough(self.directory()), clock=clock).verify(self.signed())
        self.assertEqual(r.outcome, Outcome.VERIFIED)

    def test_unrelated_lookup_method_on_custom_resolver_is_ignored(self):
        class Custom(StaticKeyResolver):
            def lookup(self, keyid):
                raise AssertionError("must not be called by the verifier")

        r = Verifier(Custom({AGENT: self.jwks}), clock=clock).verify(self.signed())
        self.assertEqual(r.outcome, Outcome.VERIFIED)

    def test_unmodified_directory_resolver_still_reports_unavailable(self):
        def down(url):
            raise TimeoutError("down")

        r = Verifier(DirectoryKeyResolver([AGENT], fetch=down), clock=clock).verify(self.signed())
        self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "key directory unavailable"))

    def test_instance_patched_resolve_can_revoke_with_fresh_cache(self):
        kid = jwk_thumbprint(public_jwk(self.key))
        res = self.directory()
        res.resolve("warm-the-cache", AGENT, NOW)
        orig = res.resolve
        res.resolve = lambda k, o, n: None if k == kid else orig(k, o, n)
        r = Verifier(res, clock=clock).verify(self.signed())
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "unknown keyid for allowlisted operator"))

    def test_instance_partial_resolve_can_downgrade_trust(self):
        def downgrade(inner, keyid, operator, now):
            r = inner(keyid, operator, now)
            return r and dataclasses.replace(r, trusted=False)

        res = self.directory()
        res.resolve = functools.partial(downgrade, res.resolve)
        r = Verifier(res, clock=clock).verify(self.signed())
        self.assertEqual(r.outcome, Outcome.SIGNED_UNTRUSTED)

    def test_unavailable_flag_is_not_consulted_when_resolve_returns_a_key(self):
        class Flagged(StaticKeyResolver):
            def directory_unavailable(self, operator, now):
                return True

        r = Verifier(Flagged({AGENT: self.jwks}), clock=clock).verify(self.signed())
        self.assertEqual(r.outcome, Outcome.VERIFIED)

    def test_unavailable_flag_true_with_no_key_is_unknown_operator_not_hostile(self):
        class Flagged(StaticKeyResolver):
            def directory_unavailable(self, operator, now):
                return True

        r = Verifier(Flagged({AGENT: {"keys": []}}), clock=clock).verify(self.signed())
        self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "key directory unavailable"))
        self.assertFalse(r.hostile)

    def test_truthy_non_bool_unavailable_flag_stays_invalid(self):
        # Only a real True may soften the outcome; a sloppy resolver must fail closed.
        for value in (1, "yes", [1]):
            with self.subTest(value=value):
                class Flagged(StaticKeyResolver):
                    def directory_unavailable(self, operator, now):
                        return value

                r = Verifier(Flagged({AGENT: {"keys": []}}), clock=clock).verify(self.signed())
                self.assertEqual(r.outcome, Outcome.INVALID)

    def test_revoking_resolve_on_cold_cache_is_unknown_operator_not_hostile(self):
        class Revoking(DirectoryKeyResolver):
            def resolve(self, keyid, operator, now):
                return None  # returns before super().resolve(), so the cache is never filled

        res = Revoking([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 300))
        for _ in range(2):  # stays unavailable until something else warms the cache
            r = Verifier(res, clock=clock).verify(self.signed())
            self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "key directory unavailable"))
            self.assertFalse(r.hostile)

    def test_unavailable_flag_false_with_no_key_stays_invalid(self):
        r = Verifier(StaticKeyResolver({AGENT: {"keys": []}}), clock=clock).verify(self.signed())
        self.assertEqual(r.outcome, Outcome.INVALID)


class DirectoryUnavailableFlag(Fixture):
    def make(self, ttl=300):
        self.calls = []
        return DirectoryKeyResolver([AGENT], fetch=lambda url: (
            self.calls.append(url) or json.dumps(self.jwks).encode(), ttl))

    def test_cold_cache_is_unavailable_without_fetching(self):
        res = self.make()
        self.assertTrue(res.directory_unavailable(AGENT, NOW))
        self.assertEqual((self.calls, res._cache, res._last_fetch), ([], {}, {}))

    def test_fresh_cache_is_available_and_expired_cache_is_not(self):
        res = self.make()
        res.resolve("x", AGENT, NOW)
        before = dict(res._cache)
        self.assertFalse(res.directory_unavailable(AGENT, NOW + 299))
        self.assertTrue(res.directory_unavailable(AGENT, NOW + 300))
        self.assertEqual((len(self.calls), res._cache), (1, before))

    def test_not_allowlisted_or_missing_operator_is_never_unavailable(self):
        res = self.make()
        self.assertFalse(res.directory_unavailable("https://stranger.example", NOW))
        self.assertFalse(res.directory_unavailable(None, NOW))

    def test_removed_operator_is_not_unavailable(self):
        res = self.make()
        res.resolve("x", AGENT, NOW)
        res.allowlist.discard(AGENT)
        self.assertFalse(res.directory_unavailable(AGENT, NOW + 300))

    def test_fetch_completing_between_resolve_and_flag_never_trusts(self):
        res = self.make()
        kid = jwk_thumbprint(public_jwk(self.key))
        orig = res.resolve
        res.fetch = lambda url: (_ for _ in ()).throw(TimeoutError("down"))
        got = orig(kid, AGENT, NOW)  # cold and failing: no key
        res.fetch = lambda url: (json.dumps({"keys": []}).encode(), 600)
        res._last_fetch.clear()
        res._refresh(AGENT, NOW, force=False)  # a concurrent fetch lands now
        self.assertIsNone(got)
        self.assertFalse(res.directory_unavailable(AGENT, NOW))  # worst case: INVALID, never a key


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

    def test_removed_operator_with_expired_cache_is_unknown_not_unavailable(self):
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 300))
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT, NOW).trusted)
        res.allowlist.discard(AGENT)
        self.assertFalse(res.directory_unavailable(AGENT, NOW + 300))
        r = Verifier(res, clock=lambda: NOW + 300).verify(self.signed(created=NOW + 299, expires=NOW + 359))
        self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "no key for this operator"))

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


# -01 Appendix E headers, unwrapped per RFC 8792; module-level so later tasks reuse them.
E_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
E_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
E_AGENT = "https://signature-agent.test"
E21_HEADERS = [
    ("Host", "example.com"),
    ("Signature-Agent", 'sig2="https://signature-agent.test"'),
    ("Signature-Input",
     'sig2=("@authority" "signature-agent";key="sig2");created=1735689600;'
     'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;'
     'nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";'
     'tag="web-bot-auth"'),
    ("Signature", "sig2=:CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==:"),
]
E22_HEADERS = [
    ("Host", "example.com"),
    ("Signature-Agent", '"https://signature-agent.test"'),
    ("Signature-Input",
     'sig2=("@authority" "signature-agent");created=1735689600;'
     'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;'
     'nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";'
     'tag="web-bot-auth"'),
    ("Signature", "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:"),
]
E11_HEADERS = [
    ("Host", "example.com"),
    ("Signature-Agent", 'sig2="https://signature-agent.test"'),
    ("Signature-Input",
     'sig2=("@authority" "signature-agent";key="sig2");created=1735689600;'
     'keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;'
     'nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";'
     'tag="web-bot-auth"'),
    ("Signature", "sig2=:iOCC:"),  # value is irrelevant: alg is rejected before any signature check
]
E12_HEADERS = [
    ("Host", "example.com"),
    ("Signature-Agent", '"https://signature-agent.test"'),
    ("Signature-Input",
     'sig2=("@authority" "signature-agent");created=1735689600;'
     'keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=1735693200;'
     'nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";'
     'tag="web-bot-auth"'),
    ("Signature", "sig2=:I1QW:"),
]
E23_BODY = (b'{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",'
            b'"x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}')
E23_DIGEST = "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"


class ConformanceDraft01(unittest.TestCase):
    """draft-ietf-webbotauth-httpsig-protocol-01 Appendix E vectors."""

    def verifier(self):
        return Verifier(StaticKeyResolver({E_AGENT: {"keys": [E_JWK]}}),
                        policy=Policy(max_age=10**10, max_lifetime=None), clock=lambda: 1735689600)

    def check(self, headers):
        return self.verifier().verify(Request("GET", "https://example.com/", headers))

    def test_e21_dictionary_agent_verifies(self):
        r = self.check(E21_HEADERS)
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertEqual(r.operator, E_AGENT)

    def test_e22_legacy_string_verifies(self):
        r = self.check(E22_HEADERS)
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertEqual(r.operator, E_AGENT)

    def test_e1_rsa_vectors_are_unsupported(self):
        for name, headers in (("E.1.1", E11_HEADERS), ("E.1.2", E12_HEADERS)):
            with self.subTest(name):
                r = self.check(headers)
                self.assertEqual(r.outcome, Outcome.INVALID)
                self.assertEqual(r.reason, "unsupported alg 'rsa-pss-sha512'")

    def test_created_beyond_skew_is_future_not_expired(self):
        # Pins the created > now + skew branch of _check_times to its own reason.
        v = Verifier(StaticKeyResolver({E_AGENT: {"keys": [E_JWK]}}),
                     policy=Policy(max_age=10**10, max_lifetime=None, clock_skew=5),
                     clock=lambda: 1735689600 - 6)
        r = v.verify(Request("GET", "https://example.com/", E21_HEADERS))
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "created is in the future"))

    def test_e23_content_digest_matches_body(self):
        self.assertTrue(content_digest_matches(E23_DIGEST, E23_BODY))
        changed = E23_BODY[:-1] + b"~"
        self.assertFalse(content_digest_matches(E23_DIGEST, changed))


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
