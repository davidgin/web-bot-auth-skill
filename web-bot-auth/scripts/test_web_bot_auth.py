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

import web_bot_auth
from web_bot_auth import (
    DirectoryKeyResolver, InMemoryNonceStore, content_digest_matches, NonceStoreError, Outcome, Policy,
    Request, StaticKeyResolver, Verifier, jwk_thumbprint, parse_dictionary, parse_directory,
    normalize_agent_url, public_jwk, sign_request, signature_base, TEST_KEY_THUMBPRINTS,
    WELL_KNOWN_DIRECTORY,
)

NOW = 1_800_000_000
AGENT = "https://agent.example"
NONCE = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2U="
AGENT_ID = AGENT + "/"  # the normalized identifier of AGENT (spec section 3.1)
LONG_PATH = "https://a.example/" + "k" * (2048 - len("https://a.example/"))
# Spec section 3.1 table, written by hand: input -> identifier, or None when rejected.
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

    # SC-005: every directory attack test checks these after each request.
    def assertFetchedSubset(self, fetched, resolver):
        self.assertLessEqual(set(fetched), set(resolver._fetch_urls.values()))

    def assertNotMisattributed(self, result, resolver):
        # T9 adds the ResolvedKey.attributed check; until then membership is the evidence.
        if result.operator is not None:
            static = getattr(resolver, "_keys", None)
            keys = static.get(result.operator, {}) if static is not None \
                else resolver._cache.get(result.operator, ({},))[0]
            self.assertIn(result.keyid, keys, f"{result.keyid} credited to {result.operator}")


class Accepts(Fixture):
    def test_verified_and_bound(self):
        r = self.outcome(self.signed())
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertTrue(r.binds_request)
        self.assertTrue(r.replay_protected)
        self.assertEqual(r.operator, AGENT_ID)

    def test_post_with_body(self):
        r = self.outcome(self.signed("POST", body=b'{"qty": 2}'))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertTrue(r.binds_request)

    def test_dictionary_signature_agent_is_default(self):
        req = self.signed()
        self.assertEqual(req.header("signature-agent"), f'sig1="{AGENT}"')
        r = self.outcome(req)
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
        req = hand_signed(self.key, f'sig1="{AGENT}"', '"@method" "@path" "signature-agent";key="sig1"')
        r = self.assertOutcome(req, Outcome.INVALID)
        self.assertEqual(r.reason, "@authority or @target-uri must be covered")

    def test_signature_agent_swap(self):
        req = self.signed()
        h = [(k, 'sig1="https://evil.example"' if k == "signature-agent" else v) for k, v in req._headers]
        r = self.outcome(Request(req.method, req.url, h))
        self.assertNotEqual(r.outcome, Outcome.VERIFIED)

    def test_uncovered_signature_agent(self):
        req = hand_signed(self.key, f'"{AGENT}"', '"@method" "@authority" "@path"')
        r = self.assertOutcome(req, Outcome.INVALID)
        self.assertEqual(r.reason, "Signature-Agent present but not covered")

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


class AgentUrl(unittest.TestCase):
    """FR-005/FR-007, spec sections 3.1 and 3.2."""

    def test_normalization_table(self):
        for url, expected in NORMALIZATION_CASES:
            with self.subTest(url=url[:60]):
                if expected is None:
                    with self.assertRaises(ValueError):
                        normalize_agent_url(url)
                else:
                    self.assertEqual(normalize_agent_url(url), expected)

    def test_non_string_rejected(self):
        for value in (None, b"https://a.example/", 1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_agent_url(value)

    def test_directory_entry_fetch_urls(self):
        entry = web_bot_auth._directory_entry
        cases = (
            (AGENT, (AGENT_ID, AGENT + WELL_KNOWN_DIRECTORY)),
            (AGENT + "/?v=%7e1", (AGENT_ID, AGENT + WELL_KNOWN_DIRECTORY + "?v=~1")),
            (AGENT + "/a/../k.json?v=%2f", (AGENT + "/k.json", AGENT + "/k.json?v=%2F")),
            ("https://a.example:8443", ("https://a.example:8443/", "https://a.example:8443" + WELL_KNOWN_DIRECTORY)),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(entry(value), expected)


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
            res.resolve("unknown", AGENT_ID, NOW + i)
        self.assertEqual(len(calls), 1)


class DirectoryConfiguration(Fixture):
    """FR-006/FR-007/FR-008, spec sections 3.2 and 3.3 (scenarios 1-3, 13, 14)."""

    def directory(self, allowlist):
        fetched = []
        res = DirectoryKeyResolver(allowlist, fetch=lambda url: (
            fetched.append(url) or json.dumps(self.jwks).encode(), 600))
        return res, Verifier(res, clock=clock), fetched

    def test_configured_directory_path_and_query_override_request(self):
        for suffix in ("/operator/keys.json", "/operator/keys.json?version=2"):
            with self.subTest(suffix=suffix):
                res, verifier, fetched = self.directory([AGENT + suffix])
                result = verifier.verify(self.signed(agent=AGENT + "/operator/keys.json?evil=1"))
                self.assertEqual(result.outcome, Outcome.VERIFIED, result.reason)
                self.assertEqual(result.operator, AGENT + "/operator/keys.json")
                self.assertEqual(res.allowlist, {AGENT + "/operator/keys.json"})
                self.assertEqual(fetched, [AGENT + suffix])

    def test_url_identity_drops_the_query(self):  # scenario 1
        res, verifier, fetched = self.directory([AGENT + "/keys.json"])
        result = verifier.verify(self.signed(agent=AGENT + "/keys.json?v=3"))
        self.assertEqual((result.outcome, result.operator, result.claimed_agent),
                         (Outcome.VERIFIED, AGENT + "/keys.json", AGENT + "/keys.json"), result.reason)
        self.assertEqual(fetched, [AGENT + "/keys.json"])

    def test_another_path_on_the_same_host_is_not_credited(self):  # scenario 2
        for allowlist in ([AGENT + "/keys.json"], [AGENT + "/operator/keys.json?version=2"]):
            with self.subTest(allowlist=allowlist):
                res, verifier, fetched = self.directory(allowlist)
                result = verifier.verify(self.signed(agent=AGENT + "/other.json"))
                self.assertEqual((result.outcome, result.reason, result.operator, result.claimed_agent),
                                 (Outcome.UNKNOWN_OPERATOR, "no key for this operator", None,
                                  AGENT + "/other.json"))
                self.assertEqual(fetched, [])

    def test_bare_origin_fetches_well_known(self):  # scenario 3
        res, verifier, fetched = self.directory([AGENT])
        result = verifier.verify(self.signed(agent=AGENT))
        self.assertEqual((result.outcome, result.operator), (Outcome.VERIFIED, AGENT_ID), result.reason)
        self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_key_of_one_path_does_not_verify_another(self):
        res, verifier, fetched = self.directory([AGENT + "/a/keys.json"])
        result = verifier.verify(self.signed(agent=AGENT + "/b/keys.json"))
        self.assertEqual((result.outcome, result.operator), (Outcome.UNKNOWN_OPERATOR, None))
        self.assertEqual(fetched, [])

    def test_explicit_well_known_is_another_identifier(self):  # scenario 13, a documented deviation
        explicit = AGENT + WELL_KNOWN_DIRECTORY
        res, verifier, fetched = self.directory([AGENT])
        result = verifier.verify(self.signed(agent=explicit))
        self.assertEqual((result.outcome, result.operator), (Outcome.UNKNOWN_OPERATOR, None))
        self.assertEqual(fetched, [])
        res, verifier, fetched = self.directory([AGENT, explicit])
        for agent, operator in ((AGENT, AGENT_ID), (explicit, explicit)):
            result = verifier.verify(self.signed(agent=agent))
            self.assertEqual((result.outcome, result.operator), (Outcome.VERIFIED, operator), result.reason)
        self.assertEqual(fetched, [explicit, explicit])  # two identifiers, two caches (accepted)

    def test_spellings_collapse_but_paths_stay_distinct(self):
        res, verifier, fetched = self.directory([AGENT + "/k"])
        for agent in (AGENT + "/a/../k", AGENT + "/%6B", AGENT + "/k"):
            with self.subTest(agent=agent):
                result = verifier.verify(self.signed(agent=agent))
                self.assertEqual((result.outcome, result.operator), (Outcome.VERIFIED, AGENT + "/k"))
        for agent in (AGENT + "/K", AGENT + "/k/"):
            with self.subTest(agent=agent):
                self.assertEqual(verifier.verify(self.signed(agent=agent)).outcome, Outcome.UNKNOWN_OPERATOR)
        self.assertEqual(fetched, [AGENT + "/k"])

    def test_unsignable_claims_are_invalid_without_fetch(self):
        res, verifier, fetched = self.directory([AGENT + "/k"])
        for agent in (AGENT + "/a\\k", AGENT + "/k?[", AGENT + "/k#f", AGENT + "/" + "k" * 2048):
            with self.subTest(agent=agent[:40]):
                header = "sig1=" + web_bot_auth.serialize_bare_item(agent)
                req = hand_signed(self.key, header, '"@authority" "signature-agent";key="sig1"')
                result = verifier.verify(req)
                self.assertEqual((result.outcome, result.operator, result.claimed_agent),
                                 (Outcome.INVALID, None, None))
        self.assertEqual(fetched, [])

    def test_origin_entries_use_normalized_well_known_location(self):
        for entry in (AGENT, AGENT + "/", "https://AGENT.example:443"):
            with self.subTest(entry=entry):
                res, verifier, fetched = self.directory([entry])
                result = verifier.verify(self.signed())
                self.assertEqual((result.outcome, result.operator), (Outcome.VERIFIED, AGENT_ID))
                self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_configured_root_query_uses_well_known_path(self):
        res, verifier, fetched = self.directory([AGENT + "/?version=2"])
        self.assertEqual(verifier.verify(self.signed()).outcome, Outcome.VERIFIED)
        self.assertEqual(res.allowlist, {AGENT_ID})
        self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY + "?version=2"])

    def test_paths_on_one_host_are_separate_identifiers(self):
        a, b = AGENT + "/a/keys.json", AGENT + "/b/keys.json"
        res, verifier, fetched = self.directory([a, b])
        self.assertEqual(res.allowlist, {a, b})
        for agent in (a, b, a):
            self.assertEqual(verifier.verify(self.signed(agent=agent)).operator, agent)
        self.assertEqual(fetched, [a, b])

    def test_conflicting_queries_for_one_identifier_rejected_in_any_order(self):
        entries = [AGENT + "/k?v=1", AGENT + "/k?v=2"]
        for allowlist in (entries, entries[::-1]):
            with self.subTest(allowlist=allowlist):
                with self.assertRaisesRegex(ValueError, "https://agent[.]example/k"):
                    DirectoryKeyResolver(allowlist)

    def test_identical_normalized_directories_are_allowed(self):
        entries = ["https://AGENT.example", AGENT]
        for allowlist in (entries, entries[::-1]):
            with self.subTest(allowlist=allowlist):
                res, verifier, fetched = self.directory(allowlist)
                self.assertEqual(verifier.verify(self.signed()).outcome, Outcome.VERIFIED)
                self.assertEqual(res.allowlist, {AGENT_ID})
                self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_runtime_added_normalized_origin_uses_well_known_directory(self):  # scenario 14
        res, verifier, fetched = self.directory([])
        request = self.signed()
        self.assertEqual(verifier.verify(request).outcome, Outcome.UNKNOWN_OPERATOR)
        for bad in (lambda: res.allowlist.add(AGENT), lambda: res.allowlist.update([AGENT])):
            with self.assertRaisesRegex(ValueError, "'https://agent[.]example/'"):
                bad()
        with self.assertRaisesRegex(ValueError, "'https://agent[.]example/'"):
            res.allowlist |= {AGENT}
        self.assertEqual((res.allowlist, fetched), (set(), []))
        res.allowlist.add(AGENT_ID)
        self.assertEqual(verifier.verify(request).outcome, Outcome.VERIFIED)
        self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY])
        res.allowlist.discard(AGENT_ID)
        self.assertEqual(verifier.verify(request).outcome, Outcome.SIGNED_UNTRUSTED)
        res.allowlist |= {AGENT_ID}
        res.allowlist.update([AGENT + "/k"])
        self.assertEqual(res.allowlist, {AGENT_ID, AGENT + "/k"})

    def test_invalid_directory_configuration_rejected(self):
        for entry in ("", "agent.example", "http://agent.example/keys", "https:///keys",
                      AGENT + "/keys#fragment", "https://user@agent.example/keys",
                      "https://agent.example:bad/keys", AGENT + "/a\\k", None):
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

    def outcome(self, req, verifier=None):
        result = super().outcome(req, verifier)
        self.assertFetchedSubset(self.fetched, self.resolver)
        self.assertNotMisattributed(result, self.resolver)
        return result

    def test_sc005_helpers_are_not_vacuous(self):
        self.warm()
        kid = jwk_thumbprint(public_jwk(self.attacker))
        forged = web_bot_auth.Result(Outcome.VERIFIED, operator=AGENT_ID, keyid=kid)
        with self.assertRaises(AssertionError):
            self.assertNotMisattributed(forged, self.resolver)
        static = StaticKeyResolver({AGENT: self.jwks})
        with self.assertRaises(AssertionError):
            self.assertNotMisattributed(forged, static)
        self.assertNotMisattributed(dataclasses.replace(forged, keyid=jwk_thumbprint(public_jwk(self.key))),
                                    static)
        with self.assertRaises(AssertionError):
            self.assertFetchedSubset([self.evil_url], self.resolver)

    def test_forged_request_cannot_choose_directory(self):
        self.warm()
        result = self.outcome(self.attack(forged=True))
        self.assertEqual((result.outcome, result.operator, result.claimed_agent),
                         (Outcome.UNKNOWN_OPERATOR, None, self.evil_url))
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY])
        result = self.outcome(self.attack(AGENT, forged=True))
        self.assertEqual((result.outcome, result.operator, result.claimed_agent),
                         (Outcome.INVALID, None, AGENT_ID))
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY] * 2)

    def test_attacker_path_cannot_impersonate_warm_operator(self):
        self.warm()
        result = self.outcome(self.attack())
        self.assertEqual((result.outcome, result.reason, result.operator),
                         (Outcome.UNKNOWN_OPERATOR, "no key for this operator", None))
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_attacker_path_cannot_impersonate_cold_operator(self):
        legacy = hand_signed(self.attacker, f'"{self.evil_url}"', '"@authority" "signature-agent"',
                             url="https://shop.example/x", created=self.now - 1)
        for name, req in (("legacy", legacy), ("dictionary", self.attack())):
            with self.subTest(name):
                self.resolver = DirectoryKeyResolver([AGENT], fetch=self.fetch)
                self.verifier = Verifier(self.resolver, clock=lambda: self.now)
                result = self.outcome(req)
                self.assertEqual((result.outcome, result.reason, result.operator),
                                 (Outcome.UNKNOWN_OPERATOR, "no key for this operator", None))
        self.assertEqual(self.fetched, [])

    def test_poison_attempt_does_not_lock_out_operator(self):
        self.warm()
        self.outcome(self.attack(forged=True))
        self.assertEqual(self.outcome(self.signed()).outcome, Outcome.VERIFIED)

    def test_request_paths_and_queries_do_not_change_configured_location(self):
        # A path claim is another identifier (-01 section 5.5); a query is not part of it.
        for agent, expected in ((self.evil_url + "?key=evil", Outcome.UNKNOWN_OPERATOR),
                                (AGENT + "/?evil=1", Outcome.VERIFIED)):
            with self.subTest(agent=agent):
                self.resolver = DirectoryKeyResolver([AGENT], fetch=self.fetch)
                self.verifier = Verifier(self.resolver, clock=lambda: self.now)
                self.assertEqual(self.outcome(self.signed(agent=agent)).outcome, expected)
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY])

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
        cases = [(h, Request(req.method, req.url, [(k, h if k == "signature-agent" else v)
                                                   for k, v in req._headers]))
                 for h in ('sig1="http://agent.example"', 'sig1="not a URL"',
                           'sig1="https://agent.example:bad"')]
        cases += [(h, hand_signed(self.attacker, h, '"@authority" "signature-agent"',
                                  url="https://shop.example/x", created=self.now - 1))
                  for h in ('""', '" "', 'sig1="unterminated', 'sig1=?1')]
        before = {k: dict(v) for k, v in vars(self.resolver).items() if isinstance(v, dict)}
        for header, bad in cases:
            with self.subTest(header=header):
                self.assertEqual(self.outcome(bad).outcome, Outcome.INVALID)
                self.assertEqual(self.fetched, [])
                self.assertEqual({k: dict(v) for k, v in vars(self.resolver).items()
                                  if isinstance(v, dict)}, before)

    def test_missing_agent_with_empty_allowlist_does_not_fetch(self):
        self.resolver = DirectoryKeyResolver([], fetch=self.fetch)
        self.verifier = Verifier(self.resolver, clock=clock)
        req = hand_signed(self.key, None, '"@method" "@authority" "@path"')
        self.assertEqual(self.outcome(req).outcome, Outcome.UNKNOWN_OPERATOR)
        self.assertEqual(self.fetched, [])
        self.assertEqual(self.resolver._cache, {})
        self.assertEqual(self.resolver._last_fetch, {})

    def test_bad_signature_spam_is_bounded_for_allowlisted_origin(self):
        kid = jwk_thumbprint(public_jwk(self.key))
        for i in range(100):
            result = self.outcome(self.attack(self.evil_url + f"?key={i}", forged=True, keyid=kid))
            self.assertEqual((result.outcome, result.reason),
                             (Outcome.UNKNOWN_OPERATOR, "no key for this operator"))
            result = self.outcome(self.attack(AGENT + f"/?key={i}", forged=True, keyid=kid))
            self.assertEqual((result.outcome, result.reason), (Outcome.INVALID, "signature does not verify"))
        self.assertEqual(self.fetched, [AGENT + WELL_KNOWN_DIRECTORY])
        self.assertEqual(set(self.resolver._cache), {AGENT_ID})
        self.assertEqual(set(self.resolver._last_fetch), {AGENT_ID})
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
                    self.assertIsNone(res.resolve(kid, AGENT_ID, NOW + offset))
                self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])
                self.assertTrue(res.resolve(kid, AGENT_ID, NOW + 60).trusted)
                self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY] * 2)

    def test_failed_fetch_limit_is_per_operator(self):
        calls = []

        def fetch(url):
            calls.append(url)
            raise TimeoutError("offline")

        other = "https://other.example"
        res = DirectoryKeyResolver([AGENT, other], fetch=fetch)
        for operator in (AGENT_ID, other + "/", AGENT_ID, other + "/"):
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

    def test_identifiers_on_one_host_reserve_their_own_attempt(self):
        a, b = AGENT + "/a", AGENT + "/b"
        calls, lock, started, release = [], threading.Lock(), threading.Semaphore(0), threading.Event()

        def fetch(url):
            with lock:
                calls.append(url)
            started.release()
            if not release.wait(5):
                raise TimeoutError("test did not release fetch")
            if url == a:
                raise TimeoutError("directory timeout")
            return json.dumps(self.jwks).encode(), 600

        res = DirectoryKeyResolver([a, b], fetch=fetch)
        kid = jwk_thumbprint(public_jwk(self.key))
        barrier = threading.Barrier(16)

        def cold(identifier):
            barrier.wait(5)
            return res.resolve(kid, identifier, NOW)

        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(cold, i) for i in (a, b) * 8]
            try:
                self.assertTrue(started.acquire(timeout=2) and started.acquire(timeout=2))
            finally:
                release.set()
            for f in futures:
                f.result(timeout=5)
        self.assertEqual(sorted(calls), [a, b])  # one attempt each, not one per host
        self.assertTrue(res.resolve(kid, b, NOW + 1).trusted)  # a's failure did not limit b
        self.assertIsNone(res.resolve(kid, a, NOW + 1))
        self.assertEqual(len(calls), 2)

    def test_warm_cache_survives_failed_rotation_and_limits_unknown_keyids(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if len(calls) > 1:
                raise TimeoutError("offline")
            return json.dumps(self.jwks).encode(), 300

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW).trusted)
        for i in range(20):
            self.assertIsNone(res.resolve(f"unknown-{i}", AGENT_ID, NOW + 61))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW + 301).trusted)
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY] * 3)

    # -01 section 6.10: only a 200 that is a JWKS is evidence about the keys.
    NON_JWKS = (b'{}', b'{"keys": {}}', b'{"error": "x"}', b'[]', b'"x"', b'null',
                b'{"keys": null}', b'{"keys": "x"}')

    def _warm_then_refresh_with(self, refreshed):
        calls = []

        def fetch(url):
            calls.append(url)
            if len(calls) == 1:
                return json.dumps(self.jwks).encode(), 300
            if isinstance(refreshed, Exception):
                raise refreshed
            return refreshed, 300

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW).trusted)
        return res, kid, calls

    def test_non_jwks_refresh_keeps_cached_keys(self):
        for body in self.NON_JWKS:
            with self.subTest(body=body):
                res, kid, calls = self._warm_then_refresh_with(body)
                found = res.resolve(kid, AGENT_ID, NOW + 301)
                self.assertEqual(len(calls), 2)  # the refresh really happened
                self.assertIsNotNone(found)
                self.assertTrue(found.trusted)

    def test_fetch_error_while_warm_keeps_cached_keys(self):
        res, kid, calls = self._warm_then_refresh_with(TimeoutError("offline"))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW + 301).trusted)
        self.assertEqual(len(calls), 2)

    def test_add_untrusted_directory_rejects_non_jwks_and_keeps_previous_entry(self):
        res = DirectoryKeyResolver([])
        res.add_untrusted_directory(AGENT, self.jwks, ttl=60, now=NOW)
        kid = jwk_thumbprint(public_jwk(self.key))
        for body in self.NON_JWKS:
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    res.add_untrusted_directory(AGENT, body, ttl=60, now=NOW + 1)
                self.assertIsNotNone(res.resolve(kid, AGENT_ID, NOW + 2))

    def test_non_jwks_refresh_still_counts_as_an_attempt(self):
        res, kid, calls = self._warm_then_refresh_with(b'{"error": "x"}')
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW + 301).trusted)  # refresh fails, copy kept
        self.assertEqual(len(calls), 2)
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW + 302).trusted)
        self.assertIsNone(res.resolve("unknown", AGENT_ID, NOW + 303))
        self.assertEqual(len(calls), 2)  # inside refetch_interval: no extra fetch

    def test_valid_directory_without_key_evicts(self):
        res, kid, calls = self._warm_then_refresh_with(b'{"keys": []}')
        self.assertIsNone(res.resolve(kid, AGENT_ID, NOW + 301))
        self.assertEqual(len(calls), 2)

    def test_parse_directory_rejects_non_jwks(self):
        for body in self.NON_JWKS + (b"not json",):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    parse_directory(body)
        self.assertEqual(parse_directory(b'{"keys": []}'), {})

    def test_static_resolver_rejects_non_jwks(self):
        with self.assertRaises(ValueError):
            StaticKeyResolver({AGENT: {}})


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
        self.assertEqual((result.operator, result.claimed_agent), (None, AGENT_ID))

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
        res.resolve("warm-the-cache", AGENT_ID, NOW)  # a cold cache would read as unavailable
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
        res.resolve("warm-the-cache", AGENT_ID, NOW)
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
        self.assertTrue(res.directory_unavailable(AGENT_ID, NOW))
        self.assertEqual((self.calls, res._cache, res._last_fetch), ([], {}, {}))

    def test_fresh_cache_is_available_and_expired_cache_is_not(self):
        res = self.make()
        res.resolve("x", AGENT_ID, NOW)
        before = dict(res._cache)
        self.assertFalse(res.directory_unavailable(AGENT_ID, NOW + 299))
        self.assertTrue(res.directory_unavailable(AGENT_ID, NOW + 300))
        self.assertEqual((len(self.calls), res._cache), (1, before))

    def test_not_allowlisted_or_missing_operator_is_never_unavailable(self):
        res = self.make()
        self.assertFalse(res.directory_unavailable("https://stranger.example", NOW))
        self.assertFalse(res.directory_unavailable(None, NOW))

    def test_removed_operator_is_not_unavailable(self):
        res = self.make()
        res.resolve("x", AGENT_ID, NOW)
        res.allowlist.discard(AGENT_ID)
        self.assertFalse(res.directory_unavailable(AGENT_ID, NOW + 300))

    def test_fetch_completing_between_resolve_and_flag_never_trusts(self):
        res = self.make()
        kid = jwk_thumbprint(public_jwk(self.key))
        orig = res.resolve
        res.fetch = lambda url: (_ for _ in ()).throw(TimeoutError("down"))
        got = orig(kid, AGENT_ID, NOW)  # cold and failing: no key
        res.fetch = lambda url: (json.dumps({"keys": []}).encode(), 600)
        res._last_fetch.clear()
        res._refresh(AGENT_ID, NOW, force=False)  # a concurrent fetch lands now
        self.assertIsNone(got)
        self.assertFalse(res.directory_unavailable(AGENT_ID, NOW))  # worst case: INVALID, never a key


class DirectoryTrust(Fixture):
    def test_removed_operator_cached_key_is_untrusted(self):
        calls = []
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (
            calls.append(url) or json.dumps(self.jwks).encode(), 600))
        verifier = Verifier(res, clock=clock)
        request = self.signed()
        self.assertEqual(verifier.verify(request).outcome, Outcome.VERIFIED)
        res.allowlist.discard(AGENT_ID)
        self.assertFalse(res.is_allowlisted(AGENT_ID))
        self.assertEqual(verifier.verify(request).outcome, Outcome.SIGNED_UNTRUSTED)
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])
        res.allowlist.add(AGENT_ID)
        self.assertEqual(verifier.verify(request).outcome, Outcome.VERIFIED)
        self.assertEqual(calls, [AGENT + WELL_KNOWN_DIRECTORY])

    def test_removed_operator_expired_cache_cannot_be_used(self):
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 300))
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW).trusted)
        res.allowlist.clear()
        self.assertFalse(res.resolve(kid, AGENT_ID, NOW + 299.999).trusted)
        self.assertIsNone(res.resolve(kid, AGENT_ID, NOW + 300))

    def test_operator_removed_during_fetch_is_not_trusted(self):
        def fetch(url):
            res.allowlist.discard(AGENT_ID)
            return json.dumps(self.jwks).encode(), 600

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        result = Verifier(res, clock=clock).verify(self.signed())
        self.assertEqual(result.outcome, Outcome.SIGNED_UNTRUSTED)

    def test_removed_operator_with_expired_cache_is_unknown_not_unavailable(self):
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (json.dumps(self.jwks).encode(), 300))
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW).trusted)
        res.allowlist.discard(AGENT_ID)
        self.assertFalse(res.directory_unavailable(AGENT_ID, NOW + 300))
        r = Verifier(res, clock=lambda: NOW + 300).verify(self.signed(created=NOW + 299, expires=NOW + 359))
        self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "no key for this operator"))

    def test_background_directory_stays_untrusted_and_expires(self):
        res = DirectoryKeyResolver([])
        res.add_untrusted_directory(AGENT, self.jwks, ttl=60, now=NOW)
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertFalse(res.resolve(kid, AGENT_ID, NOW).trusted)
        self.assertIsNone(res.resolve("unknown", AGENT_ID, NOW))
        self.assertIsNone(res.resolve(kid, AGENT_ID, NOW + 60))


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
        return Verifier(StaticKeyResolver({E_AGENT: {"keys": [E_JWK]}}, allow_test_keys=True),
                        policy=Policy(max_age=10**10, max_lifetime=None), clock=lambda: 1735689600)

    def check(self, headers):
        return self.verifier().verify(Request("GET", "https://example.com/", headers))

    def test_e21_dictionary_agent_verifies(self):
        r = self.check(E21_HEADERS)
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertEqual(r.operator, E_AGENT + "/")

    def test_e22_legacy_string_verifies(self):
        r = self.check(E22_HEADERS)
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)
        self.assertEqual(r.operator, E_AGENT + "/")

    def test_e1_rsa_vectors_are_unsupported(self):
        for name, headers in (("E.1.1", E11_HEADERS), ("E.1.2", E12_HEADERS)):
            with self.subTest(name):
                r = self.check(headers)
                self.assertEqual(r.outcome, Outcome.INVALID)
                self.assertEqual(r.reason, "unsupported alg 'rsa-pss-sha512'")

    def test_created_beyond_skew_is_future_not_expired(self):
        # Pins the created > now + skew branch of _check_times to its own reason.
        v = Verifier(StaticKeyResolver({E_AGENT: {"keys": [E_JWK]}}, allow_test_keys=True),
                     policy=Policy(max_age=10**10, max_lifetime=None, clock_skew=5),
                     clock=lambda: 1735689600 - 6)
        r = v.verify(Request("GET", "https://example.com/", E21_HEADERS))
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "created is in the future"))

    def test_e23_content_digest_matches_body(self):
        self.assertTrue(content_digest_matches(E23_DIGEST, E23_BODY))
        changed = E23_BODY[:-1] + b"~"
        self.assertFalse(content_digest_matches(E23_DIGEST, changed))

    def test_e21_rejected_by_default(self):
        # SC-001, second half: the draft's own key is a published test key.
        res = DirectoryKeyResolver([E_AGENT], fetch=lambda url: (json.dumps({"keys": [E_JWK]}).encode(), 600))
        v = Verifier(res, policy=Policy(max_age=10**10, max_lifetime=None), clock=lambda: 1735689600)
        r = v.verify(Request("GET", "https://example.com/", E21_HEADERS))
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "known test key rejected"))


def _jwk_of(x):
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


# Published private keys: RFC 9421 B.1.4 (the PEM in Conformance) and RFC 8037 A.1 (its "d").
B14_KEY = load_pem_private_key(Conformance.PEM, None)
A1_KEY = Ed25519PrivateKey.from_private_bytes(
    base64.urlsafe_b64decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="))
# (source, x, thumbprint) as in spec section 3.6; the thumbprints are recomputed by a test.
TEST_KEYS = (
    ("RFC 9421 B.1.4", "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
     "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"),
    ("RFC 8037 A.1", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
     "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"),
    ("vectors KEY", "SJUTQy84WjB_Cq9wkBIZ0TZmXQr7oG4Qo2SykDItiN0",
     "CaJn8r1wQ6jaeqa0H9w0Xw4n2xguAKi6vziTdPQqqFs"),
    ("vectors OTHER", "hXOBU2vlJ6UWSGIhxRtqMaa7n_9fhKVTJJtvupLHlNc",
     "UBQJjBYkCFLaFgwMbZIQWpA2VRag2Y4CVF51WNWQS-s"),
)


def _distinct_jwks(n):
    out = []
    for i in range(n):
        seed = i.to_bytes(32, "big")
        out.append(public_jwk(Ed25519PrivateKey.from_private_bytes(seed)))
    return out


class KeyLimit(Fixture):
    def test_directory_with_too_many_keys_is_a_discovery_failure(self):
        with self.assertRaises(ValueError):
            parse_directory({"keys": _distinct_jwks(65)})
        self.assertEqual(len(parse_directory({"keys": _distinct_jwks(64)})), 64)

    def test_limit_boundaries(self):
        self.assertEqual(parse_directory({"keys": []}), {})
        self.assertEqual(len(parse_directory({"keys": _distinct_jwks(2)}, max_keys=2)), 2)
        with self.assertRaises(ValueError):
            parse_directory({"keys": _distinct_jwks(3)}, max_keys=2)

    def test_entries_that_would_be_skipped_count_toward_the_limit(self):
        junk = [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}, "not an object", {"kty": "OKP", "crv": "Ed25519"}]
        with self.assertRaises(ValueError):
            parse_directory({"keys": _distinct_jwks(62) + junk}, max_keys=64)
        self.assertEqual(len(parse_directory({"keys": _distinct_jwks(61) + junk}, max_keys=64)), 61)
        with self.assertRaises(ValueError):  # counted before the test-key filter too
            parse_directory({"keys": [_jwk_of(TEST_KEYS[0][1])] * 3}, max_keys=2)

    def test_oversized_refresh_keeps_the_warm_cache(self):
        calls = []

        def fetch(url):
            calls.append(url)
            # The oversized body omits our key: accepting it would evict the warm copy.
            keys = [public_jwk(self.key)] if len(calls) == 1 else _distinct_jwks(65)
            return json.dumps({"keys": keys}).encode(), 300

        res = DirectoryKeyResolver([AGENT], fetch=fetch)
        kid = jwk_thumbprint(public_jwk(self.key))
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW).trusted)
        self.assertTrue(res.resolve(kid, AGENT_ID, NOW + 301).trusted)
        self.assertEqual(len(calls), 2)  # the oversized refresh really happened

    def test_resolver_max_keys_is_passed_through(self):
        body = json.dumps({"keys": _distinct_jwks(3)}).encode()
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (body, 300), max_keys=2)
        kid = jwk_thumbprint(_distinct_jwks(3)[0])
        self.assertIsNone(res.resolve(kid, AGENT_ID, NOW))
        with self.assertRaises(ValueError):
            res.add_untrusted_directory("https://other.example", {"keys": _distinct_jwks(3)}, now=NOW)
        res = DirectoryKeyResolver([AGENT], fetch=lambda url: (body, 300), max_keys=3)
        self.assertIsNotNone(res.resolve(kid, AGENT_ID, NOW))


class TestKeyDenylist(Fixture):
    def sign_with(self, key):
        return sign_request(
            Request("GET", "https://shop.example/items/42", [("host", "shop.example")]), key,
            components=("@method", "@authority", "@path", "signature-agent"),
            created=NOW - 1, expires=NOW + 59, nonce=NONCE, agent=AGENT)

    def directory_verifier(self, key, **kw):
        body = json.dumps({"keys": [public_jwk(key)]}).encode()
        return Verifier(DirectoryKeyResolver([AGENT], fetch=lambda url: (body, 600), **kw),
                        clock=clock)

    def test_test_key_thumbprints_are_the_four_known_keys(self):
        import generate_vectors
        self.assertEqual(TEST_KEY_THUMBPRINTS, frozenset(t for _, _, t in TEST_KEYS))
        for source, x, thumb in TEST_KEYS:
            with self.subTest(source):
                self.assertEqual(jwk_thumbprint(_jwk_of(x)), thumb)
        self.assertEqual(public_jwk(B14_KEY)["x"], TEST_KEYS[0][1])
        self.assertEqual(public_jwk(A1_KEY)["x"], TEST_KEYS[1][1])
        self.assertEqual(jwk_thumbprint(public_jwk(generate_vectors.KEY)), TEST_KEYS[2][2])
        self.assertEqual(jwk_thumbprint(public_jwk(generate_vectors.OTHER)), TEST_KEYS[3][2])

    def test_rfc9421_test_key_dropped_from_directory(self):
        for name, key in (("B.1.4", B14_KEY), ("8037 A.1", A1_KEY)):
            with self.subTest(name):
                r = self.directory_verifier(key).verify(self.sign_with(key))
                self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "known test key rejected"))
                r = self.directory_verifier(key, allow_test_keys=True).verify(self.sign_with(key))
                self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)

    def test_parse_directory_skips_test_keys_unless_allowed(self):
        doc = {"keys": [_jwk_of(x) for _, x, _ in TEST_KEYS] + [public_jwk(self.key)]}
        self.assertEqual(set(parse_directory(doc)), {jwk_thumbprint(public_jwk(self.key))})
        self.assertEqual(set(parse_directory(doc, allow_test_keys=True)),
                         {t for _, _, t in TEST_KEYS} | {jwk_thumbprint(public_jwk(self.key))})

    def test_test_key_rejected_in_static_config(self):
        for source, x, thumb in TEST_KEYS:
            with self.subTest(source):
                with self.assertRaisesRegex(ValueError, thumb):
                    StaticKeyResolver({AGENT: {"keys": [_jwk_of(x)]}})
                with self.assertRaisesRegex(ValueError, thumb):
                    StaticKeyResolver({AGENT: [_jwk_of(x)]})
                res = StaticKeyResolver({AGENT: {"keys": [_jwk_of(x)]}}, allow_test_keys=True)
                self.assertIsNotNone(res.resolve(thumb, AGENT_ID, NOW))

    def test_add_untrusted_directory_drops_test_keys(self):
        jwks = {"keys": [public_jwk(B14_KEY)]}
        res = DirectoryKeyResolver([])
        res.add_untrusted_directory(AGENT, jwks, now=NOW)
        r = Verifier(res, clock=clock).verify(self.sign_with(B14_KEY))
        # Not allowlisted, so the reason is the resolver's no-key outcome; never an accept.
        self.assertEqual((r.outcome, r.reason), (Outcome.UNKNOWN_OPERATOR, "no key for this operator"))
        res = DirectoryKeyResolver([], allow_test_keys=True)
        res.add_untrusted_directory(AGENT, jwks, now=NOW)
        r = Verifier(res, clock=clock).verify(self.sign_with(B14_KEY))
        self.assertEqual(r.outcome, Outcome.SIGNED_UNTRUSTED, r.reason)

    def test_ordinary_unknown_keyid_keeps_its_reason(self):
        r = self.directory_verifier(self.key).verify(self.sign_with(Ed25519PrivateKey.generate()))
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "unknown keyid for allowlisted operator"))


class Vectors(unittest.TestCase):
    def test_vectors_file_is_current(self):
        import json, os
        import generate_vectors
        path = os.path.join(os.path.dirname(__file__), "..", "assets", "test-vectors.json")
        with open(path) as f:
            self.assertEqual(json.load(f), generate_vectors.build(),
                             "regenerate: python generate_vectors.py > ../assets/test-vectors.json")

    def test_vectors_say_ports_must_allow_test_keys(self):
        import generate_vectors
        self.assertIn("allow_test_keys", generate_vectors.build()["description"])

def hand_signed(key, agent_header, components, label="sig1", url="https://shop.example/items/42",
                created=NOW - 1):
    """Sign headers and components exactly as given, through the private _sign (FR-013)."""
    headers = [("host", "shop.example")]
    if agent_header is not None:
        headers.append(("signature-agent", agent_header))
    covered = parse_dictionary(
        f'{label}=({components});created={created};expires={created + 60};'
        f'keyid="{jwk_thumbprint(public_jwk(key))}";alg="ed25519";nonce="{NONCE}";'
        f'tag="web-bot-auth"')[label]
    return web_bot_auth._sign(Request("GET", url, headers), key, covered, label)


class Signer(Fixture):
    """FR-013, spec section 3.8."""

    def test_e22_legacy_bytes_from_sign_core(self):
        headers = E22_HEADERS[:2]
        covered = parse_dictionary(E22_HEADERS[2][1])["sig2"]
        out = web_bot_auth._sign(Request("GET", "https://example.com/", headers), B14_KEY,
                                 covered, "sig2")
        self.assertEqual(out.header("signature"), E22_HEADERS[3][1])
        self.assertEqual(out.header("signature-input"), E22_HEADERS[2][1])
        self.assertEqual(out.header("signature-agent"), '"https://signature-agent.test"')

    def test_agent_is_required(self):
        with self.assertRaises(TypeError):
            sign_request(Request("GET", "https://shop.example/", []), self.key)

    def test_rejects_non_https_agent(self):
        for agent in ("http://agent.example", None, AGENT + "/#f"):
            with self.subTest(agent=agent):
                with self.assertRaises(ValueError):
                    self.signed(agent=agent)

    def test_components_must_cover_signature_agent(self):
        with self.assertRaises(ValueError):
            self.signed(components=("@method", "@authority", "@path"))

    def test_components_must_cover_authority_or_target_uri(self):
        with self.assertRaises(ValueError):
            self.signed(components=("@method", "@path", "signature-agent"))

    def test_target_uri_alone_is_enough(self):
        r = self.outcome(self.signed(components=("@target-uri", "signature-agent")))
        self.assertEqual(r.outcome, Outcome.VERIFIED, r.reason)

    def test_default_sends_dictionary_keyed_by_label(self):
        req = self.signed()
        self.assertEqual(req.header("signature-agent"), f'sig1="{AGENT}"')
        self.assertIn('"signature-agent";key="sig1"', req.header("signature-input"))

    def test_custom_label_keys_member_and_component(self):
        req = self.signed(label="agent")
        self.assertEqual(req.header("signature-agent"), f'agent="{AGENT}"')
        self.assertTrue(req.header("signature-input").startswith("agent=("))
        self.assertIn('"signature-agent";key="agent"', req.header("signature-input"))
        r = self.outcome(req)
        self.assertEqual((r.outcome, r.label, r.operator), (Outcome.VERIFIED, "agent", AGENT_ID), r.reason)

class MemberSelection(Fixture):
    """FR-003/FR-004, spec section 3.4."""
    BROWSER = "https://browser.example"

    def verify(self, req, keys):
        return Verifier(StaticKeyResolver(keys), clock=clock).verify(req)

    def test_each_label_resolves_its_own_member(self):
        keys = {AGENT: self.jwks, self.BROWSER: self.jwks}
        members = (f'browser="{self.BROWSER}"', f'agent="{AGENT}"')
        comps = ('"signature-agent";key="browser"', '"signature-agent";key="agent"')
        for header in (", ".join(members), ", ".join(reversed(members))):
            for order in (comps, tuple(reversed(comps))):
                for label, expected in (("browser", self.BROWSER + "/"), ("agent", AGENT_ID)):
                    with self.subTest(header=header, order=order, label=label):
                        req = hand_signed(self.key, header, '"@authority" ' + " ".join(order), label)
                        r = self.verify(req, keys)
                        self.assertEqual((r.outcome, r.operator), (Outcome.VERIFIED, expected), r.reason)

    def test_bare_component_selects_label_member(self):
        req = hand_signed(self.key, f'other="https://other.example", sig1="{AGENT}"',
                          '"@authority" "signature-agent"')
        r = self.verify(req, {AGENT: self.jwks})
        self.assertEqual((r.outcome, r.operator), (Outcome.VERIFIED, AGENT_ID), r.reason)

    def test_bare_component_over_dictionary_without_label_member_is_invalid(self):
        req = hand_signed(self.key, f'agent="{AGENT}"', '"@authority" "signature-agent"')
        r = self.verify(req, {AGENT: self.jwks})
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "cannot determine Signature-Agent value"))

    def test_legacy_string_still_verifies(self):
        req = hand_signed(self.key, f'"{AGENT}"', '"@authority" "signature-agent"')
        r = self.verify(req, {AGENT: self.jwks})
        self.assertEqual((r.outcome, r.operator), (Outcome.VERIFIED, AGENT_ID), r.reason)

    def assert_no_url_path(self, req):
        r = self.verify(req, {AGENT: self.jwks})
        self.assertEqual((r.outcome, r.reason, r.operator, r.claimed_agent),
                         (Outcome.UNKNOWN_OPERATOR, "no key for this operator", None, None))
        r = self.verify(req, {None: self.jwks})
        self.assertEqual((r.outcome, r.operator, r.claimed_agent), (Outcome.VERIFIED, None, None), r.reason)

    def test_member_keyed_to_another_label_is_ignored(self):
        # Spec scenario 7: not INVALID and not attributed to member agent2.
        self.assert_no_url_path(hand_signed(self.key, f'agent2="{AGENT}"',
                                            '"@authority" "signature-agent";key="agent2"', "sig2"))

    def test_relabeled_signature_is_ignored_not_invalid(self):
        req = hand_signed(self.key, f'agent2="{AGENT}"',
                          '"@authority" "signature-agent";key="agent2"', "agent2")
        self.assertEqual(self.verify(req, {AGENT: self.jwks}).outcome, Outcome.VERIFIED)
        relabel = {"signature": lambda v: v.replace("agent2=", "sig2=", 1),
                   "signature-input": lambda v: v.replace("agent2=", "sig2=", 1)}
        headers = [(k, relabel[k](v) if k in relabel else v) for k, v in req._headers]
        self.assert_no_url_path(Request(req.method, req.url, headers))

    def test_member_with_parameters_is_ignored(self):
        for header, comp in ((f'sig1="{AGENT}";x=1', '"signature-agent";key="sig1"'),
                             (f'"{AGENT}";x=1', '"signature-agent"')):
            with self.subTest(header=header):
                self.assert_no_url_path(hand_signed(self.key, header, '"@authority" ' + comp))

    def test_bare_component_over_token_with_parameters_is_invalid(self):
        # Spec section 3.4 rule 2: a Token is not the legacy sf-string, so the dictionary is read.
        req = hand_signed(self.key, "agent;x=1", '"@authority" "signature-agent"')
        r = self.verify(req, {AGENT: self.jwks})
        self.assertEqual((r.outcome, r.reason), (Outcome.INVALID, "cannot determine Signature-Agent value"))

    def test_uncovered_member_is_never_credited_or_fetched(self):
        evil = "https://evil.example"
        header = f'sig2="{evil}", agent2="{AGENT}"'
        for label, operator in (("sig2", None), ("agent2", AGENT_ID)):
            with self.subTest(label=label):
                fetched = []
                res = DirectoryKeyResolver([AGENT, evil], fetch=lambda url: (
                    fetched.append(url) or json.dumps(self.jwks).encode(), 600))
                req = hand_signed(self.key, header, '"@authority" "signature-agent";key="agent2"', label)
                r = Verifier(res, clock=clock).verify(req)
                self.assertEqual((r.outcome, r.operator), (
                    Outcome.VERIFIED if operator else Outcome.UNKNOWN_OPERATOR, operator), r.reason)
                self.assertEqual(fetched, [AGENT + WELL_KNOWN_DIRECTORY] if operator else [])


if __name__ == "__main__":
    unittest.main()
