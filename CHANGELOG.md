# Changelog

## 0.2.1

Docs-only release; no code changes.

### Docs

- README rewritten to explain the problem and how the skill solves it, with a quick-start for the 0.2.0 API (#16, fixes #15).

## 0.2.0

Retargets the verifier from draft-meunier-web-bot-auth-architecture-05 to draft-ietf-webbotauth-httpsig-protocol-01 ("-01"). Several changes are breaking; read **Breaking** before updating.

### Security

- In 0.1.1 the identity was the origin of the claimed `Signature-Agent` URL, and the keys came from the directory configured for that origin (its well-known path, or the allowlist entry). A request claiming `https://agent.example/~mallory/keys.json` was therefore verified against the keys of `https://agent.example` and credited to it, although the claimed URL was never consulted. This is mis-attribution, not forgery: the signature still had to verify under a key in the configured directory, so an attacker without such a key could not impersonate the operator. The harm was that the claimed identity was not bound to where the keys came from, so tenants sharing a host were indistinguishable and any holder of a key on that host could pass under any path claim. This is the gap -01 §5.5 describes ("TLS authenticates the host but not the path"). The identifier is now the normalized `Signature-Agent` URL (FR-005..FR-008).
- Keys from third-party lists (`add_untrusted_directory`) are no longer attributed to a URL unless the caller says they were fetched from it (-01 §5.5.3), and they never override a removal by an allowlisted identifier's own fresh directory (FR-021, "removal wins").
- A 200 response that is not a JWKS no longer evicts the cached keys; the last good copy is kept (-01 §6.10).
- Four known test keys are rejected by default (-01 §6.8): two published ones (RFC 9421 B.1.4, RFC 8037 A.1) and two from this skill's own test vectors. Anyone who uses the vectors' keys (for example their own test deployment) must pass `allow_test_keys=True`.
- A `Signature-Agent` member covered under a different label's key, or one carrying parameters, is ignored: the request follows the no-URL path and is never attributed. Its outcome is `signed_untrusted` if an unattributed redistributed list holds the key, whatever a `StaticKeyResolver` `None` entry gives (possibly `verified` with `operator` None), and otherwise `unknown_operator` (-01 §5.2.1, §6.6.1, RFC 9421 §7.2.5).
- Fixed (pre-existing since 0.1.1, never yields `verified`): `add_untrusted_directory(url, ..., fetched=True)` followed by `allowlist.add(url)` left the untrusted entry in force for its whole ttl. The newly allowlisted directory was not fetched, removed keys still resolved as `signed_untrusted` with the operator set, and served keys were downgraded. The cached entry is now fresh only while it is trusted, so allowlisting takes effect on the next request.

### Breaking

- The identifier is the normalized `Signature-Agent` URL. `Result.operator` is that URL (with trailing `/` or path) and is set only when the request is attributed; it is `None` on every non-accepted outcome, `REPLAY` included. New last field `Result.claimed_agent` carries the normalized claim for logging.
- Allowlist entries on one host are separate identifiers. A bare origin still maps to `/.well-known/http-message-signatures-directory`; this is a documented deviation from -01 §4.1/§4.4. An agent that sends the explicit well-known URL needs its own entry, so allowlist both.
- Migration trap: in 0.1.1 an allowlist entry with a path (for example `https://agent.example/keys.json`, the form the 0.1.1 changelog told users to write) also accepted agents sending the bare origin. In 0.2.0 such an agent gets `unknown_operator` ("no key for this operator"). Allowlist both identifiers, or have the agent send the full URL.
- Allowlist entries are normalized full URLs. `allowlist.add`, `update` and `|=` raise `ValueError` for anything else.
- Custom resolvers: `resolve`, `is_allowlisted` and `directory_unavailable` receive normalized identifiers. `ResolvedKey.attributed` is new (default True); False forces untrusted and `operator` None.
- `StaticKeyResolver` raises on two config keys that normalize to the same identifier, and on known test keys unless `allow_test_keys=True`.
- `add_untrusted_directory`: first parameter `operator` renamed `url`. With `fetched=True` the keys are attributed to the URL (untrusted); with the default `fetched=False` they go to a per-source pool and carry no URL.
- `parse_directory` raises `ValueError` on a body that is not a JWKS, and on more than 64 keys (`max_keys`).
- `sign_request` requires `agent=`, requires the components to include `signature-agent` and `@authority` or `@target-uri`, and always sends the dictionary form (`Signature-Agent: <label>="<agent>"`). `agent_as_dictionary` is removed.
- Removed: `normalize_origin`, `directory_url`, `agent_as_dictionary` and `RedisNonceStore` (now a copy-paste snippet in `references/nonce-stores.md`).

### Added

- `@target-uri` is accepted in place of `@authority`.
- `max_keys` (default 64) on `parse_directory`, and the test-key denylist (`TEST_KEY_THUMBPRINTS`, `allow_test_keys`).
- `normalize_agent_url`.
- -01 Appendix E conformance tests (E.2.1, E.2.2, E.2.3; E.1 RSA-PSS is reported as unsupported) and the `normalization` section of the language-neutral test vectors.

### Development

- Development environment now uses uv (`pyproject.toml`, `uv.lock`). CI runs through uv. The shipped skill is unchanged.
- The size limit for `web_bot_auth.py` is 1,150 lines.

### Deferred to 0.3.0

- `verify_all` (several signatures per request), `@query-param`, and `accept_signature_header` / `Accept-Signature` guidance.

## 0.1.1

### Security

- Version 0.1.0 (the initial public commit afc43d9, never tagged or released) let a request's `Signature-Agent` choose the key-directory URL on an allowlisted origin before the signature was verified. That allowed impersonation of allowlisted operators and lockout: attacker-chosen keys were cached as trusted for up to 24 h. It also let requests with a not-yet-verified signature add entries to an unbounded in-memory table (any origin, allowlisted or not), and fetches on a cold cache were not rate-limited.
- Fixed in 0.1.1. Anyone who vendored `web_bot_auth.py` from 0.1.0 / afc43d9 should update.
- Directory locations now come only from configuration: the origin's well-known path, or a full https URL given as the allowlist entry. Conflicting entries raise `ValueError`.
- The refetch rate limit now applies to cold and failed fetches.
- Trust is revoked when an operator is removed from the allowlist. Before the fix, the keys of an operator removed from the allowlist at runtime stayed `verified` for up to 24 h.

### Changed / Removed

- **Check your allowlist before updating.** An allowlist entry with a path or query now pins that exact directory URL; at afc43d9 the path was ignored and the origin's well-known path was used. For example, `https://agent.example/operator` must become `https://agent.example` unless that path really is the directory. Entries with userinfo or a fragment now raise `ValueError`.
- Removed `DirectoryKeyResolver.register_agent_url`.
- The result is now `unknown_operator` with reason "key directory unavailable" instead of `invalid` only when the allowlisted operator has no fresh cached copy of its key directory (the cold fetch is in flight or failed, or the cache expired and the refresh failed) and the keyid is not in the stale copy. A keyid missing from a fresh directory stays `invalid`. During such an outage, forged requests are reported as `unknown_operator`, not as hostile; this costs detection signal but grants no access.
- New optional resolver method `directory_unavailable(operator, now)`.

### Development

- CI runs Python 3.9 on ubuntu-24.04 with fail-fast disabled.
- Added a code-size gate (`scripts/check_size.py`, baseline in `scripts/size_baseline.json`) and a repo `AGENTS.md`.

## 0.1.0

- Initial release. Verifier targets draft-meunier-web-bot-auth-architecture-05 and accepts the legacy sf-string Signature-Agent.
- RFC 9421 Appendix B.2.6 conformance test, attack-case tests and language-neutral test vectors.
- This version contains the vulnerability fixed in 0.1.1 and should not be used.
