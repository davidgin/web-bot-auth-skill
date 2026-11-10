# Changelog

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
