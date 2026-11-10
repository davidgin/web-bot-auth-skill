# Changelog

## 0.1.0

- Initial release. Verifier targets draft-meunier-web-bot-auth-architecture-05 and accepts the legacy sf-string Signature-Agent.
- RFC 9421 Appendix B.2.6 conformance test, attack-case tests and language-neutral test vectors.

### Security

- The commit originally published as v0.1.0 (afc43d9, before any release) let a request's `Signature-Agent` choose the key-directory URL on an allowlisted origin before the signature was verified. That allowed impersonation of allowlisted operators and lockout. Anyone who vendored `web_bot_auth.py` from that commit should update.
- Directory locations now come only from configuration: the origin's well-known path, or a full https URL given as the allowlist entry. Conflicting entries raise `ValueError`.
- The refetch rate limit now applies to cold and failed fetches.
- Trust is revoked when an operator is removed from the allowlist.

### Changed / Removed

- Removed `DirectoryKeyResolver.register_agent_url`.
- When an allowlisted operator has no usable keys, the result is `unknown_operator` with reason "key directory unavailable" instead of `invalid`.
- New optional resolver method `directory_unavailable(operator, now)`.
