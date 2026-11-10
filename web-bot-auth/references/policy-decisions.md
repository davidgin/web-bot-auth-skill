# Policy decisions

Settle these with the user before wiring anything in. Each lists the default in `Policy` or the resolver, the reason for it, and what changing it costs.

## 1. Which operators are trusted

Only allowlisted operators produce `verified`. Options:

- **Static keys** (`StaticKeyResolver`): keys pasted into config. Simplest and no network access, but rotation is a config change.
- **Directory fetch** (`DirectoryKeyResolver`): server configuration selects the directory. Plain HTTPS origins (with or without a trailing slash) use `/.well-known/http-message-signatures-directory`. A full HTTPS allowlist entry selects its path and query, for example `DirectoryKeyResolver(["https://agent.example/operator/keys.json?version=2"])`. Its normalized origin, `https://agent.example`, remains the operator identity. Root paths use the well-known path and preserve any configured query. Fragments, userinfo, malformed URLs and non-HTTPS entries are rejected. Configure one directory per origin: conflicting directory URLs for the same normalized origin raise `ValueError` naming that origin, regardless of entry order. Identical normalized directory URLs are accepted.

The resolver caches successful fetches for the `Cache-Control` max-age (clamped to 5 min–24 h). Unknown `keyid` values can trigger rotation refetches, but all fetch attempts share a per-operator limit (once a minute by default), even with an empty cache, a timeout or a malformed response. Concurrent requests share this limit within each resolver instance. A failed refresh preserves the last good copy for an allowlisted operator. When an allowlisted operator has no fresh directory (first fetch in flight or failed, or the cache expired and the refresh failed or was rate-limited) and the keyid is not in the stale copy, the result is `unknown_operator` with reason `key directory unavailable`, not `invalid`: that is not evidence of a bad signature, and the caller treats it as unsigned and a later request succeeds once the limit allows a fetch. A keyid missing from a fresh cached directory stays `invalid`. Concurrent requests during an in-flight first fetch do not wait for it. During a directory outage, forged requests claiming an allowlisted operator are also reported as `unknown_operator` rather than hostile; that loses detection signal but never grants access.

Request `Signature-Agent` values provide the operator origin only: their paths, queries and fragments never change resolver configuration. `register_agent_url` and its request-populated URL map have been removed. The `directory_url` helper resolves server configuration only. To revoke trust, remove the normalized origin from `resolver.allowlist`; a cached key may then resolve only as `signed_untrusted` until its cache entry expires, after which it is unavailable. Removing trust does not trigger another fetch.

Removing an operator from `resolver.allowlist` at runtime revokes trust immediately. To add operators or change directory URLs, construct a new resolver with the complete configuration. Direct runtime `resolver.allowlist.add` is not supported for custom directories: for a new operator it must use the exact normalized origin and uses that origin's well-known directory. It does not configure a custom path or query.

Draft scope: [architecture-05 Sections 4.2.1, 4.4 and 4.5](https://www.ietf.org/archive/id/draft-meunier-web-bot-auth-architecture-05.html#section-4.2.1) describes signed `Signature-Agent` members and optional directory discovery. Its [directory-05 Section 4](https://www.ietf.org/archive/id/draft-meunier-http-message-signatures-directory-05.html#section-4) defines the value as a directory URI. Neither establishes this implementation's origin-based allowlist trust rule. Keeping origin identity while pinning the trusted fetch location in server configuration is this verifier's security policy, not a claim that the draft identifies every path on an origin as the same agent.

Ask who approves additions to the allowlist; this is a trust decision, not a technical one. If the user wants to recognize operators beyond the allowlist, do it in a background job that calls `safe_fetch_directory` and `add_untrusted_directory`; those operators then come back as `signed_untrusted`, never `verified`.

Not implemented: verifying the directory response's own signature (the directory draft defines one). Fetching over HTTPS from an allowlisted origin is the trust anchor here; mention this if the user needs stronger guarantees.

## 2. Request binding — `require_binding` (default False)

The draft only requires `@authority` and `signature-agent` to be signed, and many agents sign only those. A signature like that proves who sent *a* request to this host, but not which method, path or body.

- **Off (default):** such signatures verify with `binds_request=False`. Recommended handling: admit them for safe methods only.
- **On:** they become `invalid` (blocked). Choose this only if the user controls or negotiates with the agents they accept, or the endpoint is state-changing only.

## 3. Nonces — `require_nonce` (default False)

Without a nonce, a captured request can be replayed until it goes stale (`max_age`). With TLS, capture usually means a compromised intermediary or leaked logs, so the risk is real but narrow.

- **Off (default):** no-nonce signatures verify with `replay_protected=False`.
- **On:** they become `invalid`. Reasonable for APIs whose agent clients you onboard.

`min_nonce_length` (16) rejects trivially guessable nonces.

## 4. Freshness — `max_age` 300 s, `max_lifetime` 86400 s, `clock_skew` 5 s

- `max_age`: maximum age of `created`. This bounds replay for nonce-less signatures and the nonce cache's size for all signatures, independent of how far out the agent set `expires`. Lowering it below ~60 s starts rejecting agents with slow clocks or queued requests.
- `max_lifetime`: maximum `expires - created`. The draft recommends 24 h or less.
- `clock_skew`: tolerance in both directions. Keep it small; agents with drifting clocks should fix them.

## 5. Nonce store failure — `fail_closed_methods` (POST, PUT, PATCH, DELETE)

If the shared store is unreachable, state-changing requests become `invalid`, and safe ones verify with `replay_protected=False`. Ask if the user would rather fail closed for everything.

## 6. Actions per outcome

Start from the table in SKILL.md. Points to raise:

- `invalid`, `expired`, `replay`: block. Log them; spikes per operator suggest key compromise or an attack.
- An unsigned request whose User-Agent claims to be a known signing agent is suspicious. Feed that into existing bot scoring.
- `verified` says nothing about the end user. Sensitive actions still need the user's session or a user-granted token, and rate limits should apply per operator *and* per user.

Custom resolvers: the verifier always gets the key and its trust flag from `resolve(keyid, operator, now)`, so a subclass, wrapper or instance-patched `resolve` can revoke keys or downgrade trust. A resolver may also define `directory_unavailable(operator, now) -> bool` (side-effect free; `DirectoryKeyResolver` implements it from its cache). It is read only when `resolve` returned no key, and only chooses between `invalid` (False) and `unknown_operator` with `key directory unavailable` (True); it can never produce `verified` or `signed_untrusted`. A custom `resolve` that revokes a key before the cache was ever filled reads as unavailable, not invalid, for that first request.
