# Policy decisions

Settle these with the user before wiring anything in. Each lists the default in `Policy` or the resolver, the reason for it, and what changing it costs.

## 1. Which operators are trusted

Only allowlisted operators produce `verified`. Options:

- **Static keys** (`StaticKeyResolver`): keys pasted into config. Simplest and no network access, but rotation is a config change.
- **Directory fetch** (`DirectoryKeyResolver`): fetches `/.well-known/http-message-signatures-directory` for allowlisted origins, caches it for the `Cache-Control` max-age (clamped to 5 min–24 h), and refetches at most once a minute on an unknown `keyid` to pick up rotations.

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
