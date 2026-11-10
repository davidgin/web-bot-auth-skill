---
name: web-bot-auth
description: Add Web Bot Auth verification (HTTP Message Signatures, RFC 9421, Ed25519) to a web server, API, edge worker or middleware so signed AI agents and bots can be identified, and forged or replayed signatures rejected. Use this whenever the user wants to verify AI agent or bot traffic, accept signed agent requests, handle Signature / Signature-Input / Signature-Agent headers, stop blocking legitimate AI agents, distinguish real agents from spoofed ones, or add replay protection to signed requests — even if they don't name Web Bot Auth or RFC 9421.
license: Apache-2.0
compatibility: Reference implementation is Python 3.9+ with the `cryptography` package. Other languages port it and prove the port with the bundled test vectors.
---

# Web Bot Auth verification

This skill adds verification of signed agent traffic to an existing service. The hard part is not the cryptography; it is the small details that make a signature mean less than it appears to: unsigned components, a reused nonce, a header that triggers a fetch, a URL rebuilt differently from what the client signed. The reference code and tests here encode those details. Your job is to wire them into the user's stack without weakening them.

Spec status: targets `draft-meunier-web-bot-auth-architecture-05` (an IETF Internet-Draft, not a standard) and accepts the legacy quoted-string `Signature-Agent` that many deployed agents still send. Tell the user it is a draft and may change.

## Workflow

1. **Find the request entry point.** Identify the framework and where requests enter (middleware, edge handler, reverse-proxy hook). Note whether the service sits behind a proxy or CDN, because that decides how to rebuild the URL (see `references/adapters.md`).

2. **Settle the policy decisions with the user.** Read `references/policy-decisions.md` and ask about anything the conversation hasn't settled: which operators to allowlist, whether to require request binding and nonces, nonce store, and what each outcome should do. Don't silently pick strict settings: strict defaults reject most agents deployed today. Don't silently pick loose ones either: say what they leave open.

3. **Add the verifier.**
   - Python: copy `scripts/web_bot_auth.py` into the project unchanged (keep its license header), add `cryptography` to dependencies, and write a small adapter that builds a `Request`.
   - Other languages: port `scripts/web_bot_auth.py`, using the language's established Ed25519 library (never a hand-rolled one), and a maintained RFC 8941 structured-field parser if one exists. The port is not done until it passes every case in `assets/test-vectors.json`.

4. **Write the adapter carefully.** It is where most integrations break. The `Request` must carry the method as sent, the absolute URL as the client requested it, every header occurrence, and the raw body bytes before parsing or decompression. See `references/adapters.md` for per-framework notes.

5. **Choose the nonce store.** In-memory only for a single process. Anything with more than one worker or node needs a shared, strongly consistent store. See `references/nonce-stores.md`.

6. **Map outcomes to actions.** Use the table below unless the user decided otherwise.

7. **Test the integration end to end.** Write tests through the real framework (its test client) using `sign_request` to produce signed requests: one valid request, one tampered body, one replay, and one expired request. Run `scripts/test_web_bot_auth.py` too if the file was copied.

8. **Recommend a log-only rollout.** Log `outcome`, `reason`, `operator`, `keyid`, `binds_request` and `replay_protected` for every request for a period before enforcing anything.

## Outcomes

| Outcome | Meaning | Default action |
| --- | --- | --- |
| `unsigned` | No `web-bot-auth` signature | Existing bot handling / risk scoring |
| `verified` | Valid signature, allowlisted operator | Admit as that agent; still apply per-user auth and rate limits |
| `signed_untrusted` | Valid signature, known but not allowlisted operator | Treat as unsigned, optionally with lower risk |
| `unknown_operator` | Well-formed, but no key available | Treat as unsigned; optionally queue a background directory fetch |
| `invalid` | Present and wrong | Block. Legitimate clients do not send broken signatures |
| `expired` | Outside its time window | Block |
| `replay` | Nonce already used | Block |

`Result.hostile` is true for the last three. For `verified`, also check two flags. If `binds_request` is false, the signature doesn't cover the method, path, query and body. If `replay_protected` is false, there was no nonce or the store was unavailable. A sensible default is to admit verified requests with either flag false for safe methods (GET, HEAD, OPTIONS) only.

## Rules that are easy to break

These exist because each one has a concrete attack behind it. If the user's constraints seem to require breaking one, explain the risk and let them decide.

- **Never fetch a key directory inline for an operator that isn't allowlisted.** `Signature-Agent` is attacker-controlled, so fetching whatever it names is SSRF and lets anyone stall your request path. Fetch unknown operators in a background job with `safe_fetch_directory`, or not at all.
- **Configure the trusted directory URL on the server.** `DirectoryKeyResolver(["https://agent.example"])` uses that origin's `/.well-known/http-message-signatures-directory`. A full HTTPS allowlist entry, such as `https://agent.example/operator/keys.json?version=2`, selects a fixed path and query for that origin. Fragments and userinfo are rejected. Directory locations come only from the allowlist configuration; requests cannot select or update them. Fetch attempts are limited per operator (once a minute by default), including cold starts and failures. Removing an origin from `resolver.allowlist` immediately stops its cached keys resolving as trusted.
- **Verify Content-Digest against the body whenever it is covered.** Signing the header is meaningless if nobody checks that it matches the bytes received.
- **Record the nonce only after the signature verifies.** Otherwise anyone can fill the store, or burn a legitimate agent's nonces in advance.
- **Use a shared, atomic nonce store across instances.** A per-process cache lets a replay land on a different worker.
- **Bound freshness by `created`, not only `expires`.** Agents may sign with long expiries; `Policy.max_age` keeps the replay window and the nonce cache small regardless.
- **Rebuild the URL the client actually requested.** Behind a proxy, use the forwarded scheme and host only from proxies you trust. If you get it wrong, valid signatures fail to verify, or a spoofed host header gets trusted.
- **A verified signature identifies the operator, not the user.** Keep normal authentication and per-user authorization and rate limits behind it. Never let a signature stand in for user consent on sensitive actions.
- **Don't apply human-behavior checks to verified agents.** They are automation by design.

## Files

- `scripts/web_bot_auth.py`: the verifier, key resolvers, nonce stores and `sign_request`. Single file; depends only on `cryptography`.
- `scripts/test_web_bot_auth.py`: attack-case tests plus the RFC 9421 Appendix B.2.6 conformance vector. Run with `python -m unittest -v test_web_bot_auth` from `scripts/`.
- `scripts/generate_vectors.py`: regenerates `assets/test-vectors.json`.
- `assets/test-vectors.json`: language-neutral vectors for ports (test keys only).
- `references/policy-decisions.md`: the choices to make with the user, with tradeoffs. Read in step 2.
- `references/adapters.md`: building `Request` correctly in common frameworks and behind proxies. Read in step 4.
- `references/nonce-stores.md`: which stores are safe and how to size them. Read in step 5.
