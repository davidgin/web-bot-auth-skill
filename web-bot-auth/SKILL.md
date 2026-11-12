---
name: web-bot-auth
description: Add Web Bot Auth verification (HTTP Message Signatures, RFC 9421, Ed25519) to a web server, API, edge worker or middleware so signed AI agents and bots can be identified, and forged or replayed signatures rejected. Use this whenever the user wants to verify AI agent or bot traffic, accept signed agent requests, handle Signature / Signature-Input / Signature-Agent headers, stop blocking legitimate AI agents, distinguish real agents from spoofed ones, or add replay protection to signed requests — even if they don't name Web Bot Auth or RFC 9421.
license: Apache-2.0
compatibility: Reference implementation is Python 3.9+ with the `cryptography` package. Other languages port it and prove the port with the bundled test vectors.
---

# Web Bot Auth verification

This skill adds verification of signed agent traffic to an existing service. The hard part is not the cryptography; it is the small details that make a signature mean less than it appears to: unsigned components, a reused nonce, a header that triggers a fetch, a URL rebuilt differently from what the client signed. The reference code and tests here encode those details. Your job is to wire them into the user's stack without weakening them.

Spec status: targets `draft-ietf-webbotauth-httpsig-protocol-01`, an IETF working-group Internet-Draft (not a standard, and it may change before publication as an RFC). In -01 the operator is identified by its `Signature-Agent` URL, which this verifier normalizes and compares as the identifier. It also accepts the legacy quoted-string `Signature-Agent` that many deployed agents still send (-01 section 5.2.1 allows it). Tell the user it is a draft. Status-code guidance for rejected requests (status codes and the `Accept-Signature` helper) is not implemented yet; it waits for 0.3.0, so choose the HTTP responses with the user.

## Workflow

1. **Find the request entry point.** Identify the framework and where requests enter (middleware, edge handler, reverse-proxy hook). Note whether the service sits behind a proxy or CDN, because that decides how to rebuild the URL (see `references/adapters.md`).

2. **Settle the policy decisions with the user.** Read `references/policy-decisions.md` and ask about anything the conversation hasn't settled: which operators to allowlist, whether to require request binding and nonces, nonce store, and what each outcome should do. Don't silently pick strict settings: strict defaults reject most agents deployed today. Don't silently pick loose ones either: say what they leave open.

3. **Add the verifier.**
   - Python: copy `scripts/web_bot_auth.py` into the project unchanged (keep its license header), add `cryptography` to dependencies, and write a small adapter that builds a `Request`.
   - Other languages: port `scripts/web_bot_auth.py`, using the language's established Ed25519 library (never a hand-rolled one), and a maintained RFC 8941 structured-field parser if one exists. The port is not done until it passes every case in `assets/test-vectors.json`.

4. **Write the adapter carefully.** It is where most integrations break. The `Request` must carry the method as sent, the absolute URL as the client requested it, every header occurrence, and the raw body bytes before parsing or decompression. See `references/adapters.md` for per-framework notes.

5. **Choose the nonce store.** In-memory only for a single process. Anything with more than one worker or node needs a shared, strongly consistent store. See `references/nonce-stores.md`.

6. **Map outcomes to actions.** Use the table below unless the user decided otherwise.

7. **Test the integration end to end.** Write tests through the real framework (its test client) using `sign_request` (which needs `agent=`, the Signature-Agent URL) to produce signed requests: one valid request, one tampered body, one replay, and one expired request. Run `scripts/test_web_bot_auth.py` too if the file was copied.

8. **Recommend a log-only rollout.** Log `outcome`, `reason`, `operator`, `claimed_agent`, `keyid`, `binds_request` and `replay_protected` for every request for a period before enforcing anything. `operator` is the identifier the key was resolved under and is `None` when the key carries no URL; then `keyid` (the key thumbprint) is the identifier (-01 section 4.3). `claimed_agent` is the normalized `Signature-Agent` URL the request asserted. It is for logging only: -01 section 4.1 says not to attach policy to a URL that was not resolved.

## Outcomes

The outcomes refine the three of -01 Appendix C.1: *verified* (signature and key validate), *invalid* (signature, covered components, key or freshness fail) and *unverified* (not enough information to decide, for example discovery failed). `verified` and `signed_untrusted` are both C.1 "verified"; `unknown_operator` is C.1 "unverified"; `invalid`, `expired` and `replay` are C.1 "invalid". Whether the URL is on your list is a separate input to policy, which is what `verified` versus `signed_untrusted` records.

| Outcome | Meaning | Default action |
| --- | --- | --- |
| `unsigned` | No `web-bot-auth` signature | Existing bot handling / risk scoring |
| `verified` | Valid signature, allowlisted operator | Admit as that agent; still apply per-user auth and rate limits |
| `signed_untrusted` | Valid signature, but the key is not from an allowlisted URL: it was added through `add_untrusted_directory`, or it is a `StaticKeyResolver(trusted=False)` key, or it came from a redistributed list and carries no URL (`operator` is `None`) | Treat as unsigned, optionally with lower risk |
| `unknown_operator` | Unverified (-01 App. C.1): well-formed, but no key available: URL not allowlisted (`no key for this operator`), or an allowlisted URL's directory is unavailable (`key directory unavailable`: cold fetch in flight or failed, or cache expired and refresh failed) | Treat as unsigned; optionally queue a background directory fetch. Not hostile: a transient fetch failure must not block a legitimate agent |
| `invalid` | Present and wrong, including a keyid missing from a fresh cached directory of an allowlisted URL (a directory that resolves without the key is evidence, -01 section 6.10), or a known test key | Block. Legitimate clients do not send broken signatures |
| `expired` | Outside its time window | Block |
| `replay` | Nonce already used | Block |

`Result.hostile` is true for the last three. For `verified`, also check two flags. If `binds_request` is false, the signature doesn't cover the method, path, query and body. If `replay_protected` is false, there was no nonce or the store was unavailable. A sensible default is to admit verified requests with either flag false for safe methods (GET, HEAD, OPTIONS) only.

## Rules that are easy to break

These exist because each one has a concrete attack behind it. If the user's constraints seem to require breaking one, explain the risk and let them decide.

- **Never fetch a key directory inline for a URL that isn't allowlisted.** `Signature-Agent` is attacker-controlled, so fetching whatever it names is SSRF and lets anyone stall your request path (-01 section 6.7). Fetch unknown URLs in a background job with `safe_fetch_directory`, or not at all. -01 section 5.4 only says a verifier MAY fetch; the allowlist is this skill's stricter policy.
- **Allowlist identifiers are full normalized HTTPS URLs, configured on the server.** `DirectoryKeyResolver(["https://agent.example/keys.json"])` trusts the identifier `https://agent.example/keys.json` and fetches that URL. The query is dropped from the identifier but kept in the fetch URL. Fragments and userinfo are rejected. `resolver.allowlist.add` (and `update`, `|=`) takes the normalized identifier and raises `ValueError` otherwise, naming the normalized form; this makes an old origin-style `add("https://host")` fail loudly instead of never matching. Removing an identifier revokes trust at once.
- **Bare origins are a documented deviation from -01.** -01 sections 4.1 and 4.4 make the identifier the URL the verifier fetched. For a bare origin (`https://agent.example`, path `/`) this verifier instead fetches `/.well-known/http-message-signatures-directory` (the path is reserved for the domain operator, -01 section 4.5) and keeps `https://agent.example/` as the identifier. The two spellings are different identifiers (-01 section 5.5 compares octets), so when an agent may send either, allowlist both `https://agent.example` and `https://agent.example/.well-known/http-message-signatures-directory`. An agent that sends the explicit well-known URL does not match a bare-origin entry and comes back as `unknown_operator`.
- **A path is not an origin.** `https://agent.example/team-a` and `https://agent.example/team-b` are different identifiers; a key resolved for one is never credited to the other or to the origin (-01 section 5.5: an arbitrary path does not name the host's operator).
- **Redistributed key lists carry no URL.** `add_untrusted_directory(url, data)` keys verify requests but are attributed to no URL (-01 section 5.5.3); the result is `signed_untrusted` with `operator=None`. Pass `fetched=True` only when you fetched `url` yourself over TLS. A fresh directory of an allowlisted URL that lacks the key wins over any list (removal wins).
- **Known test keys are rejected by default** (-01 section 6.8): the RFC 9421 B.1.4, RFC 8037 A.1 keys and this skill's own vector keys, in directories and in `StaticKeyResolver` configuration. The list is not exhaustive. Pass `allow_test_keys=True` only in tests.
- **Verify Content-Digest against the body whenever it is covered.** Signing the header is meaningless if nobody checks that it matches the bytes received.
- **Record the nonce only after the signature verifies.** Otherwise anyone can fill the store, or burn a legitimate agent's nonces in advance.
- **Use a shared, atomic nonce store across instances.** A per-process cache lets a replay land on a different worker.
- **Bound freshness by `created`, not only `expires`.** Agents may sign with long expiries; `Policy.max_age` keeps the replay window and the nonce cache small regardless.
- **Rebuild the URL the client actually requested.** Behind a proxy, use the forwarded scheme and host only from proxies you trust. If you get it wrong, valid signatures fail to verify, or a spoofed host header gets trusted. When the agent covers `@target-uri`, `req.url` must be the exact string the agent signed: `https://h:443/` is not the same string as `https://h/`, and a TLS-terminating proxy must rebuild the external URL, not the internal one.
- **Refuse signature headers over plain http** (-01 section 6.1, a SHOULD): do not verify, and do not treat as signed, a request that arrived over an unsecured channel.
- **A verified signature identifies the operator, not the user.** Keep normal authentication and per-user authorization and rate limits behind it. Never let a signature stand in for user consent on sensitive actions.
- **Don't apply human-behavior checks to verified agents.** They are automation by design.

## Files

- `scripts/web_bot_auth.py`: the verifier, key resolvers, the in-memory nonce store and `sign_request`. Single file; depends only on `cryptography`.
- `scripts/test_web_bot_auth.py`: attack-case tests plus the RFC 9421 Appendix B.2.6 conformance vector. Run with `python -m unittest -v test_web_bot_auth` from `scripts/`.
- `scripts/generate_vectors.py`: regenerates `assets/test-vectors.json`.
- `assets/test-vectors.json`: language-neutral vectors for ports (test keys only).
- `references/policy-decisions.md`: the choices to make with the user, with tradeoffs. Read in step 2.
- `references/adapters.md`: building `Request` correctly in common frameworks and behind proxies. Read in step 4.
- `references/nonce-stores.md`: which stores are safe and how to size them. Read in step 5, including the Redis snippet to copy.
