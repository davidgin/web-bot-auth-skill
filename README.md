# web-bot-auth skill

An Agent Skill that teaches coding agents (Claude Code and other agents that load the Agent Skills format) to add **Web Bot Auth** verification to a web service. Once it is in place, AI agents and bots that sign their requests (HTTP Message Signatures, RFC 9421, Ed25519) can be identified, and forged or replayed signatures are rejected.

It is for developers who run a website, API or edge worker and want to let legitimate signed agents through without letting impostors in.

## The problem

Services cannot easily tell a legitimate AI agent or crawler from a scraper or impersonator:

- **User-Agent strings can be spoofed.** Anyone can send `User-Agent: SomeBot`.
- **IP ranges are brittle.** They are shared, change, and have to be published and kept in sync out of band.

So firewalls either block useful agents or let impostors through. The Web Bot Auth drafts say the same: "Current identification methods such as IP allowlisting, User-Agent strings, or shared API keys have significant limitations" ([architecture-05](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/05/), section 1).

**What Web Bot Auth proposes:** the agent operator signs each request with HTTP Message Signatures (RFC 9421) and publishes its public keys as a JWKS key directory, by default at `https://<operator>/.well-known/http-message-signatures-directory`. The signature carries `tag="web-bot-auth"` and a `keyid` that is the key's JWK SHA-256 thumbprint. The optional `Signature-Agent` header names the operator's directory. A server can then check cryptographically which operator sent a request.

**The second problem:** verification is easy to get subtly wrong, and each mistake becomes a bypass. A signature can mean less than it appears to: components it does not cover, a reused nonce, a header that makes the server fetch an attacker's URL, a URL rebuilt differently from what the client signed.

## How this skill solves it

The skill gives a coding agent a workflow, a tested reference verifier and the rules behind it, so the agent wires verification into your stack without weakening it. It handles the mistakes that matter:

- rebuilding the signed request correctly behind proxies (host and path);
- replay (nonces and `created` age);
- body binding (`Content-Digest`) and partially covered signatures;
- SSRF when fetching keys;
- trusting only allowlisted operators.

What the agent does with it (from [`web-bot-auth/SKILL.md`](web-bot-auth/SKILL.md)):

1. Finds the request entry point (middleware, edge handler, proxy hook) and whether the service is behind a proxy or CDN.
2. Settles the policy decisions with you: which operators to allowlist, whether to require request binding and nonces, the nonce store, and what each outcome does.
3. Vendors the Python verifier unchanged, or ports it to your language and proves the port against the bundled test vectors.
4. Writes the adapter that turns your framework's request into a `Request` (method as sent, absolute URL as requested, every header, raw body).
5. Picks a nonce store that is safe for your deployment.
6. Maps outcomes to actions, adds end-to-end tests (valid, tampered body, replay, expired) and recommends a log-only rollout first.

### Request flow

```
Agent operator                                  Your service
--------------                                  ------------
Ed25519 key  ->  public_jwk(key) published at
                 /.well-known/http-message-signatures-directory
sign_request(..., agent=URL) adds Signature-Agent,
Signature-Input, Signature (and Content-Digest
if covered)  ---------- signed request ------>  adapter builds Request(method, url, headers, body)
                                                Verifier.verify(request):
                                                  find the tag="web-bot-auth" signature
                                                  check created/expires against Policy
                                                  resolve keyid via DirectoryKeyResolver
                                                    (allowlisted identifiers only, SSRF-guarded fetch)
                                                  rebuild the RFC 9421 signature base, verify Ed25519
                                                  check Content-Digest against the body if covered
                                                  record the nonce (after the signature verifies)
                                                -> Result(outcome, operator, binds_request, replay_protected, ...)
```

Results split traffic into three groups:

| Group | Outcomes | Default action |
| --- | --- | --- |
| Verified agent | `verified` | Admit as that operator; still apply per-user auth and rate limits |
| Hostile | `invalid`, `expired`, `replay` (`Result.hostile`) | Block |
| Not identified | `unsigned`, `signed_untrusted`, `unknown_operator` | Your existing bot handling |

The full outcome table and the rules behind each check are in [`web-bot-auth/SKILL.md`](web-bot-auth/SKILL.md).

### What ships

Only the `web-bot-auth/` folder ships:

- **A reference verifier** (`scripts/web_bot_auth.py`): one Python file whose only dependency is `cryptography`. It covers RFC 8941 parsing, RFC 9421 signature bases, Ed25519, RFC 9530 Content-Digest, JWK thumbprints (RFC 7638 / RFC 8037), SSRF-guarded key directory fetching, nonce-based replay protection, and `sign_request` for tests.
- **Attack-case tests** (`scripts/test_web_bot_auth.py`): tampered body, method/path/host swap, replay, expiry, wrong key, uncovered `Signature-Agent`, nonce store outage, and more, plus the RFC 9421 Appendix B.2.6 Ed25519 conformance vector.
- **Language-neutral test vectors** (`assets/test-vectors.json`), so ports to TypeScript, Go, Rust and other languages can prove they behave the same.
- **References** for the agent: [policy decisions](web-bot-auth/references/policy-decisions.md), [framework and proxy adapters](web-bot-auth/references/adapters.md), [nonce stores](web-bot-auth/references/nonce-stores.md).

## Quick start

### Install the skill

- **Claude Code:** copy the `web-bot-auth/` folder into `~/.claude/skills/` (all projects) or `.claude/skills/` in a repository (that project only).
- **Claude apps:** download `web-bot-auth.skill` from the [latest release](https://github.com/davidgin/web-bot-auth-skill/releases/latest) and upload it in the Skills section of Settings.
- **Other agents** that support the Agent Skills format: place `web-bot-auth/` wherever the agent loads skills from.

Then ask something like: *"Add Web Bot Auth verification to this FastAPI app"* or *"We're blocking AI shopping agents. Let signed ones through."*

### Try the verifier by hand

Copy `web-bot-auth/scripts/web_bot_auth.py` next to this script and install `cryptography` (`pip install cryptography`). It signs a request as an agent would, then verifies it twice:

```python
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from web_bot_auth import (InMemoryNonceStore, Request, StaticKeyResolver, Verifier,
                          public_jwk, sign_request)

AGENT = "https://agent.example"
key = Ed25519PrivateKey.generate()            # the agent operator's signing key
jwks = {"keys": [public_jwk(key)]}            # what the operator publishes in its key directory

# Agent side: sign an outgoing request.
req = sign_request(Request("GET", "https://shop.example/products?id=1"), key,
                   agent=AGENT, nonce=secrets.token_urlsafe(32))

# Server side: verify it. StaticKeyResolver stands in for DirectoryKeyResolver here.
verifier = Verifier(StaticKeyResolver({AGENT: jwks}), InMemoryNonceStore())
print(verifier.verify(req).outcome.value)     # verified
print(verifier.verify(req).outcome.value)     # replay: same nonce again
```

`sign_request` requires `agent=` and always sends `Signature-Agent` in the dictionary form (`sig1="https://agent.example"`); it also requires the covered components to include `signature-agent` and `@authority` or `@target-uri`. The verifier identifies the agent by that full URL, normalized (`https://agent.example/`), not by its origin. `result.operator` holds the identifier on accepted outcomes only; `result.claimed_agent` holds the normalized claim for logging.

### Use it in a service

```python
from web_bot_auth import SAFE_METHODS, DirectoryKeyResolver, Outcome, Request, Verifier

# RedisNonceStore is not part of web_bot_auth.py: copy the snippet from
# web-bot-auth/references/nonce-stores.md into your application.
verifier = Verifier(
    keys=DirectoryKeyResolver(allowlist=["https://agent.example/"]),
    nonces=RedisNonceStore(redis_client),
)
result = verifier.verify(Request(method, absolute_url, header_pairs, raw_body))
if result.hostile:
    ...  # block: invalid, expired or replayed signature
elif result.outcome is Outcome.VERIFIED:
    if (result.binds_request and result.replay_protected) or method.upper() in SAFE_METHODS:
        ...  # known agent operator; still apply per-user auth and rate limits
    else:
        ...  # signature does not bind the request or has no nonce: not enough for a state-changing method
else:
    ...  # unsigned or unknown: your existing bot handling
```

A `VERIFIED` result can still have `binds_request` false (the signature does not cover the method, path, query and body) or `replay_protected` false (no nonce, or the nonce store was unavailable). The example admits those only for safe methods. For strict mode, pass `policy=Policy(require_binding=True, require_nonce=True)` to `Verifier` (import `Policy` from `web_bot_auth`); such signatures then become `invalid` instead.

Allowlist entries are full, normalized HTTPS URLs, and each is a separate identifier: `https://agent.example/` and `https://agent.example/team-a` are different operators even on the same host, and an agent is matched only by the exact URL it sends in `Signature-Agent`. If an agent might send either form, allowlist both. A bare origin entry fetches keys from `/.well-known/http-message-signatures-directory`; any other entry is fetched from its own URL. A request can never choose where keys are fetched from. Conflicting entries for the same identifier, and entries that are not normalized, raise `ValueError`. A directory may hold at most 64 keys, and the known public test keys (RFC 9421 and the skill's own vectors) are rejected unless you pass `allow_test_keys=True`.

## Spec status

Web Bot Auth is an IETF Internet-Draft, not a standard, and may change. As of 0.2.0 the verifier targets the webbotauth working group draft [`draft-ietf-webbotauth-httpsig-protocol-01`](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/): `tag="web-bot-auth"`, the JWK thumbprint `keyid`, the dictionary `Signature-Agent` header, and the `/.well-known/http-message-signatures-directory` location. The identity of an agent is its normalized `Signature-Agent` URL; one documented deviation is that a bare-origin entry fetches the well-known directory. It accepts `@target-uri` in place of `@authority`. The earlier drafts ([architecture-05](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/05/), [directory-05](https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/05/)) are no longer the target. The verifier still accepts the legacy quoted-string `Signature-Agent` that many deployed agents send, but `sign_request` only produces the dictionary form. See the [CHANGELOG](CHANGELOG.md) for what changed and the breaking changes.

## What this does not do

- It does not decide whether a user is allowed to do something. A valid signature identifies the agent's operator, not the person behind it.
- It does not verify the signature on a key directory response.
- It does not implement risk scoring for unsigned traffic. It tells you which requests are unsigned so your existing defenses can handle them.

## Security

- Version 0.1.0 (the initial commit, never released) let a request's `Signature-Agent` choose the key-directory URL before the signature was verified. It is fixed in 0.1.1; anyone who vendored `web_bot_auth.py` from 0.1.0 should update and check their allowlist entries. Details are in [CHANGELOG.md](CHANGELOG.md#011).
- Version 0.2.0 binds an agent's identity to its full `Signature-Agent` URL instead of its origin, so tenants on a shared host are distinct identifiers. Allowlist entries from 0.1.1 that carry a path no longer match an agent that sends the bare origin; allowlist both forms or have the agent send the full URL. Details are in [CHANGELOG.md](CHANGELOG.md#020).
- To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Development

This repo uses [uv](https://docs.astral.sh/uv/) for the dev environment (`pyproject.toml` and `uv.lock` at the root; they are not part of the shipped skill).

```sh
uv sync
(cd web-bot-auth/scripts && uv run python -m unittest -v test_web_bot_auth)
uv run python scripts/check_size.py    # code-size gate, baseline in scripts/size_baseline.json
```

If you change verification behavior, add a failing test first, then regenerate the vectors from `web-bot-auth/scripts`:

```sh
uv run python generate_vectors.py > ../assets/test-vectors.json
```

A test fails if the vectors are out of date. CI runs the tests on Python 3.9, 3.11 and 3.13 and the size gate on 3.13. Repo rules for contributors and agents are in [AGENTS.md](AGENTS.md).

The verifier needs only `cryptography`, so `pip install cryptography` in any virtualenv works too (for example when you vendor the file).

## License

Apache License 2.0. See [LICENSE](LICENSE).
