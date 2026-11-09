# web-bot-auth skill

An Agent Skill that teaches coding agents to add **Web Bot Auth** verification to a web service. With it, AI agents and bots that sign their requests (HTTP Message Signatures, RFC 9421, Ed25519) can be identified, and forged or replayed signatures are rejected.

The skill bundles:

- **A reference verifier** (`web-bot-auth/scripts/web_bot_auth.py`): a single Python file whose only dependency is `cryptography`. It covers RFC 8941 parsing, RFC 9421 signature bases, Ed25519, RFC 9530 Content-Digest, JWK thumbprints, SSRF-guarded key directory fetching and nonce-based replay protection.
- **Attack-case tests**: tampered body, method/path/host swap, replay, expiry, wrong key, uncovered `Signature-Agent`, nonce store outage, and more. It also includes the RFC 9421 Appendix B.2.6 Ed25519 conformance vector.
- **Language-neutral test vectors** (`web-bot-auth/assets/test-vectors.json`), so ports to TypeScript, Go, Rust and other languages can prove they behave the same.
- **Instructions and references** for agents: the policy decisions to settle with the user, how to build the request correctly in common frameworks and behind proxies, and which nonce stores are safe.

## Spec status

Web Bot Auth is an IETF Internet-Draft, not a standard. This skill targets [`draft-meunier-web-bot-auth-architecture-05`](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/). It also accepts the legacy quoted-string `Signature-Agent` form that many deployed agents still send. Expect changes as the draft evolves.

## Install

**Claude Code:** copy the `web-bot-auth/` folder into `~/.claude/skills/` (all projects) or `.claude/skills/` in a repository (that project only).

**Claude apps:** download `web-bot-auth.skill` from the latest release and upload it in the Skills section of Settings.

**Other agents** that support the Agent Skills format: place `web-bot-auth/` wherever the agent loads skills from.

Then ask something like: *"Add Web Bot Auth verification to this FastAPI app"* or *"We're blocking AI shopping agents — let signed ones through."*

## Using the verifier directly

```python
from web_bot_auth import Verifier, DirectoryKeyResolver, RedisNonceStore, Request, Outcome

verifier = Verifier(
    keys=DirectoryKeyResolver(allowlist=["https://agent.example"]),
    nonces=RedisNonceStore(redis_client),
)
result = verifier.verify(Request(method, absolute_url, header_pairs, raw_body))
if result.hostile:
    ...  # block: invalid, expired or replayed signature
elif result.outcome is Outcome.VERIFIED:
    ...  # known agent operator; still apply per-user auth and rate limits
else:
    ...  # unsigned or unknown: your existing bot handling
```

See `web-bot-auth/SKILL.md` for the outcome table and the rules that keep this safe.

## Development

This repo uses [uv](https://docs.astral.sh/uv/) for the dev environment (`pyproject.toml` and `uv.lock` at the root; they are not part of the shipped skill).

```sh
uv sync
cd web-bot-auth/scripts
uv run python -m unittest -v test_web_bot_auth
```

If you change verification behavior, regenerate the vectors with `uv run python generate_vectors.py > ../assets/test-vectors.json` (from `web-bot-auth/scripts`). A test fails if they are out of date.

The verifier needs only `cryptography`, so `pip install cryptography` in any virtualenv works too (for example when you vendor the file).

## What this does not do

- It does not decide whether a user is allowed to do something. A valid signature identifies the agent's operator, not the person behind it.
- It does not verify the signature on a key directory response.
- It does not implement risk scoring for unsigned traffic. It tells you which requests are unsigned so your existing defenses can handle them.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache License 2.0. See [LICENSE](LICENSE).
