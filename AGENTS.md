# web-bot-auth-skill agent rules

Extends `~/.agents/AGENTS.md`; everything there applies unless overridden here.

## Size limits (exception to the global "Code size" rule)

- `web-bot-auth/scripts/web_bot_auth.py` may be up to **1,100 lines**. It must
  stay one vendorable file whose only dependency is `cryptography`, so it cannot
  be split into modules. All other source files keep the global 1,000-line limit;
  functions stay at 50 lines or fewer. Tests are not counted.
- The gate is `python scripts/check_size.py`, run in CI, with its baseline in
  `scripts/size_baseline.json`. The baseline lists known oversized functions
  and may only shrink; a new or growing offender fails.

## Conventions

- Every `.py` file starts with `# SPDX-License-Identifier: Apache-2.0`.
- A behaviour change needs a failing test first and regenerated vectors
  (`web-bot-auth/scripts/generate_vectors.py`).
- Check spec facts against the current draft, not memory.
- Only `web-bot-auth/` ships to users; tooling lives outside it (e.g. `scripts/`).
