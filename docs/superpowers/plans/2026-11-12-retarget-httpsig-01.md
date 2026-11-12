# Plan: retarget to draft-ietf-webbotauth-httpsig-protocol-01 (release 0.2.0)

- Spec: `docs/superpowers/specs/2026-11-12-retarget-httpsig-01-design.md`
  (revision 1)
- Branch / worktree: `feat/retarget-httpsig-01` at
  `/home/eldan/projects/web-bot-auth-skill-retarget` (from `main` @ d35a52b)
- Status: revision 1, after the analyze pass
  (`/home/eldan/.cache/claude-tmp/claude-1000/-home-eldan-projects-web-bot-auth-skill/b6c82dcc-11ca-4f3f-ad39-f9681656b973/scratchpad/retarget-01-analyze.md`)
  and the user's reply "1a 2 rec 3rec" (spec, Clarifications 2026-11-12b).
  Approved by the user on 2026-11-12 ("A, rec, rec, approved", spec,
  Clarifications 2026-11-12c): line-limit option A, an ignored member keeps
  `unknown_operator`, README default. The pre-flight rulings R1-R24 are applied
  in the task text below (list at the end).
- Scope: 0.2.0 only. T4 (`@query-param`), T10 (`verify_all`) and T11
  (`accept_signature_header`) are deferred to 0.3.0 and keep their numbers so
  references stay stable (see "Deferred to 0.3.0").
- Executor: Claude agents (repo memory: "use Claude agents, not Codex"). One
  writing agent per task; `git status --short` after each task.

## Ground rules for every task

- Read `/home/eldan/.agents/skills/unit-testing/SKILL.md` before the first code
  task.
- TDD for every code task: write the listed failing tests first, run them, and
  confirm each fails **for the stated reason** (not an import error or typo).
  Then the minimal code, then the full suite, then refactor on green.
- Any test that passes on its first run: break the line it covers, see it fail,
  revert. Record the line broken in the task's commit message.
- After every task, from the worktree root, with `<scratch>` the executing
  session's scratchpad directory (never `/tmp`):
  - `cd web-bot-auth/scripts && uv run python -m unittest -v test_web_bot_auth 2>&1 | tee <scratch>/wba-T<n>.log; tail -3 <scratch>/wba-T<n>.log`
    (confirm "Ran N tests" with N non-zero and growing, and "OK");
  - `uv run python scripts/check_size.py`;
  - `wc -l web-bot-auth/scripts/web_bot_auth.py` against the task's ceiling in
    the line budget below. Over the ceiling: **stop and ask**; do not squeeze
    code and do not apply an unapproved cut.
- Functions ≤ 50 lines. New public names go into `__all__`. Every `.py` keeps
  its SPDX header. Python 3.9 compatible (CI matrix 3.9/3.11/3.13).
- A task that changes any vector outcome or the signer's output regenerates
  `assets/test-vectors.json` with
  `cd web-bot-auth/scripts && uv run python generate_vectors.py > ../assets/test-vectors.json`,
  so `test_vectors_file_is_current` stays green, **and reviews the diff of
  the regenerated file** (`git diff --stat` plus a read of every changed
  `expected` block); the commit message states which outcomes changed and why.
  New vector cases wait for T12.
- Docstrings and comments of code a task touches are updated in that task
  (FR-018); `SKILL.md`/`references/` wait for T13, except the two files T1
  edits when it moves content out of the code (stated exception, T1 step 0 and
  step 3: `references/nonce-stores.md`, `references/policy-decisions.md` s6).
- Check every quoted spec fact against the -01 text (repo `AGENTS.md`).
- Commit per task on `feat/retarget-httpsig-01`; never `--no-verify`; do not
  push until the user approves (and see T14 for the rebase).
- Code search: the codebase-memory graph is the first tool when it is up; it was
  down while this plan was written, so the line numbers below come from a direct
  read of `main` @ d35a52b.

## Parallelism

Every code task (T1–T9) edits `web_bot_auth.py` and `test_web_bot_auth.py`, so
they run strictly in order. T12 (`generate_vectors.py`, `assets/`,
`test_web_bot_auth.py` class `Vectors` only) and T13 (`SKILL.md`,
`references/`) share no files, but they run in one worktree and the rule is
never two writers in one worktree: run them **serially**, T12 then T13, and T13
only after T9 (it documents T7/T8/T9's final names). `[P]` is kept only to mean
"no shared files"; parallel runs would need separate worktrees. T14 and T15 run
last, in that order.

## Line budget for `web-bot-auth/scripts/web_bot_auth.py`

Start: 1,017 lines. The analyze pass judged the revision 0 estimate (1,096) to
be 35–45 lines low. Revision 1 re-estimates every task from the code shape and
measures the largest one: §3.1 plus `_directory_entry` was written as a
throwaway prototype in the scratchpad (`proto/norm.py`, not in the repo) and
is 77 lines. Other numbers are estimates, ±5 per task unless noted.

| Task | Change | Est. delta |
|---|---|---|
| T1 | split `_verify` into 5 helpers (+20: def line, blank line and a 2-line call site each); collapse 7 three-line banners (−14); shorten the `KeyResolver` comment and `directory_unavailable` docstring to a 2-line contract summary each, rest to `references/policy-decisions.md` §6 (−6); then move `RedisNonceStore` out (−13) and its `__all__` entry (−1) | −14 |
| T2 | tests only | 0 |
| T3 | `@target-uri` condition | +1 |
| T5 | `parse_directory` shape check | +2 |
| T6 | `TEST_KEY_THUMBPRINTS` (4 keys, +7), `max_keys` (+2), skip (+2), static-config raise (+3), constructor pass-through (+2), "known test key rejected" reason (+1), `__all__` entry (+1) | +18 |
| T7 | `_agent_member` with rule 3 ignore (+5 net), `_sign` extraction (+4), drop `agent_as_dictionary` (−5), `agent` check (+1), component checks incl. `@authority`/`@target-uri` (+4) | +9 |
| T8 | §3.1 normalizer and `_directory_entry` (+77, measured), `_Allowlist` set subclass overriding `add`, `update` and `__ior__` (+12), `Result.claimed_agent` (+1), attribution handling (+4), docstrings (+2), `__all__` entry for `normalize_agent_url` (+1), delete `normalize_origin` and `directory_url` (−17) | +80 (±10) |
| T9 | per-source pools (+1), `fetched` branch (+3), fallback with removal-wins check (+8), `operator=None` path (+2), `ResolvedKey.attributed` field (+1) | +15 |
| T12–T15 | docstrings only | 0 |

**Projected final: about 1,142 (±15) before the `RedisNonceStore` move, about
1,128 after it.** Option A (the user's answer, spec Clarifications 2026-11-12c)
raises the limit to 1,150, so the margin is about 22. The 0.3.0 split
(decision 1a) removed about 40 lines of revision 0 scope, but fully specifying
§3.1 (A2), the allowlist guard (U5), removal wins (U1) and two more denylisted
keys (U3) added about 45, and the old normalizer estimate was about 30 low.
`__all__` changes are counted: `RedisNonceStore` removed (T1, −1),
`TEST_KEY_THUMBPRINTS` (T6, +1), `normalize_agent_url` (T8, +1).

Ceilings (stop and ask when `wc -l` exceeds one):

| Task | Projected / ceiling (limit 1,150) |
|---|---|
| T1 | 1,003 / 1,010 |
| T2 | 1,003 / 1,010 |
| T3 | 1,004 / 1,012 |
| T5 | 1,006 / 1,016 |
| T6 | 1,024 / 1,035 |
| T7 | 1,033 / 1,046 |
| T8 | 1,113 / 1,128 |
| T9 | 1,128 / 1,140 |
| T12–T15 | 1,128 / **1,130** (these tasks add docstrings only; a ceiling equal to the limit would never trigger the stop) |
| **Final** | **about 1,128, margin about 22** |

The first commit of T1 raises `FILE_LIMIT_OVERRIDES` in `scripts/check_size.py`
and the repo `AGENTS.md` size-limit paragraph from 1,100 to 1,150 (user
approval: Clarifications 2026-11-12c; it changes the project constitution), with
`scripts/test_check_size.py` updated first (T1 step 0). There is no other
option: options B and C were dropped by the user's answer.

## Tasks

### T1 — Split `Verifier._verify` by responsibility (FR-020)

Refactor on green; behaviour unchanged, except that the public name
`RedisNonceStore` is removed (own commit, step 0c).

0. Line limit and `RedisNonceStore` (three commits):
   a. Edit `scripts/test_check_size.py` first: the vendored-file tests become
      1,150 passes and 1,151 fails (they were 1,100 and 1,101; CI runs this
      file, so it cannot stay as is). Run them and confirm red for the stated
      reason: the new 1,150-passes test fails against the old
      `FILE_LIMIT_OVERRIDES` (1,100). Then change `FILE_LIMIT_OVERRIDES` to 1,150
      in `scripts/check_size.py` and the size-limit paragraph in the repo
      `AGENTS.md` (1,100 to 1,150). Run `cd scripts && uv run python -m unittest
      -v test_check_size` and `uv run python scripts/check_size.py`. Commit 1.
   b. Move `RedisNonceStore` (the class) into `references/nonce-stores.md` as a
      copy-paste snippet, and change the table row that says "Use the included
      `RedisNonceStore`" to point at the snippet (stated exception to "docs wait
      for T13": content moved out of code must not be lost and the row would
      otherwise name a deleted symbol). Commit 2 (docs).
   c. Remove the class and its `__all__` entry from `web_bot_auth.py` and any
      other mention in `SKILL.md`/`references/`. Commit 3, message "remove public
      name RedisNonceStore (CHANGELOG Breaking in T15)". This is not a
      behaviour-neutral refactor and is kept out of the split commit.
1. Characterization first: the current 84 tests are the safety net. Run them
   and save the count.
2. Extract from `_verify` (lines 819–931), each ≤ 50 lines. Helper return
   convention: a helper returns a `Result` to stop verification and `None` to
   continue (`_select` returns its tuple, or a `Result` for an early stop):
   - `_select(req)` → `(label, covered, signature)` or an early `Result`
     (header presence, parse, first `web-bot-auth` label).
   - `_check_params(covered, res)` (keyid, created/expires types, alg, nonce
     type).
   - `_check_times(created, expires, now, res)` (future, ordering, lifetime,
     expiry/age).
   - `_identity(req, covered, label, res)`: the first statements are the
     `@authority` coverage rule (T3 turns it into `@authority` or
     `@target-uri`), then the Signature-Agent logic that yields the claim. T3,
     T7 and T8 grow it and the spec (§3.9) names this function.
   - `_check_nonce(req, keyid, nonce, created, expires, now, res)`.
   - `_verify` keeps orchestration, digest, key resolution, crypto and binding.
3. Collapse the seven `# ----` banner blocks to one line each
   (`# --- RFC 8941 structured fields (subset) ---`). Shorten the `KeyResolver`
   comment (lines 546–549) and the `directory_unavailable` docstring (lines
   655–660) to a 2-line contract summary each, kept in the file (analyze U9);
   the full text goes to `references/policy-decisions.md` §6 (second stated
   exception to "docs wait for T13").
4. Break-the-line check: for each extracted helper, break one line (e.g. flip
   `created > now + p.clock_skew`), confirm a named test fails, revert.
5. Remove `"web_bot_auth.py::Verifier._verify"` from `scripts/size_baseline.json`
   (leaving `{}`); run the size gate.

Done when: 84/84 pass, `test_check_size` passes, size gate passes with an empty
baseline, `wc -l` ≤ the T1 ceiling (1,010).

### T2 — -01 Appendix E conformance tests (FR-016, SC-001)

Tests only, in a new `ConformanceDraft01(unittest.TestCase)` next to
`Conformance`:

- `test_e21_dictionary_agent_verifies` and `test_e22_legacy_string_verifies`:
  the literal headers from -01 E.2.1/E.2.2 (unwrapped per RFC 8792), request
  `GET https://example.com/` with `Host: example.com`, key
  `{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}`
  under `https://signature-agent.test`,
  `Policy(max_age=10**10, max_lifetime=None)`, clock 1735689600. Expect
  VERIFIED and operator `https://signature-agent.test` (T8 changes this to the
  trailing-slash form; T6 adds `allow_test_keys=True`).
- `test_e1_rsa_vectors_are_unsupported`: E.1.1 and E.1.2 headers → INVALID
  (documents scope). Before writing it, read the -01 E.1.1/E.1.2 headers
  (the plan has not probed them): `_verify` checks keyid and integer
  created/expires before `alg`. If `created`, `expires`, `keyid` or the tag
  differ in a way that changes the first failing check, assert the real reason
  and record it in the commit message; if the shape is as assumed, the reason is
  `unsupported alg 'rsa-pss-sha512'`.
- `test_e23_content_digest_matches_body`: `content_digest_matches` on the E.2.3
  `Content-Digest` and the exact body bytes → True; one changed byte → False.

Define the E.2.1/E.2.2 headers as module-level constants (T6's
`test_e21_rejected_by_default` reuses them instead of copying). Save the
84-test baseline count (T1 also uses it). All four are expected to pass first
time (probe in spec §1). Break-the-line:
for E.2.1, make the dictionary branch of `_agent_url` return None; for E.2.2,
make the legacy branch fall through; for E.1, accept any `alg`; for E.2.3,
return True early in `content_digest_matches`. Revert each.

### T3 — Accept `@target-uri` instead of `@authority` (FR-001)

Failing tests first (class `Accepts`/`Rejects`):

- `test_target_uri_without_authority_verifies`: components
  `("@method", "@target-uri", "signature-agent")` → VERIFIED and
  `binds_request` True for a query-less GET. Fails today with INVALID
  "@authority must be covered".
- `test_neither_authority_nor_target_uri_is_invalid` (class `Rejects`): request
  built with `sign_request` now (T7 re-specs it to `_sign`, because `sign_request`
  then raises `ValueError` for exactly these components), components
  `("@method", "@path", "signature-agent")` → INVALID with reason
  "@authority or @target-uri must be covered". Fails today on the reason text.
- `test_target_uri_host_swap_is_invalid`: re-target the request to
  `https://other.example/items/42` → INVALID (signature does not verify).
  Likely passes first: break-the-line by making `_derived("@target-uri")`
  return a constant.

Code: one condition in `_identity`, among its first statements (the
`@authority`/`@target-uri` coverage check precedes the Signature-Agent logic;
T1 pins this placement). Ceiling per the budget table.

### T4 — `@query-param` (FR-002) — deferred to 0.3.0

Not on this branch. See "Deferred to 0.3.0".

### T5 — Non-JWKS 200 must not evict the cache (FR-009)

Failing tests first (class `DirectoryRefetch`):

- `test_non_jwks_refresh_keeps_cached_keys`: warm the cache with a 300 s TTL,
  move the clock past expiry and the refetch interval, make `fetch` return each
  of `b'{}'`, `b'{"keys": {}}'`, `b'{"error": "x"}'`, `b'[]'`, `b'"x"'`,
  `b'null'`, `b'{"keys": null}'`, `b'{"keys": "x"}'` (subTest each, fresh
  resolver per case; the last three distinguish the shape check
  `isinstance(doc.get("keys"), list)` from a truthiness check). Expect `resolve`
  still returns the original key, trusted, from the stale copy. The first three
  fail today (the cache is replaced by `{}`). `b'[]'`, `b'"x"'` and `b'null'`
  **pass today**, because `doc.get` raises `AttributeError`, which `resolve`
  already swallows: for them, break-the-line (make `resolve`'s `except`
  re-raise) and record it. Run all eight and record which pass first; any other
  case that passes first gets the same break-the-line step.
- `test_valid_directory_without_key_evicts`: refresh returns `{"keys": []}` →
  key no longer resolves (state transition "evidence", -01 §6.10). Likely
  passes first: break by skipping the cache write in `_refresh`.
- `test_parse_directory_rejects_non_jwks`: `parse_directory` raises
  `ValueError` for the eight bodies above and for invalid JSON; returns `{}` for
  `{"keys": []}`. Fails today for the bodies that return `{}` and for
  `[]`/`"x"`/`null` (they raise `AttributeError`, not `ValueError`).
- `test_static_resolver_rejects_non_jwks`: `StaticKeyResolver({AGENT: {}})`
  raises `ValueError`.
- Error category: `fetch` raising `TimeoutError` while warm keeps the key
  (already true; break-the-line check on the `except` in `resolve`).

Code: two lines at the top of `parse_directory` (shape check first; T6 then adds
the count check and the test-key filter after it, in that order).

### T6 — `max_keys` and test-key denylist (FR-010, FR-011)

Failing tests first:

- `test_directory_with_too_many_keys_is_a_discovery_failure`: 65 entries →
  `ValueError`; 64 → parsed; via `DirectoryKeyResolver(max_keys=64)` a warm
  cache survives a 65-key refresh. Fails today: no limit.
- `test_test_key_thumbprints_are_the_four_known_keys`: the constant equals the
  four thumbprints in spec §3.6, and each equals `jwk_thumbprint` of the
  listed `x` (and of `public_jwk(generate_vectors.KEY/OTHER)`).
- `test_rfc9421_test_key_dropped_from_directory`: an allowlisted directory
  serving the B.1.4 key → a request signed with it is INVALID "known test key
  rejected"; with `allow_test_keys=True` → VERIFIED. Repeat for the RFC 8037
  A.1 key (signing with its published `d`). Fails today: VERIFIED.
- `test_test_key_rejected_in_static_config`: `StaticKeyResolver` raises
  `ValueError` mentioning the thumbprint, for each of the four keys;
  `allow_test_keys=True` accepts it.
- `test_add_untrusted_directory_drops_test_keys`: `add_untrusted_directory(AGENT,
  jwks_with_B14_key, now=NOW)` on a default resolver, then a request signed with
  that key naming `AGENT` is not SIGNED_UNTRUSTED and not VERIFIED (INVALID
  "known test key rejected" or the resolver's no-key outcome, whichever the
  code gives; assert the exact one observed and that it is not an accept); with
  `DirectoryKeyResolver(allow_test_keys=True)` the same call yields
  SIGNED_UNTRUSTED.
- Boundary: 0 keys; exactly 64; non-Ed25519 entries count toward the limit.
- Update T2's E.2 tests to pass `allow_test_keys=True`, and add
  `test_e21_rejected_by_default` (SC-001 second half; reuse T2's header
  constants, do not copy them): a
  `DirectoryKeyResolver` whose fake fetch serves the B.1.4 key → INVALID
  "known test key rejected".
- `generate_vectors.build` passes `allow_test_keys=True` (its `KEY` is now
  denylisted); the vectors' `description` says ports must do the same.

Code: `TEST_KEY_THUMBPRINTS` (exported), `parse_directory(data, max_keys=64,
allow_test_keys=False)`, constructor parameters on both resolvers, the reason
text in `_resolve_key` (analyze U7). The reason fires in `_resolve_key`
without knowing the resolver's flag, so with `allow_test_keys=True` an
unknown test key gets a misleading reason; the spec accepts this (outcome
unchanged) and T13 documents it. `add_untrusted_directory` and `_refresh` call
`parse_directory(data, self.max_keys, self.allow_test_keys)` (T9's pool storage
keeps that call, otherwise this task's `add_untrusted_directory` test regresses).
Add `TEST_KEY_THUMBPRINTS` to `__all__`. Regenerate vectors (description only).

### T7 — Member selection, ignored members, conformant signer (FR-003, FR-004, FR-013)

Failing tests first:

- Member selection (spec §3.4): two covered members `browser` and `agent`, in
  both header orders and both coverage orders → each label resolves its own
  member (fails today: first covered component wins); bare `"signature-agent"`
  over a dictionary with member `sig1` → that member; bare over a dictionary
  without `sig1` → INVALID (fails today: single-member fallback); legacy string
  still VERIFIED.
- Rule 3, ignored mismatch (spec scenario 7): label `sig2` covering only
  `"signature-agent";key="agent2"` with `Signature-Agent:
  agent2="https://agent.example"` → not INVALID; `operator` None;
  UNKNOWN_OPERATOR "no key for this operator" with
  `StaticKeyResolver({AGENT: ...})`; VERIFIED with
  `StaticKeyResolver({None: ...})` (the no-URL path, same as a request without
  the header). Fails today: VERIFIED as AGENT. Also: a relabeled copy of a
  valid `agent2` signature (rename the `Signature`/`Signature-Input` members
  to `sig2`) gives the same result. These tests assert only outcome, reason and
  `operator is None`: `Result.claimed_agent` does not exist until T8, so every
  `claimed_agent is None` assertion for rule 3 and the ignored-parameter cases
  moves to T8 (where the field is created).
- Ignored parameters: `sig1="https://agent.example";x=1` covered with key
  `sig1` → the same no-URL results as rule 3 (fails today: attributed to
  AGENT).
- Test construction: `sign_request` always covers `"signature-agent";key=<label>`
  and sends the dictionary form, so the multi-member, non-String, odd-header,
  parameterized-member and uncovered-header tests are built with `_sign` plus
  hand-written `Signature-Agent` headers.
- Spec scenario 7 against `DirectoryKeyResolver` is tested in T9 (R18).
- Signer: `sign_request(req, key)` without `agent` → `TypeError`;
  `agent="http://agent.example"` → `ValueError`; components without
  `"signature-agent"` → `ValueError`; components without `"@authority"` and
  `"@target-uri"` → `ValueError` (analyze I3); `("@target-uri",
  "signature-agent")` accepted; default output has
  `Signature-Agent: sig1="https://agent.example"` and covers
  `"signature-agent";key="sig1"`; `label="agent"` keys both by `agent`.
- `_sign(req, key, covered, label)` produces the -01 E.2.2 legacy bytes when
  given the B.1.4 private key, the E.2.2 parameters and nonce (Ed25519 is
  deterministic).

Until T8 exists, the `agent` check uses `normalize_origin` (it rejects `http`);
T8 switches it to `normalize_agent_url`.

Re-specified existing tests (record in the commit message, SC-008):
- `Accepts.test_draft05_dictionary_signature_agent` → renamed
  `test_dictionary_signature_agent_is_default`;
- `Rejects.test_uncovered_signature_agent`,
  `DirectorySecurity.test_missing_agent_with_empty_allowlist_does_not_fetch` and
  `Rejects.test_neither_authority_nor_target_uri_is_invalid` (T3's second test)
  build their requests with `_sign`;
- the legacy subcase of
  `DirectorySecurity.test_attacker_path_cannot_impersonate_cold_operator` uses
  `_sign`;
- `Rejects.test_signature_agent_swap`: the swap is made in dictionary form
  (`sig1="https://evil.example"`); a legacy-string swap on a `key="sig1"`
  covered component now fails in `signature_base`, still "not VERIFIED" but for
  the wrong reason;
- `DirectorySecurity.test_malformed_agent_does_not_fetch_or_change_state`: the
  header values become `sig1="http://agent.example"`, `sig1="not a URL"`,
  `sig1="https://agent.example:bad"` (so the scheme/URL checks are still
  exercised), and the structurally bad ones (not a dictionary) stay as separate
  cases built with `_sign`.
Fixtures: `Fixture.signed`, `DirectorySecurity.attack`, `generate_vectors.req`
drop `agent_as_dictionary`. `generate_vectors.cases`: `verified_dictionary_agent`
would now equal `verified_bound`, so it is changed to
`verified_custom_label` = `req(label="agent")` (a label-keyed member case; T12's
`EXPECTED` uses the new name) and adds nothing else yet. Regenerate vectors
(most change from legacy to dictionary form; review the diff).

Code: rewrite `_agent_url` as `_agent_member(header, covered, label)`
returning `(url_or_None, error_or_None)`; `_sign` extracted from
`sign_request`. `_agent_member` returns the raw URL and the `agent` check uses
`normalize_origin` until T8 swaps both.

### T8 — URL identity and allowlist semantics (FR-005, FR-006, FR-007, FR-008; SC-005)

Failing tests first (new class `AgentUrl`, then `DirectoryConfiguration`,
`DirectorySecurity`):

- `normalize_agent_url`: one subTest per row of the hand-written table and per
  rejected input in spec §3.1, literal expected values (fails today: name
  missing). Extra rows: the 2,048/2,049 boundary; ports 65535 and 65536;
  `:+443`; `[` in the query.
- `_directory_entry`: bare origin → well-known fetch URL (with and without a
  query); path entry keeps its normalized query; port kept in the well-known
  URL.
- Identity: spec §5 scenarios 1–3 (fail today: operator is the origin; path
  claim is attributed). `Result.claimed_agent` set on UNKNOWN_OPERATOR and
  INVALID; `Result.operator` None on both. Also the `claimed_agent is None`
  assertions for rule 3 and the ignored-parameter cases moved from T7.
- (URL, key) property: allowlist `[AGENT + "/a/keys.json"]`; a request naming
  `AGENT + "/b/keys.json"` signed with the `/a` key → UNKNOWN_OPERATOR, no fetch
  (fails today: VERIFIED as AGENT).
- Deviation and mismatch (analyze I2, scenario 13): allowlist `[AGENT]`; a
  request naming `AGENT + "/.well-known/http-message-signatures-directory"` →
  UNKNOWN_OPERATOR, no fetch; with both spellings allowlisted, both VERIFIED
  with their own `operator`, and two fetches of the same URL (accepted, U8).
- Test constants: `AGENT_ID = AGENT + "/"` and `NORMALIZATION_CASES` (the
  hand-written §3.1 table, input → identifier or `None`) at module level of
  `test_web_bot_auth.py`; `AgentUrl` subTests iterate `NORMALIZATION_CASES`
  (T12's test (c) reuses it).
- Un-signable claims (backslash, `[` in the query, over-long, fragment): build
  the request with `_sign` and a hand-written `Signature-Agent` header, because
  `sign_request(agent=...)` validates with `normalize_agent_url` and would raise
  `ValueError` before the verifier is tested.
- Allowlist: `[AGENT + "/a/keys.json", AGENT + "/b/keys.json"]` builds two
  identifiers with separate fetches; `[AGENT + "/k?v=1", AGENT + "/k?v=2"]`
  raises `ValueError` naming `https://agent.example/k` in any order.
- Runtime add (analyze U5, scenario 14): `allowlist.add("https://agent.example")`
  raises `ValueError` naming `https://agent.example/`;
  `allowlist.add("https://agent.example/")` works and fetches the well-known
  URL; `allowlist.discard` of that identifier revokes trust;
  `allowlist.update(["https://agent.example"])` and
  `allowlist |= {"https://agent.example"}` raise the same `ValueError` (the
  guard covers `add`, `update` and `__ior__`; other set operations are
  documented; assigning `resolver.allowlist = {...}` is documented as
  unsupported).
- Concurrency: two identifiers on one host, 8 threads each with a barrier on a
  cold cache → exactly one fetch attempt per identifier (pattern of
  `test_concurrent_cold_requests_share_one_fetch_attempt`); failures on one
  identifier do not rate-limit the other.
- Spelling collapse: `AGENT + "/a/../k"` and `AGENT + "/%6B"` claims resolve to
  the allowlisted `AGENT + "/k"`; `AGENT + "/K"` and `AGENT + "/k/"` do not;
  `AGENT + "/a\\k"` is INVALID.
- SC-005 (analyze C1): add `assertFetchedSubset(fetched, resolver)` and
  `assertNotMisattributed(result, resolver)` helpers, and call them in every
  `DirectorySecurity` test (existing and new). Definition of the second: if
  `result.operator` is not None then `result.keyid` is in the resolver's cached
  or static key set for that operator and that entry is attributed (T8 has no
  `attributed` flag yet, so it checks membership; T9 adds the flag check). Add a
  negative self-check test that the helper fails (`assertRaises
  (AssertionError)`) on a hand-built misattributed state, so SC-005 cannot pass
  vacuously.

Re-specified existing tests (expected outcome changes; cite -01 §4.4/§5.4/§5.5
in the commit, SC-008). The new contract is normalized identifiers: every direct
resolver call and set operation that takes an identifier (`resolve`,
`directory_unavailable`, `is_allowlisted`, `allowlist.add`/`discard`, `_cache`
and `_last_fetch` key assertions) in `DirectoryRefetch`, `DirectoryUnavailable`,
`DirectoryUnavailableFlag`, `ResolverExtensionPoints`, `DirectoryTrust` and
`DirectorySecurity` changes from `AGENT` to `AGENT_ID` (`discard(AGENT)` would
silently become a no-op and a revocation test would pass without revoking);
fetch-URL assertions stay raw. `DirectoryUnavailable.assert_unavailable` asserts
`operator is None` and `claimed_agent == AGENT_ID` (spec §3.3). Then the
specific tests:
`DirectoryConfiguration.test_configured_directory_path_and_query_override_request`
(the request names the configured identifier to verify; the mismatched claim
becomes the new UNKNOWN_OPERATOR test);
`test_origin_entries_use_normalized_well_known_location` (operator
`https://agent.example/`); `test_configured_root_query_uses_well_known_path`
(unchanged fetch; identifier `https://agent.example/`);
`test_conflicting_custom_directories_rejected_in_any_order` and
`test_origin_and_custom_directory_conflict_in_any_order` (no longer conflicts:
two identifiers; replaced by the query-conflict test above);
`test_identical_normalized_directories_are_allowed` (`allowlist ==
{"https://agent.example/"}`);
`test_runtime_added_normalized_origin_uses_well_known_directory` (adds
`"https://agent.example/"`; the 0.1.1 form now raises);
`test_invalid_directory_configuration_rejected` (same rejections via
`normalize_agent_url`);
`DirectorySecurity.test_attacker_path_cannot_impersonate_warm_operator` and
`..._cold_operator` (UNKNOWN_OPERATOR "no key for this operator", operator
None, still no fetch of the attacker path);
`test_request_paths_and_queries_do_not_change_configured_location` (a path
claim no longer verifies; a query-only difference still does; fetches
unchanged); `test_bad_signature_spam_is_bounded_for_allowlisted_origin`
(UNKNOWN_OPERATOR without fetch for the path claims; state sets keyed by
`https://agent.example/`); every `assertEqual(..operator, AGENT)` → the
trailing-slash form; T2's E.2 tests → `https://signature-agent.test/`; the
two existing `allowlist.add(AGENT)` calls → `AGENT + "/"`;
`DirectoryTrust.test_background_directory_stays_untrusted_and_expires` gets its
constants updated here (T9 rewrites it).
`StaticKeyResolver` and `generate_vectors.build`/`trusted_keys` key by
normalized identifiers (this task only; analyze D1). Regenerate vectors and
review the diff (operators gain `/`).

Code: `normalize_agent_url`, `_split_agent_url`, `_host_port`, `_pct`,
`_remove_dot_segments`, `_directory_entry`, `_Allowlist` (a `set` subclass
whose `add`, `update` and `__ior__` raise on non-normalized values; the last two
loop through `add`), `Result.claimed_agent`,
resolver re-keying, `_identity` uses
`normalize_agent_url`; rename `_directory_urls` → `_fetch_urls` (analyze I1);
delete `normalize_origin` and `directory_url` (update every caller; check the
repo for both names with the SC-006 command); add `normalize_agent_url` to
`__all__`. `ResolvedKey.attributed` is **not** added here (it has no consumer
until T9; moved to T9). Update `StaticKeyResolver`,
`DirectoryKeyResolver` and module docstrings, naming the bare-origin rule a
deviation.

### T9 — Redistributed keys carry no URL; removal wins (FR-014, FR-021; SC-005)

Failing tests first (class `DirectoryTrust`):

- Spec §5 scenario 9: `add_untrusted_directory(url, jwks, now=NOW)` → request
  naming `url` is SIGNED_UNTRUSTED, operator None, keyid set (fails today:
  operator is the URL).
- `fetched=True` → SIGNED_UNTRUSTED with operator the normalized URL.
- Unattributed keys verify for a request naming a non-allowlisted identifier
  or none, and never produce `trusted` or VERIFIED.
- **Removal wins** (FR-021, spec scenario 12): allowlisted identifier with a
  fresh directory that lacks K, plus a pool that holds K → INVALID "unknown
  keyid for allowlisted operator". Red-first is impossible here: no pools exist
  on current code, so this test **passes before the fallback**. Steps: write the
  test and confirm it passes on current code; implement the fallback with the
  `directory_unavailable` guard; break the guard line (make the fallback ignore
  it), confirm this named test fails; revert. Same
  identifier, cold cache and failing fetch → SIGNED_UNTRUSTED, operator None.
  Same identifier, warm cache past its TTL with the refetch rate-limited →
  SIGNED_UNTRUSTED (directory unavailable). State transition: fresh directory
  with K → refresh without K → INVALID even though the pool holds K.
- Re-adding the same source replaces its keys (old key stops resolving); a
  second source keeps both; each expires at its own `ttl` (boundary
  `NOW + ttl` exclusive, as today).
- Allowlisted identifier → `ValueError` for both `fetched` values.
- Concurrency: one thread re-adding a source while 8 threads resolve → every
  resolve sees either the old or the new key set, never a mixed or missing one
  (barrier, no sleeps).
- Custom resolver forcing: a resolver returning
  `ResolvedKey(key, True, attributed=False)` gives SIGNED_UNTRUSTED with
  `operator` None (spec §3.3: `attributed` False forces trusted False and
  operator None). The test fails before `ResolvedKey.attributed` exists.
- Spec scenario 7 against the real resolver (R18): an allowlisted directory
  holds the key, the request's member is ignored (key differs from the label) →
  `DirectoryKeyResolver` gives UNKNOWN_OPERATOR "no key for this operator",
  `operator` and `claimed_agent` None, zero fetches.
- SC-005 helpers from T8 in every test of this class; extend
  `assertNotMisattributed` with the `attributed` flag check.
- Existing `test_background_directory_stays_untrusted_and_expires` is
  re-specified (operator None unless `fetched=True`; SC-008); T8 only updated its
  constants, this task rewrites it.

Code: unattributed pools in `DirectoryKeyResolver` under the existing lock,
keyed by the normalized source URL; `add_untrusted_directory(url, jwks, ...)`
(its first parameter `operator` is renamed `url`: breaking, listed in T15) stores
via `parse_directory(data, self.max_keys, self.allow_test_keys)` so T6's
test-key filter still applies; fallback in `resolve` guarded by
`directory_unavailable` (it reads the cache in a second lock acquisition; the
benign race is documented in a comment); new field
`ResolvedKey.attributed` (default True) and its forcing in `_verify`; add it to
the docstring contract.

### T10 — `verify_all` (FR-012) — deferred to 0.3.0

### T11 — `accept_signature_header` (FR-015) — deferred to 0.3.0

### T12 [P: no shared files; run serially, before T13] — Regenerate and extend vectors (FR-017, SC-004)

Files: `web-bot-auth/scripts/generate_vectors.py`,
`web-bot-auth/assets/test-vectors.json`, and class `Vectors` in
`web-bot-auth/scripts/test_web_bot_auth.py` (analyze I5; T13 does not touch
it).

- Test first: extend `Vectors` with (a) exactly one vector's
  `Signature-Agent` header is a bare sf-string; (b) a **hand-written** table
  `EXPECTED = {name: (outcome, operator, claimed_agent)}` for every vector,
  asserted against a fresh `Verifier` run for every vector and against the JSON
  fields only where present (`claimed_agent` is in the JSON for accepted
  outcomes only), independently of `build()` (analyze U4); it uses the T7 name
  `verified_custom_label`; (c) the JSON `normalization` section equals the test
  constant `NORMALIZATION_CASES` (T8) and `normalize_agent_url` reproduces it.
  `generate_vectors.py` carries its own literal copy of the table, emitted
  verbatim and not computed from the implementation (two intentional copies:
  the test constant and the generator literal; the equality test catches
  drift). Fails until the cases and section exist.
- Add cases: `verified_target_uri_only`, `verified_legacy_string_agent` (the
  only legacy one, via `_sign`), `ignored_parameterized_member`,
  `ignored_member_key_not_label`, `unknown_operator_path_mismatch`,
  `verified_query_ignored_in_identifier`. No vector for FR-021 (the format has
  no pools; it is unit-tested in T9) and no `invalid_test_key_rejected` vector
  (a key absent from `trusted_keys` gives INVALID with or without a denylist and
  vectors carry no reason, so it proves nothing; `invalid_wrong_key` covers
  plain INVALID and T6 unit-tests the denylist).
- Add the `normalization` section (input → identifier, or `null` for reject).
- `expected.operator` and `expected.claimed_agent` on accepted outcomes;
  `description` and the module docstring say operators are normalized URLs,
  that ports must pass `allow_test_keys=True`, and that the `normalization`
  section is the cross-language identity contract.
- Review the full diff of `test-vectors.json` before committing.

### T13 [P: no shared files; run serially, after T9 and T12] — Skill docs (FR-018)

Files: `web-bot-auth/SKILL.md`, `web-bot-auth/references/policy-decisions.md`,
`references/adapters.md`, `references/nonce-stores.md`. Docs only; no tests.
Starts after T9 and T12 (it documents the final names of T7/T8/T9); T1 already
edited `nonce-stores.md` (Redis snippet and table row) and `policy-decisions.md`
§6, so read their current text first.

- `SKILL.md`: spec status (-01, a WG draft); outcomes table with -01 App. C.1
  vocabulary (status-code guidance waits for 0.3.0); Rules bullet on
  allowlist identifiers (full URLs, the bare-origin rule **as a deviation from
  -01 §4.1/§4.4**, allowlist both `https://host` and
  `https://host/.well-known/http-message-signatures-directory` when an agent
  may send either; path claims not attributed; `allowlist.add` takes
  normalized identifiers); logging fields (`operator`, `claimed_agent`,
  `keyid` as the no-URL identifier).
- `policy-decisions.md`: rewrite §1 directory paragraph and "Draft scope"
  (cite -01 §4.1, §4.4, §5.4, §5.5, §5.5.3, §6.6.1); replace "Not implemented:
  verifying the directory response's own signature" with the -01 App. B
  position; `fetched=True` guidance for background jobs; removal wins over
  third-party lists; §2 `@authority` or `@target-uri`; §3 `min_nonce_length`
  is local policy (-01 §5.2.3); §4 cite -01 §5.2; test-key denylist (the four
  keys, "not exhaustive") and `max_keys`; ignored relabeled members; the
  custom-resolver contract (identifiers, `attributed`); the test-key reason
  caveat (T6: with `allow_test_keys=True` an unknown test key can carry the
  "known test key rejected" reason, outcome unchanged); the ceiling and
  line-limit wording is "1,150" where the limit is mentioned.
- `adapters.md`: refuse signature headers over plain http (-01 §6.1).
- `nonce-stores.md`: cite RFC 9421 §7.2.2 and -01 App. C.6 (the
  `RedisNonceStore` snippet and table row arrived in T1; keep them).
- Check SC-006 with the `rg` command in the spec.

### T14 — README (FR-018)

At task start run `git branch --merged main` and check whether `docs/readme` is
in it. Today it is not merged, so only T14a runs, and T15 adds the "README
quick-start update pending" lines and the follow-up issue (user default,
Clarifications 2026-11-12c).

- **T14a (always, in this PR):** on `main`'s README, replace the line-28
  spec-status sentence (architecture-05) with the -01 target and a pointer to
  the CHANGELOG. One line; no test.
- **T14b (only if `docs/readme` @ 62de1d4 merged first):** `git rebase main`
  before this branch's first push (no force-push needed), then update README
  line 14 (cite -01 §1), line 16 (header required, URL fetched directly,
  well-known as one case), lines 105/113 (drop `agent_as_dictionary=True`,
  which raises `TypeError` in 0.2.0), line 139 (identifier semantics), lines
  141–146 (spec status: target -01).
- **If T14b is skipped** (analyze I4): the 0.2.0 CHANGELOG entry and PR body
  say "README quick-start update pending", and a follow-up issue records that
  `docs/readme` must drop `agent_as_dictionary=True` and retarget lines 14 and
  145–146 before it merges.

### T15 — Release 0.2.0 (FR-019, SC-007, SC-008)

- `CHANGELOG.md` `## 0.2.0`, with the current `Unreleased` uv entry folded in:
  - **Security:** identity was the origin, so keys and signatures were
    attributed to the host operator for any path on that host, and two tenants
    on one host could not be told apart (-01 §5.5: "TLS authenticates the host
    but not the path"); keys from third-party lists were attributed to a URL
    (-01 §5.5.3), and they never override a removal by an allowlisted
    identifier's own fresh directory (FR-021); a 200 non-JWKS response evicted
    good keys (-01 §6.10); known test keys are rejected (-01 §6.8).
  - **Breaking:** identifier is the normalized Signature-Agent URL;
    `Result.operator` values (trailing `/`, path) and set only when attributed;
    new `Result.claimed_agent`; allowlist entries on one host are separate
    identifiers; the bare-origin rule is a deviation and an agent sending the
    explicit well-known URL needs its own entry (allowlist both);
    `allowlist.add` raises unless given a normalized identifier; custom
    resolvers' `resolve`, `is_allowlisted` and `directory_unavailable` receive
    normalized identifiers, and `ResolvedKey.attributed` is new (analyze U11);
    `normalize_origin`, `directory_url`, `agent_as_dictionary` and
    `RedisNonceStore` (now a snippet in `references/nonce-stores.md`) removed; `sign_request` requires
    `agent`, covers `@authority` or `@target-uri`, and always sends the
    dictionary form; a covered member whose key differs from the label is
    ignored; `add_untrusted_directory` attributes only with `fetched=True` and
    its first parameter `operator` is renamed `url`; `Result.operator` is None
    whenever the request is not attributed;
    test keys rejected by default; `parse_directory` raises on non-JWKS and on
    more than 64 keys.
  - **Added:** `@target-uri` without `@authority`, `normalize_agent_url`,
    `TEST_KEY_THUMBPRINTS`, -01 Appendix E tests, the `normalization` vectors.
  - **Pending:** "README quick-start update pending", if T14b was skipped (it
    is skipped unless `docs/readme` merged first); also file the follow-up issue
    that `docs/readme` must drop `agent_as_dictionary=True` and retarget lines
    14 and 145–146 before it merges.
- `pyproject.toml` `version = "0.2.0"` (it is 0.1.0 today although the CHANGELOG
  already has 0.1.1, so the bump is 0.1.0 → 0.2.0); `uv lock`; `uv sync --locked`.
- PR body: the SC-008 list collected from the T3, T5–T9 commit messages (T3's
  reason text, T7's re-specified tests, T8's re-specified tests), including
  the two revision-0 behaviours that changed (rule 3 ignore, removal wins); the
  0.3.0 deferred list.
- Final gates: full suite (count quoted), size gate, `wc -l` (≤ 1,150, the
  settled limit; expected about 1,128), SC-006 `rg`, `git status --short`.
- PR review: one Opus review with `~/.agents/templates/review-spec-coverage.md`
  pasted; unmet FR/SC become follow-up issues.

## Deferred to 0.3.0

Not implemented on this branch (spec §9). A later plan writes the tasks; these
notes carry the analyze findings forward.

| Old task | FR | Carry-forward notes |
|---|---|---|
| T4 `@query-param` | FR-002 | U6: `parse_qsl` splits on `;` on Python 3.9.0–3.9.1; split on `&` by hand or require 3.9.2+. Vector `verified_query_param`. |
| T10 `verify_all` | FR-012 | U10: `verify()` then `verify_all()` on one request reports REPLAY; document or share the per-label path. Scenario 6; vector `two_signatures`. |
| T11 `accept_signature_header` + docs | FR-015 | I3: raise unless `@authority` or `@target-uri` is in the components (no empty-components case). A3: 400 only for RFC 9421 §3.2 steps 1–3 parse failures. Scenario 11. |

## Edge-case coverage map (seven categories)

| Category | Tasks |
|---|---|
| Null/empty/zero | T5 (`{}`, empty `keys`), T6 (0 keys), T8 (empty string, empty path, empty port, port 0) |
| Boundaries | T6 (64/65), T8 (2,048/2,049, ports 443/8443/65535/65536), T9 (ttl edge) |
| Invalid data | T3, T5 (non-JWKS), T7 (member params, non-String, signer components), T8 (every §3.1 rejection, non-normalized `allowlist.add`) |
| Concurrency | T8 (two identifiers, barrier), T9 (re-add vs resolve) |
| Errors | T5 (fetch raises while warm), T9 (fetch fails cold while a pool holds the key) |
| State transitions | T5 (warm → failed → warm; warm → evidence → evicted), T8 (runtime add/remove), T9 (replace, expire, fresh-with-K → fresh-without-K with pool) |
| Security | T7 (relabeled member not attributed), T8 (path claim, no fetch, spelling collapse, backslash), T6 (test keys), T9 (removal wins) |

## Analyze findings disposition

| ID | Sev. | Disposition |
|---|---|---|
| A1 | HIGH | Fixed in part: scope split (decision 1a), budget re-estimated with a measured prototype ("Line budget"); the projection is still over 1,100, so the limit question was the spec's second open marker; answered (option A, Clarifications 2026-11-12c). |
| U1 | HIGH | Fixed: removal wins (decision 2), spec §3.7, FR-021, scenario 12, T9 failing tests, CHANGELOG Security, SC-008 note. |
| I1 | MED | Fixed both ways: SC-006 uses `\b`, and T8 renames `_directory_urls` → `_fetch_urls`. |
| U2 | MED | Fixed: mismatched member key is ignored (decision 3), spec §3.4 rule 3 cites -01 §6.6.1 and RFC 9421 §7.2.5, FR-003, scenario 7, T7 tests. The no-URL outcome was the spec's third open marker; answered: stays `unknown_operator` (Clarifications 2026-11-12c). |
| I2 | MED | Fixed: spec §3.2 labels the bare-origin rule a deviation from -01 §4.1/§4.4 with rationale; mismatch documented (scenario 13, T8 test, T13 docs, T15 CHANGELOG). |
| U3 | MED | Fixed: four keys, thumbprints computed with the repo's `jwk_thumbprint` (spec §3.6 table), T6 tests, vectors pass `allow_test_keys=True`. |
| A2 | MED | Fixed: spec §3.1 rules 1–11 (character set incl. backslash, port grammar, host decoding and case, trailing slash, userinfo/fragment), hand-written table, T8 subTests. |
| I3 | MED | Fixed for the signer (spec §3.8, FR-013, T7). For `accept_signature_header`: deferred with the helper (spec §9). |
| C1 | MED | Fixed: SC-005 cited by T8 and T9, assertion helpers used by every `DirectorySecurity`/`DirectoryTrust` test. |
| U4 | MED | Fixed: hand-written expectation table and `normalization` section (FR-017, T12); diff review of every regenerated vectors file (ground rules, T6–T8). |
| U5 | MED | Fixed: `allowlist.add` raises on non-normalized values (spec §3.2, FR-008, scenario 14, T8, CHANGELOG). |
| I4 | MED | Fixed: T14a always fixes `main`'s README line 28; T14b conditional; if skipped, CHANGELOG/PR say so and a follow-up records the `agent_as_dictionary=True` break on `docs/readme` (also spec §8). Sequencing was the first open marker; answered: default applies (Clarifications 2026-11-12c). |
| I5 | LOW | Fixed: T12 lists the test file (`Vectors` class only). |
| I6 | LOW | Fixed: T5 says `[]`/`"x"` pass today and gives their break-the-line step. |
| U6 | LOW | Not applicable to 0.2.0 (`parse_qsl` only arrives with `@query-param`); carried to the 0.3.0 table. |
| U7 | LOW | Fixed: reason "known test key rejected" (spec §3.6, T6). |
| A3 | LOW | Deferred with the status-code guidance; note carried to the 0.3.0 table. |
| I7 | LOW | Fixed: logs go to the session scratchpad (ground rules). |
| U8 | LOW | Accepted and documented: no fetch coalescing; two spellings fetch twice (spec §3.2, T8 test). |
| U9 | LOW | Fixed: T1 keeps a 2-line contract summary in the file. |
| U10 | LOW | Deferred with `verify_all`; note carried to the 0.3.0 table. |
| U11 | LOW | Fixed: custom-resolver contract in spec §3.3 and the T15 Breaking list. |
| D1 | LOW | Fixed: re-keying of `trusted_keys`/`build` is in T8 only; T12 no longer lists it. |
| A4 | LOW | No change needed (analyze: none beyond A1). |

## Pre-flight rulings applied

All of R1–R24 (R16 and R21 unused) were adopted from the pre-flight scan
(ledger `.superpowers/sdd/2026-11-12-retarget-httpsig-01/progress.md`) and are
applied in the task text above.

| Ruling | Applied in |
|---|---|
| R1 test_check_size first, then limit 1,150 | T1 step 0a; Line budget |
| R2 Option B deleted, T12–T15 ceiling 1,130, status line, markers resolved | Status; Line budget (ceilings); T1; spec Clarifications 2026-11-12c |
| R3 coverage check placed first in `_identity` | T1 step 2; T3 Code |
| R3a no `claimed_agent` assertions in T7 | T7 (rule 3); T8 (Identity) |
| R4 T7 re-spec list extended; `_sign` for hand-built headers | T7 (Test construction, Re-specified existing tests); T3 test 2 |
| R5 `AGENT_ID`, direct resolver calls rewritten | T8 (Test constants, Re-specified existing tests) |
| R6 `_Allowlist` guards `add`/`update`/`__ior__` | T8 (Runtime add, Code); Line budget |
| R7 `ResolvedKey.attributed` moved to T9 with a forcing test | T8 Code; T9 (Custom resolver forcing, Code); Line budget |
| R8 `assertNotMisattributed` defined plus self-check | T8 (SC-005); T9 |
| R9 removal-wins step order | T9 (Removal wins) |
| R10 `verified_custom_label` | T7 (Re-specified existing tests); T12 |
| R11 `invalid_test_key_rejected` dropped | T12 |
| R12 FR-017 without FR-021 | spec FR-017; T12 |
| R13 two copies of the normalization table | T8 (Test constants); T12 |
| R14 T12 then T13, serial; T13 after T9 | Parallelism; T12, T13 headers |
| R15 T1 doc exception; RedisNonceStore removal own commit | Ground rules; T1 step 0b/0c; T15 Breaking |
| R17 probe -01 E.1 headers | T2 |
| R18 scenario 7 against `DirectoryKeyResolver` | T7 (note); T9 |
| R19 `parse_directory` call kept in `add_untrusted_directory`/`_refresh` | T6 Code; T9 Code |
| R20 README check at T14 start | T14; T15 (Pending) |
| R22 un-signable claims via `_sign` | T8 (Test constants) |
| R23 extra non-JWKS bodies | T5 |
| R24 `__all__` counted in the budget | Line budget (T1, T6, T8 rows and note) |
