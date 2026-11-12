# Plan: retarget to draft-ietf-webbotauth-httpsig-protocol-01 (release 0.2.0)

- Spec: `docs/superpowers/specs/2026-11-12-retarget-httpsig-01-design.md`
  (revision 1)
- Branch / worktree: `feat/retarget-httpsig-01` at
  `/home/eldan/projects/web-bot-auth-skill-retarget` (from `main` @ d35a52b)
- Status: revision 1, after the analyze pass
  (`/home/eldan/.cache/claude-tmp/claude-1000/-home-eldan-projects-web-bot-auth-skill/b6c82dcc-11ca-4f3f-ad39-f9681656b973/scratchpad/retarget-01-analyze.md`)
  and the user's reply "1a 2 rec 3rec" (spec, Clarifications 2026-11-12b).
  Waiting for user approval; T1 cannot start until the line-limit marker in
  the spec is answered.
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
  (FR-018); `SKILL.md`/`references/` wait for T13.
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
`references/`) share no files and are `[P]`. T14 and T15 run last.

## Line budget for `web-bot-auth/scripts/web_bot_auth.py`

Start: 1,017 lines. The analyze pass judged the revision 0 estimate (1,096) to
be 35–45 lines low. Revision 1 re-estimates every task from the code shape and
measures the largest one: §3.1 plus `_directory_entry` was written as a
throwaway prototype in the scratchpad (`proto/norm.py`, not in the repo) and
is 77 lines. Other numbers are estimates, ±5 per task unless noted.

| Task | Change | Est. delta |
|---|---|---|
| T1 | split `_verify` into 5 helpers (+20: def line, blank line and a 2-line call site each); collapse 7 three-line banners (−14); shorten the `KeyResolver` comment and `directory_unavailable` docstring to a 2-line contract summary each, rest to `references/policy-decisions.md` §6 (−6) | 0 |
| T2 | tests only | 0 |
| T3 | `@target-uri` condition | +1 |
| T5 | `parse_directory` shape check | +2 |
| T6 | `TEST_KEY_THUMBPRINTS` (4 keys, +7), `max_keys` (+2), skip (+2), static-config raise (+3), constructor pass-through (+2), "known test key rejected" reason (+1) | +17 |
| T7 | `_agent_member` with rule 3 ignore (+5 net), `_sign` extraction (+4), drop `agent_as_dictionary` (−5), `agent` check (+1), component checks incl. `@authority`/`@target-uri` (+4) | +9 |
| T8 | §3.1 normalizer and `_directory_entry` (+77, measured), `_Allowlist` set subclass (+8), two fields (+2), attribution handling (+4), docstrings (+2), delete `normalize_origin` and `directory_url` (−17) | +76 (±10) |
| T9 | per-source pools (+1), `fetched` branch (+3), fallback with removal-wins check (+8), `operator=None` path (+2) | +14 |
| T12–T15 | docstrings only | 0 |

**Projected final with no cuts: about 1,136 (±15), 36 over 1,100.** The
0.3.0 split (decision 1a) removed about 40 lines of revision 0 scope, but
fully specifying §3.1 (A2), the allowlist guard (U5), removal wins (U1) and two
more denylisted keys (U3) added about 45, and the old normalizer estimate was
about 30 low. So the spec's second open marker must be answered before T1.

Ceilings (stop and ask when `wc -l` exceeds one):

| Task | Option A (limit 1,150; `RedisNonceStore` moved in T1) projected / ceiling | Option B (limit 1,100; three cuts) projected / ceiling |
|---|---|---|
| T1 | 1,004 / 1,010 | 992 / 998 |
| T2 | 1,004 / 1,010 | 992 / 998 |
| T3 | 1,005 / 1,012 | 993 / 1,000 |
| T5 | 1,007 / 1,016 | 995 / 1,004 |
| T6 | 1,024 / 1,035 | 1,012 / 1,022 |
| T7 | 1,033 / 1,046 | 1,021 / 1,033 |
| T8 | 1,109 / 1,124 | 1,081 / 1,092 |
| T9 | 1,123 / 1,140 | 1,095 / 1,100 |
| T12–T15 | 1,123 / 1,150 | 1,095 / 1,100 |
| **Final** | **about 1,123, margin 27** | **about 1,095, margin 5** |

Option A edits the repo `AGENTS.md` size-limit paragraph and
`FILE_LIMIT_OVERRIDES` in `scripts/check_size.py` (1,100 → 1,150) as the first
commit of T1, only after the user's yes (it changes the project constitution).
Option B's cuts: T1 moves `RedisNonceStore` (−13) and the long docstrings
(−12); T8 rejects dot segments and host percent-encodings instead of
normalizing them (−16; spec §3.1 rules 6 and 10 change and the deviation is
documented). Another answer gets a new table before T1.

## Tasks

### T1 — Split `Verifier._verify` by responsibility (FR-020)

Refactor on green; behaviour unchanged.

0. Apply the line-limit answer: option A edits `AGENTS.md` and
   `scripts/check_size.py` (`uv run python -m unittest -v test_check_size` from
   `scripts/` stays green); both options move `RedisNonceStore` (class, its
   `__all__` entry and any `SKILL.md`/`references/` mention) into
   `references/nonce-stores.md` as a copy-paste snippet. Option B also moves
   the long docstrings (one-line summaries stay).
1. Characterization first: the current 84 tests are the safety net. Run them
   and save the count.
2. Extract from `_verify` (lines 819–931), each ≤ 50 lines:
   - `_select(req)` → `(label, covered, signature)` or an early `Result`
     (header presence, parse, first `web-bot-auth` label).
   - `_check_params(covered, res)` (keyid, created/expires types, alg, nonce
     type).
   - `_check_times(created, expires, now, res)` (future, ordering, lifetime,
     expiry/age).
   - `_identity(req, covered, label, res)` (coverage rule + Signature-Agent →
     claim; grows in T3, T7, T8).
   - `_check_nonce(req, keyid, nonce, created, expires, now, res)`.
   - `_verify` keeps orchestration, digest, key resolution, crypto and binding.
3. Collapse the seven `# ----` banner blocks to one line each
   (`# --- RFC 8941 structured fields (subset) ---`). Shorten the `KeyResolver`
   comment (lines 546–549) and the `directory_unavailable` docstring (lines
   655–660) to a 2-line contract summary each, kept in the file (analyze U9);
   the full text goes to `references/policy-decisions.md` §6.
4. Break-the-line check: for each extracted helper, break one line (e.g. flip
   `created > now + p.clock_skew`), confirm a named test fails, revert.
5. Remove `"web_bot_auth.py::Verifier._verify"` from `scripts/size_baseline.json`
   (leaving `{}`); run the size gate.

Done when: 84/84 pass, size gate passes with an empty baseline, `wc -l` ≤ the
T1 ceiling.

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
- `test_e1_rsa_vectors_are_unsupported`: E.1.1 and E.1.2 headers → INVALID,
  reason `unsupported alg 'rsa-pss-sha512'` (documents scope).
- `test_e23_content_digest_matches_body`: `content_digest_matches` on the E.2.3
  `Content-Digest` and the exact body bytes → True; one changed byte → False.

All four are expected to pass first time (probe in spec §1). Break-the-line:
for E.2.1, make the dictionary branch of `_agent_url` return None; for E.2.2,
make the legacy branch fall through; for E.1, accept any `alg`; for E.2.3,
return True early in `content_digest_matches`. Revert each.

### T3 — Accept `@target-uri` instead of `@authority` (FR-001)

Failing tests first (class `Accepts`/`Rejects`):

- `test_target_uri_without_authority_verifies`: components
  `("@method", "@target-uri", "signature-agent")` → VERIFIED and
  `binds_request` True for a query-less GET. Fails today with INVALID
  "@authority must be covered".
- `test_neither_authority_nor_target_uri_is_invalid`: request built with
  `sign_request` today (with `_sign` after T7), components
  `("@method", "@path", "signature-agent")` → INVALID with reason
  "@authority or @target-uri must be covered". Fails today on the reason text.
- `test_target_uri_host_swap_is_invalid`: re-target the request to
  `https://other.example/items/42` → INVALID (signature does not verify).
  Likely passes first: break-the-line by making `_derived("@target-uri")`
  return a constant.

Code: one condition in `_identity`. Ceiling per the budget table.

### T4 — `@query-param` (FR-002) — deferred to 0.3.0

Not on this branch. See "Deferred to 0.3.0".

### T5 — Non-JWKS 200 must not evict the cache (FR-009)

Failing tests first (class `DirectoryRefetch`):

- `test_non_jwks_refresh_keeps_cached_keys`: warm the cache with a 300 s TTL,
  move the clock past expiry and the refetch interval, make `fetch` return each
  of `b'{}'`, `b'{"keys": {}}'`, `b'{"error": "x"}'`, `b'[]'`, `b'"x"'`
  (subTest each, fresh resolver per case). Expect `resolve` still returns the
  original key, trusted, from the stale copy. The first three fail today (the
  cache is replaced by `{}`). `b'[]'` and `b'"x"'` **pass today**, because
  `doc.get` raises `AttributeError`, which `resolve` already swallows: for
  them, break-the-line (make `resolve`'s `except` re-raise) and record it.
- `test_valid_directory_without_key_evicts`: refresh returns `{"keys": []}` →
  key no longer resolves (state transition "evidence", -01 §6.10). Likely
  passes first: break by skipping the cache write in `_refresh`.
- `test_parse_directory_rejects_non_jwks`: `parse_directory` raises
  `ValueError` for the five bodies above and for invalid JSON; returns `{}` for
  `{"keys": []}`. Fails today for the first three (they return `{}`) and for
  `[]`/`"x"` (they raise `AttributeError`, not `ValueError`).
- `test_static_resolver_rejects_non_jwks`: `StaticKeyResolver({AGENT: {}})`
  raises `ValueError`.
- Error category: `fetch` raising `TimeoutError` while warm keeps the key
  (already true; break-the-line check on the `except` in `resolve`).

Code: two lines at the top of `parse_directory`.

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
- `test_add_untrusted_directory_drops_test_keys`.
- Boundary: 0 keys; exactly 64; non-Ed25519 entries count toward the limit.
- Update T2's E.2 tests to pass `allow_test_keys=True`, and add
  `test_e21_rejected_by_default` (SC-001 second half): a
  `DirectoryKeyResolver` whose fake fetch serves the B.1.4 key → INVALID
  "known test key rejected".
- `generate_vectors.build` passes `allow_test_keys=True` (its `KEY` is now
  denylisted); the vectors' `description` says ports must do the same.

Code: `TEST_KEY_THUMBPRINTS` (exported), `parse_directory(data, max_keys=64,
allow_test_keys=False)`, constructor parameters on both resolvers, the reason
text in `_resolve_key` (analyze U7). Regenerate vectors (description only).

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
  agent2="https://agent.example"` → not INVALID; `operator` and
  `claimed_agent` None; UNKNOWN_OPERATOR "no key for this operator" with
  `StaticKeyResolver({AGENT: ...})`; VERIFIED with
  `StaticKeyResolver({None: ...})` (the no-URL path, same as a request without
  the header). Fails today: VERIFIED as AGENT. Also: a relabeled copy of a
  valid `agent2` signature (rename the `Signature`/`Signature-Input` members
  to `sig2`) gives the same result.
- Ignored parameters: `sig1="https://agent.example";x=1` covered with key
  `sig1` → the same no-URL results as rule 3 (fails today: attributed to
  AGENT).
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
`Accepts.test_draft05_dictionary_signature_agent` → renamed
`test_dictionary_signature_agent_is_default`;
`Rejects.test_uncovered_signature_agent` and
`DirectorySecurity.test_missing_agent_with_empty_allowlist_does_not_fetch`
build their requests with `_sign`; the legacy subcase of
`DirectorySecurity.test_attacker_path_cannot_impersonate_cold_operator` uses
`_sign`. Fixtures: `Fixture.signed`, `DirectorySecurity.attack`,
`generate_vectors.req` drop `agent_as_dictionary`; `generate_vectors.cases`
keeps `verified_dictionary_agent` and adds nothing yet. Regenerate vectors
(most change from legacy to dictionary form; review the diff).

Code: rewrite `_agent_url` as `_agent_member(header, covered, label)`
returning `(url_or_None, error_or_None)`; `_sign` extracted from
`sign_request`.

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
  INVALID; `Result.operator` None on both.
- (URL, key) property: allowlist `[AGENT + "/a/keys.json"]`; a request naming
  `AGENT + "/b/keys.json"` signed with the `/a` key → UNKNOWN_OPERATOR, no fetch
  (fails today: VERIFIED as AGENT).
- Deviation and mismatch (analyze I2, scenario 13): allowlist `[AGENT]`; a
  request naming `AGENT + "/.well-known/http-message-signatures-directory"` →
  UNKNOWN_OPERATOR, no fetch; with both spellings allowlisted, both VERIFIED
  with their own `operator`, and two fetches of the same URL (accepted, U8).
- Allowlist: `[AGENT + "/a/keys.json", AGENT + "/b/keys.json"]` builds two
  identifiers with separate fetches; `[AGENT + "/k?v=1", AGENT + "/k?v=2"]`
  raises `ValueError` naming `https://agent.example/k` in any order.
- Runtime add (analyze U5, scenario 14): `allowlist.add("https://agent.example")`
  raises `ValueError` naming `https://agent.example/`;
  `allowlist.add("https://agent.example/")` works and fetches the well-known
  URL; `allowlist.discard` of that identifier revokes trust.
- Concurrency: two identifiers on one host, 8 threads each with a barrier on a
  cold cache → exactly one fetch attempt per identifier (pattern of
  `test_concurrent_cold_requests_share_one_fetch_attempt`); failures on one
  identifier do not rate-limit the other.
- Spelling collapse: `AGENT + "/a/../k"` and `AGENT + "/%6B"` claims resolve to
  the allowlisted `AGENT + "/k"`; `AGENT + "/K"` and `AGENT + "/k/"` do not;
  `AGENT + "/a\\k"` is INVALID.
- SC-005 (analyze C1): add `assertFetchedSubset(fetched, resolver)` and
  `assertNotMisattributed(result, resolver)` helpers, and call them in every
  `DirectorySecurity` test (existing and new).

Re-specified existing tests (expected outcome changes; cite -01 §4.4/§5.4/§5.5
in the commit, SC-008):
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
two existing `allowlist.add(AGENT)` calls → `AGENT + "/"`.
`StaticKeyResolver` and `generate_vectors.build`/`trusted_keys` key by
normalized identifiers (this task only; analyze D1). Regenerate vectors and
review the diff (operators gain `/`).

Code: `normalize_agent_url`, `_split_agent_url`, `_host_port`, `_pct`,
`_remove_dot_segments`, `_directory_entry`, `_Allowlist` (a `set` subclass
whose `add` raises on non-normalized values), `Result.claimed_agent`,
`ResolvedKey.attributed`, resolver re-keying, `_identity` uses
`normalize_agent_url`; rename `_directory_urls` → `_fetch_urls` (analyze I1);
delete `normalize_origin` and `directory_url` (update every caller; check the
repo for both names with the SC-006 command). Update `StaticKeyResolver`,
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
  keyid for allowlisted operator" (fails against a naive fallback; write it
  before the fallback so it guards the fallback's first version). Same
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
- SC-005 helpers from T8 in every test of this class.
- Existing `test_background_directory_stays_untrusted_and_expires` is
  re-specified (operator None unless `fetched=True`; SC-008).

Code: unattributed pools in `DirectoryKeyResolver` under the existing lock,
fallback in `resolve` guarded by `directory_unavailable`,
`ResolvedKey(..., attributed=False)`.

### T10 — `verify_all` (FR-012) — deferred to 0.3.0

### T11 — `accept_signature_header` (FR-015) — deferred to 0.3.0

### T12 [P] — Regenerate and extend vectors (FR-017, SC-004)

Files: `web-bot-auth/scripts/generate_vectors.py`,
`web-bot-auth/assets/test-vectors.json`, and class `Vectors` in
`web-bot-auth/scripts/test_web_bot_auth.py` (analyze I5; T13 does not touch
it).

- Test first: extend `Vectors` with (a) exactly one vector's
  `Signature-Agent` header is a bare sf-string; (b) a **hand-written** table
  `EXPECTED = {name: (outcome, operator, claimed_agent)}` for every vector,
  asserted against the JSON and against a fresh `Verifier` run, independently
  of `build()` (analyze U4); (c) the `normalization` section equals the spec
  §3.1 table row for row and `normalize_agent_url` reproduces it. Fails until
  the cases and section exist.
- Add cases: `verified_target_uri_only`, `verified_legacy_string_agent` (the
  only legacy one, via `_sign`), `ignored_parameterized_member`,
  `ignored_member_key_not_label`, `unknown_operator_path_mismatch`,
  `verified_query_ignored_in_identifier`, `invalid_test_key_rejected` (signed
  with the RFC 9421 B.1.4 key, which is not in `trusted_keys`; expected
  `invalid`, reason "known test key rejected").
- Add the `normalization` section (input → identifier, or `null` for reject).
- `expected.operator` and `expected.claimed_agent` on accepted outcomes;
  `description` and the module docstring say operators are normalized URLs,
  that ports must pass `allow_test_keys=True`, and that the `normalization`
  section is the cross-language identity contract.
- Review the full diff of `test-vectors.json` before committing.

### T13 [P] — Skill docs (FR-018)

Files: `web-bot-auth/SKILL.md`, `web-bot-auth/references/policy-decisions.md`,
`references/adapters.md`, `references/nonce-stores.md`. Docs only; no tests.

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
  custom-resolver contract (identifiers, `attributed`).
- `adapters.md`: refuse signature headers over plain http (-01 §6.1).
- `nonce-stores.md`: cite RFC 9421 §7.2.2 and -01 App. C.6 (the
  `RedisNonceStore` snippet arrives in T1).
- Check SC-006 with the `rg` command in the spec.

### T14 — README (FR-018)

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
    `normalize_origin`, `directory_url`, `agent_as_dictionary` (and, per the
    line-limit answer, `RedisNonceStore`) removed; `sign_request` requires
    `agent`, covers `@authority` or `@target-uri`, and always sends the
    dictionary form; a covered member whose key differs from the label is
    ignored; `add_untrusted_directory` attributes only with `fetched=True`;
    test keys rejected by default; `parse_directory` raises on non-JWKS and on
    more than 64 keys.
  - **Added:** `@target-uri` without `@authority`, `normalize_agent_url`,
    `TEST_KEY_THUMBPRINTS`, -01 Appendix E tests, the `normalization` vectors.
  - **Pending:** README quick-start, if T14b was skipped.
- `pyproject.toml` `version = "0.2.0"`; `uv lock`; `uv sync --locked`.
- PR body: the SC-008 list collected from the T5–T9 commit messages, including
  the two revision-0 behaviours that changed (rule 3 ignore, removal wins); the
  0.3.0 deferred list.
- Final gates: full suite (count quoted), size gate, `wc -l` (≤ the settled
  limit), SC-006 `rg`, `git status --short`.
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
| A1 | HIGH | Fixed in part: scope split (decision 1a), budget re-estimated with a measured prototype ("Line budget"); the projection is still over 1,100, so the limit question is the spec's second open marker, to be answered before T1. |
| U1 | HIGH | Fixed: removal wins (decision 2), spec §3.7, FR-021, scenario 12, T9 failing tests, CHANGELOG Security, SC-008 note. |
| I1 | MED | Fixed both ways: SC-006 uses `\b`, and T8 renames `_directory_urls` → `_fetch_urls`. |
| U2 | MED | Fixed: mismatched member key is ignored (decision 3), spec §3.4 rule 3 cites -01 §6.6.1 and RFC 9421 §7.2.5, FR-003, scenario 7, T7 tests. The no-URL outcome is the spec's third open marker. |
| I2 | MED | Fixed: spec §3.2 labels the bare-origin rule a deviation from -01 §4.1/§4.4 with rationale; mismatch documented (scenario 13, T8 test, T13 docs, T15 CHANGELOG). |
| U3 | MED | Fixed: four keys, thumbprints computed with the repo's `jwk_thumbprint` (spec §3.6 table), T6 tests, vectors pass `allow_test_keys=True`. |
| A2 | MED | Fixed: spec §3.1 rules 1–11 (character set incl. backslash, port grammar, host decoding and case, trailing slash, userinfo/fragment), hand-written table, T8 subTests. |
| I3 | MED | Fixed for the signer (spec §3.8, FR-013, T7). For `accept_signature_header`: deferred with the helper (spec §9). |
| C1 | MED | Fixed: SC-005 cited by T8 and T9, assertion helpers used by every `DirectorySecurity`/`DirectoryTrust` test. |
| U4 | MED | Fixed: hand-written expectation table and `normalization` section (FR-017, T12); diff review of every regenerated vectors file (ground rules, T6–T8). |
| U5 | MED | Fixed: `allowlist.add` raises on non-normalized values (spec §3.2, FR-008, scenario 14, T8, CHANGELOG). |
| I4 | MED | Fixed: T14a always fixes `main`'s README line 28; T14b conditional; if skipped, CHANGELOG/PR say so and a follow-up records the `agent_as_dictionary=True` break on `docs/readme` (also spec §8). Sequencing itself stays the first open marker. |
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
