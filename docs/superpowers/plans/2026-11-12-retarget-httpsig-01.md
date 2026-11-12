# Plan: retarget to draft-ietf-webbotauth-httpsig-protocol-01

- Spec: `docs/superpowers/specs/2026-11-12-retarget-httpsig-01-design.md`
- Branch / worktree: `feat/retarget-httpsig-01` at
  `/home/eldan/projects/web-bot-auth-skill-retarget` (from `main` @ d35a52b)
- Status: waiting for user approval. Before approval, run the independent
  read-only Opus pass with `~/.agents/templates/analyze-prompt.md`
  (SPEC/PLAN = the two files above, RULES = `~/.agents/AGENTS.md` +
  `AGENTS.md`).
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
- After every task, from the worktree root:
  - `cd web-bot-auth/scripts && uv run python -m unittest -v test_web_bot_auth 2>&1 | tee /tmp/wba-T<n>.log; tail -3 /tmp/wba-T<n>.log`
    (confirm "Ran N tests" with N non-zero and growing, and "OK");
  - `uv run python scripts/check_size.py`;
  - `wc -l web-bot-auth/scripts/web_bot_auth.py` against the task's ceiling in
    the line budget below. Over the ceiling: stop and report; do not squeeze
    code (spec, second clarification marker).
- Functions ≤ 50 lines. New public names go into `__all__`. Every `.py` keeps
  its SPDX header. Python 3.9 compatible (CI matrix).
- A task that changes any vector outcome or the signer's output regenerates
  `assets/test-vectors.json` with
  `cd web-bot-auth/scripts && uv run python generate_vectors.py > ../assets/test-vectors.json`,
  so `test_vectors_file_is_current` stays green. New vector cases wait for T12.
- Docstrings and comments of code a task touches are updated in that task
  (FR-018); `SKILL.md`/`references/` wait for T13.
- Check every quoted spec fact against the -01 text (repo `AGENTS.md`).
- Commit per task on `feat/retarget-httpsig-01`; never `--no-verify`; do not
  push until the user approves (and see T14 for the rebase).
- Code search: the codebase-memory graph is the first tool when it is up; it was
  down while this plan was written, so the line numbers below come from a direct
  read of `main` @ d35a52b.

## Parallelism

Every code task (T1–T11) edits `web_bot_auth.py` and `test_web_bot_auth.py`, so
they run strictly in order. T12 (`generate_vectors.py`, `assets/`) and T13
(`SKILL.md`, `references/`) share no files and are `[P]`. T14 and T15 run last.

## Line budget for `web-bot-auth/scripts/web_bot_auth.py`

Start: 1,017 lines; limit 1,100. Estimates are ±10 per task.

| Task | Change | Est. delta | Projected | Ceiling |
|---|---|---|---|---|
| T1 | split `_verify` (+14); collapse 7 three-line section banners to one line (−14); move the `KeyResolver` comment and the `directory_unavailable` docstring body into `references/policy-decisions.md` §6, which already documents both (−8) | −8 | 1,009 | 1,017 |
| T2 | tests only | 0 | 1,009 | 1,009 |
| T3 | `@target-uri` rule | +1 | 1,010 | 1,012 |
| T4 | `_query_param` + call site | +15 | 1,025 | 1,030 |
| T5 | `parse_directory` shape check | +2 | 1,027 | 1,032 |
| T6 | `TEST_KEY_THUMBPRINTS`, `max_keys`, `allow_test_keys` | +14 | 1,041 | 1,048 |
| T7 | member selection rewrite, `_sign`, drop `agent_as_dictionary` | +1 | 1,042 | 1,050 |
| T8 | `normalize_agent_url` + helpers, `_directory_entry`, fields; remove `normalize_origin`, `directory_url` | +32 | 1,074 | 1,084 |
| T9 | unattributed pools | +8 | 1,082 | 1,090 |
| T10 | `verify_all`, one-line `verify` | +7 | 1,089 | 1,096 |
| T11 | `accept_signature_header` | +7 | 1,096 | 1,100 |

Projected final: about 1,096 lines. Fallback if a ceiling is hit: the order in
the spec's second clarification marker, only after the user answers it.

## Tasks

### T1 — Split `Verifier._verify` by responsibility (FR-020)

Refactor on green; behaviour unchanged.

1. Characterization first: the current 84 tests are the safety net. Run them
   and save the count.
2. Extract from `_verify` (lines 819–931), each ≤ 50 lines:
   - `_select(req)` → `(inputs, sigs, labels)` or an early `Result`
     (header presence, parse, `web-bot-auth` label list). Returning the full
     label list now prepares T10.
   - `_check_params(covered, res)` (keyid, created/expires types, alg, nonce
     type).
   - `_check_times(created, expires, now, res)` (future, ordering, lifetime,
     expiry/age).
   - `_identity(req, covered, label, res)` (coverage rule + Signature-Agent →
     operator; grows in T3, T7, T8).
   - `_check_nonce(req, keyid, nonce, created, expires, now, res)`.
   - `_verify` keeps orchestration, digest, key resolution, crypto and binding.
3. Collapse the seven `# ----` banner blocks to one line each
   (`# --- RFC 8941 structured fields (subset) ---`). Move the `KeyResolver`
   comment (lines 546–549) and the body of the `directory_unavailable`
   docstring (lines 655–660) into `references/policy-decisions.md` §6 (keep a
   one-line docstring and a pointer). This is the only doc file T1 touches.
4. Break-the-line check: for each extracted helper, break one line (e.g. flip
   `created > now + p.clock_skew`), confirm a named test fails, revert.
5. Remove `"web_bot_auth.py::Verifier._verify"` from `scripts/size_baseline.json`
   (leaving `{}`); run the size gate.

Done when: 84/84 pass, size gate passes with an empty baseline, ≤ 1,017 lines.

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
  trailing-slash form; note it there).
- `test_e1_rsa_vectors_are_unsupported`: E.1.1 and E.1.2 headers → INVALID,
  reason `unsupported alg 'rsa-pss-sha512'` (documents scope).
- `test_e23_content_digest_matches_body`: `content_digest_matches` on the E.2.3
  `Content-Digest` and the exact body bytes → True; one changed byte → False.
  Directory response signatures themselves are out of scope (spec §2).

All four are expected to pass first time (probe in spec §1). Break-the-line:
for E.2.1, make the dictionary branch of `_agent_url` return None (fails);
for E.2.2, make the legacy branch fall through; for E.1, accept any `alg`; for E.2.3, return True early in
`content_digest_matches`. Revert each.

### T3 — Accept `@target-uri` instead of `@authority` (FR-001)

Failing tests first (class `Accepts`/`Rejects`):

- `test_target_uri_without_authority_verifies`: components
  `("@method", "@target-uri", "signature-agent")` → VERIFIED and
  `binds_request` True for a query-less GET. Fails today with INVALID
  "@authority must be covered".
- `test_neither_authority_nor_target_uri_is_invalid`: components
  `("@method", "@path", "signature-agent")` → INVALID with reason
  "@authority or @target-uri must be covered". Fails today on the reason text.
- `test_target_uri_host_swap_is_invalid`: re-target the request to
  `https://other.example/items/42` → INVALID (signature does not verify).
  Likely passes first: break-the-line by making `_derived("@target-uri")`
  return a constant.

Code: one condition in `_identity`. Ceiling 1,012.

### T4 — `@query-param` (FR-002)

Failing tests first (new class `QueryParam`), each with the expected failure
"unsupported parameters on @query-param" today:

- RFC 9421 §2.2.8 values through `signature_base`: for
  `/path?param=value&foo=bar&baz=batman&qux=`, lines
  `"@query-param";name="baz": batman`, `"@query-param";name="qux": ` (trailing
  space), `"@query-param";name="param": value`; for
  `/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something`,
  values `this%20is%20a%20big%0Amultiline%20value`,
  `with%20plus%20whitespace`, and name `fa%C3%A7ade%22%3A%20` → `something`.
- `~` in a value is encoded `%7E`; `*-._` stay literal; invalid UTF-8
  (`%FF`) becomes `%EF%BF%BD`.
- End to end: signed with `"@query-param";name="id"` → VERIFIED,
  `binds_request` False; changing `id` → INVALID; changing another parameter
  → still VERIFIED.
- Errors → INVALID "malformed": no `name`; `name` a token or integer; an extra
  parameter; name absent from the query; name occurring twice; no query at all.
- Boundary: empty value; parameter order in the query differs from coverage
  order.

Code: `_query_param(params, req)` (≤ 15 lines; `parse_qsl`, `quote` imports),
dispatch from `_component_value` before the "unsupported parameters" check.
`_QUERY_COVERING` unchanged. Ceiling 1,030.

### T5 — Non-JWKS 200 must not evict the cache (FR-009)

Failing tests first (class `DirectoryRefetch`):

- `test_non_jwks_refresh_keeps_cached_keys`: warm the cache with a 300 s TTL,
  move the clock past expiry and the refetch interval, make `fetch` return each
  of `b'{}'`, `b'{"keys": {}}'`, `b'[]'`, `b'"x"'`, `b'{"error": "x"}'`
  (subTest each, fresh resolver per case). Expect `resolve` still returns the
  original key, trusted, from the stale copy. Fails today: the cache is
  replaced by `{}`.
- `test_valid_directory_without_key_evicts`: refresh returns `{"keys": []}` →
  key no longer resolves (state transition "evidence", -01 §6.10). Likely
  passes first: break by skipping the cache write in `_refresh`.
- `test_parse_directory_rejects_non_jwks`: `parse_directory` raises
  `ValueError` for the five bodies above and for invalid JSON; returns `{}` for
  `{"keys": []}`.
- `test_static_resolver_rejects_non_jwks`: `StaticKeyResolver({AGENT: {}})`
  raises `ValueError` (configuration error surfaces early).
- Error category: `fetch` raising `TimeoutError` while warm keeps the key
  (already true; break-the-line check on the `except` in `resolve`).

Code: two lines at the top of `parse_directory`. Ceiling 1,032.

### T6 — `max_keys` and test-key denylist (FR-010, FR-011)

Failing tests first:

- `test_directory_with_too_many_keys_is_a_discovery_failure`: 65 entries →
  `ValueError`; 64 → parsed; via `DirectoryKeyResolver(max_keys=64)` a warm
  cache survives a 65-key refresh. Fails today: no limit.
- `test_rfc9421_test_key_dropped_from_directory`: an allowlisted directory
  serving the B.1.4 key → a request signed with it is INVALID "unknown keyid
  for allowlisted operator"; with `allow_test_keys=True` → VERIFIED. Fails
  today: VERIFIED.
- `test_rfc9421_test_key_rejected_in_static_config`: `StaticKeyResolver` raises
  `ValueError` mentioning the thumbprint; `allow_test_keys=True` accepts it.
- `test_add_untrusted_directory_drops_test_keys`.
- Boundary: 0 keys; exactly 64; non-Ed25519 entries count toward the limit.
- Update T2's E.2 tests to pass `allow_test_keys=True`, and add
  `test_e21_rejected_by_default` (SC-001 second half).

Code: `TEST_KEY_THUMBPRINTS` constant (exported), `parse_directory(data,
max_keys=64, allow_test_keys=False)`, constructor parameters on both resolvers.
Ceiling 1,048.

### T7 — Member selection, ignored parameters, conformant signer (FR-003, FR-004, FR-013)

Failing tests first:

- Member selection (spec §3.4): two covered members `browser` and `agent`, in
  both header orders and both coverage orders → each label resolves its own
  member (fails today: first covered component wins); label `sig2` covering
  only `key="agent2"` → INVALID "Signature-Agent member for this label is not
  covered" (fails today: VERIFIED); bare `"signature-agent"` over a dictionary
  with member `sig1` → that member; bare over a dictionary without `sig1` →
  INVALID (fails today: single-member fallback); legacy string still VERIFIED.
- Ignored member: `sig1="https://agent.example";x=1` covered with key `sig1` →
  operator None, `claimed_agent` None, outcome UNKNOWN_OPERATOR with
  `StaticKeyResolver({AGENT: ...})` and VERIFIED with
  `StaticKeyResolver({None: ...})` (fails today: attributed to AGENT).
- Signer: `sign_request(req, key)` without `agent` → `TypeError`;
  `agent="http://agent.example"` → `ValueError`; components without
  `"signature-agent"` → `ValueError`; default output has
  `Signature-Agent: sig1="https://agent.example"` and covers
  `"signature-agent";key="sig1"`; `label="agent"` keys both by `agent`.
- `_sign(req, key, covered, label)` produces the -01 E.2.2 legacy bytes when
  given the B.1.4 private key, the E.2.2 parameters and nonce (signing
  determinism check; Ed25519 is deterministic).

Re-specified existing tests (record in the commit message):
`Accepts.test_draft05_dictionary_signature_agent` → renamed
`test_dictionary_signature_agent_is_default` (no `agent_as_dictionary`);
`Rejects.test_uncovered_signature_agent` and
`DirectorySecurity.test_missing_agent_with_empty_allowlist_does_not_fetch`
build their requests with `_sign` (the signer now refuses them);
`DirectorySecurity.test_attacker_path_cannot_impersonate_cold_operator` builds
the legacy subcase with `_sign`. Fixtures: `Fixture.signed`,
`DirectorySecurity.attack`, `generate_vectors.req` drop `agent_as_dictionary`;
`generate_vectors.cases` keeps `verified_dictionary_agent` (now the default
shape) and adds nothing yet. Regenerate vectors (most change from legacy to
dictionary form).

Code: rewrite `_agent_url` as `_agent_member(header, covered, label)`
returning `(url_or_None, error_or_None)`; `_sign` extracted from
`sign_request`. Ceiling 1,050.

### T8 — URL identity and allowlist semantics (FR-005, FR-006, FR-007, FR-008)

Failing tests first (new class `AgentUrl`, then `DirectoryConfiguration`,
`DirectorySecurity`):

- `normalize_agent_url`, one subTest per row (fails today: name missing):
  case (`HTTPS://Agent.EXAMPLE/K` → `https://agent.example/K`, path case kept);
  default port; explicit `:8443` kept; empty port `https://a.example:/`;
  empty path → `/`; dot segments `/a/./b/../c`, `/..`, `/a/..`, trailing
  `/a/.`; `%2E%2E` decoded then removed; `%7e` → `~`; `%2f` → `%2F` (stays
  encoded); query dropped; IPv6 `https://[2001:DB8::1]/` → lowercase in
  brackets; rejects: empty string, `agent.example`, `http://`, `data:`,
  `https:///k`, userinfo, `#frag`, bare `#`, bad port, `%zz`, `%4`, non-ASCII
  host, space, tab, `\x7f`, 2,049 characters (2,048 accepted).
- Identity: spec §5 scenarios 1–3 (fail today: operator is the origin; path
  claim is attributed). `Result.claimed_agent` set on UNKNOWN_OPERATOR and
  INVALID; `Result.operator` None on both.
- (URL, key) property: allowlist `[AGENT + "/a/keys.json"]`; a request naming
  `AGENT + "/b/keys.json"` signed with the `/a` key → UNKNOWN_OPERATOR, no fetch
  (fails today: VERIFIED as AGENT).
- Allowlist: `[AGENT + "/a/keys.json", AGENT + "/b/keys.json"]` builds two
  identifiers with separate fetches; `[AGENT + "/k?v=1", AGENT + "/k?v=2"]`
  raises `ValueError` naming `https://agent.example/k` in any order;
  `[AGENT, AGENT + "/.well-known/http-message-signatures-directory"]` gives two
  identifiers, both fetching the well-known URL.
- Concurrency: two identifiers on one host, 8 threads each with a barrier on a
  cold cache → exactly one fetch attempt per identifier (pattern of
  `test_concurrent_cold_requests_share_one_fetch_attempt`); failures on one
  identifier do not rate-limit the other.
- Spelling collapse: `AGENT + "/a/../k"` and `AGENT + "/%6B"` claims resolve to
  the allowlisted `AGENT + "/k"`; `AGENT + "/K"` does not.

Re-specified existing tests (expected outcome changes; cite -01 §4.4/§5.4/§5.5
in the commit):
`DirectoryConfiguration.test_configured_directory_path_and_query_override_request`
(the request now names the configured identifier to verify; the mismatched
claim becomes the new UNKNOWN_OPERATOR test);
`test_origin_entries_use_normalized_well_known_location` (operator
`https://agent.example/`); `test_configured_root_query_uses_well_known_path`
(unchanged fetch; identifier `https://agent.example/`);
`test_conflicting_custom_directories_rejected_in_any_order` and
`test_origin_and_custom_directory_conflict_in_any_order` (no longer conflicts:
two identifiers; replaced by the query-conflict test above);
`test_identical_normalized_directories_are_allowed` (`allowlist ==
{"https://agent.example/"}`);
`test_runtime_added_normalized_origin_uses_well_known_directory` (add
`"https://agent.example/"`; the request names that identifier);
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
trailing-slash form; T2's E.2 tests → `https://signature-agent.test/`.
`StaticKeyResolver` and `generate_vectors.build` key by normalized identifiers.
Regenerate vectors.

Code: `normalize_agent_url` (+ `_pct`, `_remove_dot_segments`, `import re`),
`_directory_entry(entry) -> (identifier, fetch_url)`, `Result.claimed_agent`,
`ResolvedKey.attributed`, resolver re-keying, `_identity` uses
`normalize_agent_url`; delete `normalize_origin` and `directory_url` (update
every caller; `rg` the repo for both names). Update `StaticKeyResolver`,
`DirectoryKeyResolver` and module docstrings. Ceiling 1,084.

### T9 — Redistributed keys carry no URL (FR-014)

Failing tests first (class `DirectoryTrust`):

- Spec §5 scenario 9: `add_untrusted_directory(url, jwks, now=NOW)` → request
  naming `url` is SIGNED_UNTRUSTED, operator None, keyid set (fails today:
  operator is the URL).
- `fetched=True` → SIGNED_UNTRUSTED with operator the normalized URL.
- Unattributed keys verify for a request naming any identifier (including none)
  and never produce `trusted` or VERIFIED, also when the claim is an
  allowlisted identifier whose fresh directory lacks the key.
- Re-adding the same source replaces its keys (old key stops resolving); a
  second source keeps both; each expires at its own `ttl` (boundary
  `NOW + ttl` exclusive, as today).
- Allowlisted identifier → `ValueError` for both `fetched` values.
- Concurrency: one thread re-adding a source while 8 threads resolve → every
  resolve sees either the old or the new key set, never a mixed or missing one
  (barrier, no sleeps).
- Existing `test_background_directory_stays_untrusted_and_expires` is
  re-specified (operator None unless `fetched=True`).

Code: unattributed pools in `DirectoryKeyResolver` under the existing lock,
fallback in `resolve`, `ResolvedKey(..., attributed=False)`. Ceiling 1,090.

### T10 — `verify_all` (FR-012)

Failing tests first (new class `MultipleSignatures`, requests built by signing
twice with `_sign` and two keys; the second signature covers the D.2 set):

- Spec §5 scenario 6: both labels VERIFIED, each `operator` its own member,
  `verify` equals the first result (fails today: no `verify_all`).
- Tampering a component covered only by `agent` → `agent` INVALID and
  `browser` INVALID (it covers the agent's components); tampering a component
  covered only by `browser` → `agent` VERIFIED, `browser` INVALID.
- An outer signature covering `"signature";key="agent"` without
  `"signature-input";key="agent"` is still verified on its own terms
  (verifier MUST validate independently; the coverage MUST binds signers).
- Non-`web-bot-auth` labels are skipped; none at all → `[UNSIGNED]`; malformed
  `Signature-Input` → one INVALID "malformed"; a label missing from
  `Signature` → that label INVALID, the other still verified.
- Boundary: 8 labels verified, the 9th INVALID "too many signatures" with no
  resolver call (counting resolver).
- Replay: two labels with the same keyid and nonce → second REPLAY; a nonce
  store error affects only the label being recorded.
- `verify` still verifies only the first label (counting resolver: one call).

Code: `verify_all`; `verify` returns the first-label path through the same
per-label function. Ceiling 1,096.

### T11 — `accept_signature_header` (FR-015, code part)

Failing tests first: default output equals
`sig1=("@method" "@authority" "@path" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"`;
custom label and components; `nonce` adds `;nonce="..."` and is serialized as
an sf-string (a `"` in it is escaped); the output parses with
`parse_dictionary`; a request signed by `sign_request` with the requested
label and components satisfies it (same component list). Edge: empty
components still yields the `signature-agent` component; an invalid label
(uppercase) raises `ValueError`. Ceiling 1,100.

### T12 [P] — Regenerate and extend vectors (FR-017)

Files: `web-bot-auth/scripts/generate_vectors.py`, `web-bot-auth/assets/test-vectors.json`.

- Add cases: `verified_target_uri_only`, `verified_query_param`,
  `verified_legacy_string_agent` (the only legacy one, via `_sign`),
  `ignored_parameterized_member` (UNKNOWN_OPERATOR),
  `invalid_member_key_not_label`, `unknown_operator_path_mismatch`,
  `verified_query_ignored_in_identifier`, and a `two_signatures` vector with
  `expected_all` (list) for `verify_all`.
- `trusted_keys` keyed by `https://agent.example/`; `expected.operator` and
  `expected.claimed_agent` on accepted outcomes; `description` and the module
  docstring say operators are normalized URLs and that ports must also run
  `verify_all` for vectors with `expected_all`.
- Test first: extend `Vectors` with a check that exactly one vector's
  `Signature-Agent` header is a bare sf-string (SC-004) and that every vector
  with `expected_all` has a list; fails until the cases exist.

### T13 [P] — Skill docs (FR-015 docs, FR-018)

Files: `web-bot-auth/SKILL.md`, `web-bot-auth/references/policy-decisions.md`,
`references/adapters.md`, `references/nonce-stores.md`. Docs only; no tests.

- `SKILL.md`: spec status (-01, a WG draft); outcomes table with -01 App. C.1
  vocabulary and status codes (400 for "malformed", 403 + `Accept-Signature`,
  429 for `replay`); Rules bullet on allowlist identifiers (full URLs, bare
  origin compatibility rule, path claims not attributed); logging fields
  (`operator`, `claimed_agent`, `keyid` as the no-URL identifier); `verify_all`.
- `policy-decisions.md`: rewrite §1 directory paragraph and "Draft scope"
  (cite -01 §4.1, §4.4, §5.4, §5.5, §5.5.3); replace "Not implemented:
  verifying the directory response's own signature" with the -01 App. B
  position (optional for direct resolution; needed only to attribute
  redistributed keys, which this verifier does not do); `fetched=True`
  guidance for background jobs; §2 `@authority` or `@target-uri`;
  `@query-param`; §3 `min_nonce_length` is local policy (-01 §5.2.3 defers
  nonces to RFC 9421 §7.2.2); §4 cite -01 §5.2; test-key denylist and
  `max_keys`.
- `adapters.md`: status codes with `accept_signature_header`; refuse signature
  headers over plain http (-01 §6.1).
- `nonce-stores.md`: cite RFC 9421 §7.2.2 and -01 App. C.6.
- Check SC-006 with the `rg` command in the spec.

### T14 — README (FR-018)

Precondition (spec, first clarification marker): `docs/readme` @ 62de1d4 is
merged to `main`. Then `git rebase main` on this branch **before its first
push** (no force-push needed), and update README line 14 (cite -01 §1), line 16
(header required, URL fetched directly, well-known as one case), lines 105/113
(`agent_as_dictionary` gone), line 139 (identifier semantics), lines 141–146
(spec status: target -01; line 146's "keeps the well-known location" claim is
only partly true). If `docs/readme` is unmerged when T15 is ready, skip T14
and open it as a follow-up PR.

### T15 — Release 0.2.0 (FR-019)

- `CHANGELOG.md` `## 0.2.0`, with the current `Unreleased` uv entry folded in:
  - **Security:** identity was the origin, so keys and signatures were
    attributed to the host operator for any path on that host, and two tenants
    on one host could not be told apart (-01 §5.5: "TLS authenticates the host
    but not the path"); keys from third-party lists were attributed to a URL
    (-01 §5.5.3); a 200 non-JWKS response evicted good keys (-01 §6.10).
  - **Breaking:** identifier is the normalized Signature-Agent URL;
    `Result.operator` values (trailing `/`, path) and set only when attributed;
    new `Result.claimed_agent`; allowlist entries on one host are separate
    identifiers; `normalize_origin`, `directory_url` and `agent_as_dictionary`
    removed; `sign_request` requires `agent` and always sends the dictionary
    form; member key must equal the label; `add_untrusted_directory` attributes
    only with `fetched=True`; test keys rejected by default; `parse_directory`
    raises on non-JWKS and on more than 64 keys.
  - **Added:** `verify_all`, `@target-uri` without `@authority`,
    `@query-param`, `accept_signature_header`, `normalize_agent_url`,
    `TEST_KEY_THUMBPRINTS`, -01 Appendix E tests.
- `pyproject.toml` `version = "0.2.0"`; `uv lock`; `uv sync --locked`
  (SC-007).
- Final gates: full suite (count quoted), size gate, `wc -l` (≤ 1,100),
  SC-006 `rg`, `git status --short`.
- PR review: one Opus review with `~/.agents/templates/review-spec-coverage.md`
  pasted; unmet FR/SC become follow-up issues.

## Edge-case coverage map (seven categories)

| Category | Tasks |
|---|---|
| Null/empty/zero | T4 (empty value, no query), T5 (`{}`, empty `keys`), T6 (0 keys), T8 (empty string, empty path), T10 (no labels), T11 (empty components) |
| Boundaries | T6 (64/65), T8 (2,048/2,049, ports), T9 (ttl edge), T10 (8/9 labels) |
| Invalid data | T3, T4 (bad `name`), T5 (non-JWKS), T7 (member params, non-String), T8 (all rejections), T11 (bad label) |
| Concurrency | T8 (two identifiers, barrier), T9 (re-add vs resolve), T10 (shared nonce) |
| Errors | T5 (fetch raises while warm), T10 (nonce store error per label) |
| State transitions | T5 (warm → failed → warm; warm → evidence → evicted), T8 (runtime add/remove), T9 (replace, expire) |
| Security | T7 (key ≠ label), T8 (path claim, no fetch, spelling collapse), T6 (test keys), T10 (outer covers inner) |
