# Retarget the web-bot-auth skill to draft-ietf-webbotauth-httpsig-protocol-01

- Date: 2026-11-12
- Status: draft, waiting for user approval
- Branch: `feat/retarget-httpsig-01` (from `main` @ d35a52b)
- Plan: `docs/superpowers/plans/2026-11-12-retarget-httpsig-01.md`
- Target release: 0.2.0 (breaking; contains a security fix)

## 1. Background

The verifier in `web-bot-auth/scripts/web_bot_auth.py` (0.1.1) targets
`draft-meunier-web-bot-auth-architecture-05` plus
`draft-meunier-http-message-signatures-directory-05`. Both were replaced. The
current document is the working-group draft
`draft-ietf-webbotauth-httpsig-protocol-01` (29 Oct 2026, "-01" below). It folds
the directory format, the well-known URI and the media type into itself, so the
retarget has one normative document plus RFC 9421, 9530, 7638, 8037, 9651 and
3986.

Sources checked for this spec (2026-11-12):

- -01 text: `https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-01.txt`,
  fetched and read in full (2464 lines, byte-identical to the copy used by the
  earlier gap analysis).
- RFC 9421 §2.2.8 (`@query-param`) and §5.1–5.2 (`Accept-Signature`), fetched
  from `https://www.rfc-editor.org/rfc/rfc9421.txt`.
- Gap analysis (prior, read-only):
  `/home/eldan/.cache/claude-tmp/claude-1000/-home-eldan-projects-web-bot-auth-skill/b6c82dcc-11ca-4f3f-ad39-f9681656b973/scratchpad/retarget-01-plan.md`.
  Its D1–D32 table was re-checked against the -01 text; the numbering below
  cites -01 sections directly.
- Code at `main` @ d35a52b, read directly (the codebase-memory MCP server was not
  connected this session). Baseline: 84 tests pass, size gate passes,
  `web_bot_auth.py` is 1,017 lines, `Verifier._verify` is 113 lines and is the
  only baseline entry.
- Probe (scratchpad script, not in the repo): the -01 E.2.1 (dictionary) and
  E.2.2 (legacy string) vectors already verify with the current code under
  `Policy(max_age=10**10, max_lifetime=None)` at `now=1735689600`. The RFC 9421
  §2.2.8 encoding rule (below) reproduces the RFC's three worked values.

## 2. What changes in -01 that matters to this code

| -01 | Rule | Current code | Gap |
|---|---|---|---|
| §5.2 | At least one of `@authority`, `@target-uri` | requires `@authority` (`_verify`) | rejects valid `@target-uri`-only signatures |
| §5.2 | Agents SHOULD consider `@query-param` | any parameter on a derived component raises | `@query-param` signatures are INVALID |
| §5.2.1 | Member keyed to the signature label MUST be signed; members with parameters MUST be ignored; signers MUST send the dictionary form; verifiers MAY accept the legacy string as `{label: value}` | first covered `signature-agent` wins; any key accepted; parameters ignored; signer defaults to the legacy string | wrong member selection; signer non-conformant |
| §4.3, §5.2.5 | A signed request MUST carry Signature-Agent; no URL means the identifier is the keyid thumbprint | `sign_request(agent=None)` omits it | signer non-conformant |
| §4.1, §4.4, §5.4, §5.5 | Identifier is the resolved Signature-Agent URL, query dropped, RFC 3986 §6.2.2/§6.2.3 normalized, compared octet for octet; lookup keyed on (URL, key); never attribute without making that association; an unresolved URL is a claim and verifiers MUST NOT attach policy to it | identity is the origin; a request naming any path on an allowlisted origin is attributed to the origin | identity overclaims: "TLS authenticates the host but not the path" (§5.5) |
| §5.2.2 | Several signatures; verifiers MUST validate each independently; MUST NOT attribute a signature to a member it does not cover | only the first `web-bot-auth` label is verified | no API to verify the others |
| §5.5.3 | Redistributed keys carry no URL unless they carry a valid directory response signature | `add_untrusted_directory` attributes keys to the given URL | overclaims for third-party lists |
| §6.10 | A failed resolution, including "not a directory", MUST NOT evict a cached entry; a resolved directory without the key replaces it | a 200 JSON body without `keys` parses to `{}` and overwrites the cache | bug: evicts good keys |
| §6.7 | Verifiers SHOULD enforce a maximum key count | none | missing SHOULD |
| §6.8 | Verifiers SHOULD reject known test keys in directories or configuration | none | missing SHOULD |
| §5.3, §5.4 | Origin SHOULD send `Accept-Signature` when it expects signatures; refusal usually 403 with `Accept-Signature`; 400 MAY on parse failure; 429 MAY on over-used nonce/signature | docs say "Block" | missing guidance |
| App. E | E.1.x (RSA-PSS), E.2.1, E.2.2 (Ed25519), E.2.3 (signed directory response) | RFC 9421 B.2.6 vector only | -01 vectors not run |

Unchanged and already compliant: required parameters and 24 h expiry
recommendation (§5.2), tag (§5.4), HMAC ban (§6.4), 200-only and no redirects
(§5.5), byte cap, timeout and public-address filter (§6.7), Content-Digest when
the body matters (§5.2), nonce handling deferred to RFC 9421 §7.2.2 (§5.2.3).
`min_nonce_length=16` is local policy with no draft basis; docs say so.

Out of scope (decided, see Clarifications): verifying directory response
signatures (App. B), `Policy.require_https` (§6.1 is covered by adapter
guidance), RSA-PSS and other algorithms (Ed25519 only, as today), HTTP caching
semantics beyond `max-age` (App. C.4), `kid` checks at the well-known URI (§5.5;
thumbprints are always computed, which -01 allows).

## 3. Design

### 3.1 Identifier

`normalize_agent_url(url) -> str` (public) returns the -01 identifier:

1. Reject (`ValueError`) unless the value is ASCII, has no whitespace or control
   characters, and is at most 2,048 characters.
2. Reject unless the scheme is `https` (case-insensitive) and there is a host.
3. Reject userinfo and any fragment (including an empty one, `...#`). Reject a
   malformed port and a malformed percent-encoding (`%` not followed by two hex
   digits).
4. RFC 3986 §6.2.2: lowercase scheme and host; uppercase the hex digits of
   percent-encodings; decode percent-encoded unreserved characters
   (`ALPHA / DIGIT / - . _ ~`); remove dot segments (§5.2.4 algorithm, after
   percent-decoding, so `%2E%2E` counts as `..`).
5. RFC 3986 §6.2.3: drop port 443; an empty path becomes `/`.
6. Drop the query (-01 §5.5). IPv6 literals stay bracketed.

So `https://Agent.Example:443/a/./b/../%7euser/k%2fs.json?v=3` becomes
`https://agent.example/a/~user/k%2Fs.json` (`%7e` is unreserved `~` and is
decoded; `%2f` is reserved and only has its hex uppercased). A trailing dot in the
host is not removed (RFC 3986 does not define it); `agent.example.` is a
different identifier.

`normalize_origin` and `directory_url` are removed.

### 3.2 Allowlist and fetch location

`DirectoryKeyResolver(allowlist)` entries are full https URLs. For each entry:

- identifier = `normalize_agent_url(entry)`;
- fetch URL = the normalized entry with its query kept, except that an entry
  whose normalized path is `/` (a bare origin) fetches
  `https://host/.well-known/http-message-signatures-directory` plus the entry's
  query. This is the documented compatibility rule from Clarification 2: the
  identifier stays `https://host/`.
- An explicit `https://host/.well-known/http-message-signatures-directory` entry
  is a different identifier from `https://host/` (it names a domain, -01 §4.5).
- Two entries with the same identifier but different fetch URLs (for example two
  queries) raise `ValueError` naming the identifier, in any order. Different
  paths on one host are different identifiers and do not conflict.
- `resolver.allowlist` is the set of identifiers. Runtime `allowlist.add(id)`
  with a normalized identifier fetches that identifier (or the well-known URL if
  its path is `/`). Removing an identifier revokes trust immediately, as today.
- Cache, rate limit and fetch reservation are keyed by identifier, so two
  identifiers on one host are limited separately.

The verifier never fetches a URL named by a request. A request whose normalized
Signature-Agent is not an allowlisted identifier gets no fetch.

### 3.3 Attribution

- `Result.claimed_agent`: the normalized Signature-Agent URL the signature
  covers, or None. For logging only; -01 §4.1 forbids attaching policy to it.
- `Result.operator`: the identifier, set only when the key came from that
  identifier's own resolution (allowlisted fetch, `StaticKeyResolver` entry, or
  `add_untrusted_directory(..., fetched=True)`). Otherwise None, and
  `Result.keyid` (the thumbprint) is the identifier (-01 §4.3).
- `ResolvedKey` gains `attributed: bool = True`. A custom resolver that returns
  `ResolvedKey(key, trusted)` keeps today's behaviour. When `attributed` is
  False, `trusted` is forced to False and `operator` to None.
- `StaticKeyResolver` keys are normalized identifiers (`None` still means "no
  Signature-Agent").

### 3.4 Signature-Agent member selection

For the signature with label `L`, among its covered `signature-agent`
components:

1. A component with `key="L"`: the member `L` of the dictionary is used. Other
   `signature-agent;key=X` components are ordinary covered components (the -01
   App. D.2 shape).
2. Otherwise a bare `"signature-agent"` component: if the header is a single
   sf-string (legacy, -01 E.x.2), it is treated as `{L: value}`; if it is a
   dictionary, its member `L` is used (the whole field is covered).
3. Otherwise, if any `signature-agent;key=X` is covered with `X != L`: INVALID,
   "Signature-Agent member for this label is not covered" (Clarification 3:
   key-differs-from-label is no longer accepted; this was the arch-05 A.x.2
   shape).
4. Header present but no `signature-agent` covered: INVALID (unchanged).
5. Header absent: no URL; identifier is the thumbprint (unchanged; -01 §4.3).

The selected member:

- carries parameters → ignored (-01 §5.2.1 MUST): no URL, same as case 5. The
  signature is still verified; the outcome is usually `unknown_operator`.
- is not a String, or its value fails `normalize_agent_url` → INVALID
  (stricter than the -01 MAY-ignore; unchanged behaviour).

### 3.5 Multiple signatures

`Verifier.verify_all(req) -> list[Result]` returns one `Result` per
`Signature-Input` label whose `tag` is `web-bot-auth`, in header order, each
verified independently against its own components, key and identity. Labels
after the eighth are returned as INVALID "too many signatures" without key
lookup or crypto. No `web-bot-auth` label returns `[Result(UNSIGNED)]`. A parse
failure of `Signature`/`Signature-Input` returns one INVALID "malformed" result.
Nonces are recorded per label after that label verifies; two labels with the
same keyid and nonce make the second one `replay`.

`Verifier.verify(req)` keeps its contract: the first `web-bot-auth` label only.

### 3.6 Directory parsing

`parse_directory(data, max_keys=64, allow_test_keys=False)`:

- raises `ValueError` unless the document is a JSON object whose `keys` is a
  list (a discovery failure, which `_refresh` already treats as "keep the last
  good copy");
- raises `ValueError` when `len(keys) > max_keys` (counted before filtering);
- skips JWKs whose thumbprint is in `TEST_KEY_THUMBPRINTS` unless
  `allow_test_keys`. The set holds the RFC 9421 Appendix B.1.4 Ed25519 key
  (`poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`), the only Ed25519 key in
  RFC 9421 and the key of the -01 E.2 vectors and the §5.5.1 example.

`StaticKeyResolver(keys, trusted=True, allow_test_keys=False)` raises
`ValueError` naming the key when configuration contains a test key (fail fast on
configuration). `DirectoryKeyResolver(..., max_keys=64, allow_test_keys=False)`
passes both through. A directory that resolves and lacks the key still replaces
the cache (-01 §6.10 "evidence").

### 3.7 Redistributed keys

`add_untrusted_directory(url, data, ttl=3600, now=None, *, fetched=False)`:

- `fetched=True`: the caller fetched `url` itself over TLS (a background job or
  a control plane, -01 §5.5.3 para. 2). Keys are attributed to
  `normalize_agent_url(url)` and resolve as `signed_untrusted`, as today.
- `fetched=False` (default): the keys verify but carry no URL. They are stored
  per source (`url` is only the replacement key, so re-adding the same list
  replaces it, -01 §4.4 "newer pair wins") and expire after `ttl`. A request
  whose own identifier has no key falls back to these pools; a hit gives
  `signed_untrusted` with `operator=None`.
- An allowlisted identifier still raises `ValueError` (fetched, not added).

### 3.8 Signer

`sign_request(req, key, *, agent, components=(..., "signature-agent"), label="sig1", ...)`:

- `agent` is required and must pass `normalize_agent_url` (`ValueError`
  otherwise); `agent_as_dictionary` is removed.
- Always sends `Signature-Agent: <label>="<agent>"` and covers
  `"signature-agent";key="<label>"`.
- `components` must include `"signature-agent"` (`ValueError` otherwise).
- The signing core moves to a private `_sign(req, key, covered, label)` that
  tests and `generate_vectors.py` use to build legacy and no-header requests.

### 3.9 Derived components

- `@target-uri` satisfies the "@authority or @target-uri" rule; the reason text
  becomes "@authority or @target-uri must be covered".
- `@query-param;name="<n>"` (RFC 9421 §2.2.8): parse the query with
  `urllib.parse.parse_qsl(keep_blank_values=True)` (HTML form parsing, `+` is a
  space, invalid UTF-8 becomes U+FFFD); encode names and values with
  `quote(s, safe="*-._")` plus `~` → `%7E` (the urlencoded percent-encode set;
  space is `%20`, matching the RFC's own examples). The component value is the
  encoded value of the one parameter whose encoded name equals `n`. Errors
  (SignatureBaseError, so INVALID "malformed"): no `name`, a non-String `name`,
  any other parameter, the name absent, or the name occurring more than once
  (RFC: MUST NOT be included). `binds_request` is unchanged: one parameter does
  not bind the whole query.

### 3.10 Accept-Signature helper and status codes

`accept_signature_header(label="sig1", components=("@method", "@authority", "@path"), nonce=None) -> str`
returns an RFC 9421 §5.1 dictionary member, for example
`sig1=("@method" "@authority" "@path" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"`,
with `;nonce="..."` when given. The `signature-agent;key=<label>` component is
always appended. Docs map outcomes to status codes: 400 MAY for a "malformed"
reason; 403 plus `Accept-Signature` for refusal; 429 plus a fresh
`Accept-Signature` nonce MAY for `replay`; `unknown_operator` is -01 App. C.1
"unverified" and stays on the existing bot-management path.

## 4. Requirements

- **FR-001** The verifier accepts a signature that covers `@target-uri` and not
  `@authority`; it rejects one that covers neither.
- **FR-002** The verifier supports `@query-param;name="..."` per RFC 9421 §2.2.8
  and §3.9 above, including all listed error cases.
- **FR-003** The verifier selects the Signature-Agent member as in §3.4; a
  covered member whose key differs from the label is not accepted; the legacy
  sf-string is accepted only through a bare `"signature-agent"` component.
- **FR-004** A selected member that carries parameters is ignored and the
  request is treated as having no Signature-Agent URL.
- **FR-005** `normalize_agent_url` implements §3.1, including every rejection.
- **FR-006** Attribution follows §3.3: `Result.operator` is set only from that
  identifier's own resolution; `Result.claimed_agent` carries the normalized
  claim; a request naming identifier A is never attributed using keys resolved
  for identifier B != A.
- **FR-007** A bare-origin allowlist entry fetches the well-known URL and its
  identifier is `https://host/` (compatibility rule); every other entry is
  fetched as configured.
- **FR-008** Allowlist configuration follows §3.2: identifier-level conflict
  detection, independent cache and rate limit per identifier, no fetch of any
  request-named URL.
- **FR-009** A directory response that is not a JSON object with a `keys` list
  is a discovery failure and does not evict a cached copy; a valid directory
  without the key replaces the cached copy.
- **FR-010** `parse_directory` rejects a directory with more than `max_keys`
  entries (default 64) as a discovery failure.
- **FR-011** Known test keys are rejected by default: dropped from fetched or
  added directories, and a `ValueError` for static configuration; both have an
  `allow_test_keys=True` opt-out.
- **FR-012** `Verifier.verify_all` implements §3.5; `verify` keeps first-label
  behaviour.
- **FR-013** `sign_request` implements §3.8.
- **FR-014** `add_untrusted_directory` implements §3.7.
- **FR-015** `accept_signature_header` implements §3.10, and the docs give the
  status-code guidance.
- **FR-016** The -01 Appendix E vectors run as tests: E.2.1 and E.2.2 verify;
  E.1.1 and E.1.2 are INVALID "unsupported alg"; E.2.3's Content-Digest matches
  its body (directory response signatures are out of scope).
- **FR-017** `assets/test-vectors.json` is regenerated: dictionary form by
  default, one legacy-string vector, new cases for FR-001–FR-004, FR-006 and
  FR-012, `trusted_keys` keyed by normalized identifiers, `expected.operator`
  and `expected.claimed_agent` given for accepted outcomes.
- **FR-018** Docs describe -01: module docstring and docstrings, `SKILL.md`,
  `references/policy-decisions.md`, `references/adapters.md`,
  `references/nonce-stores.md`, and the README spec-status section.
- **FR-019** Release 0.2.0: `CHANGELOG.md` entry with Breaking, Security and
  Fixed sections; `pyproject.toml` version 0.2.0 and a regenerated `uv.lock`
  (CI runs `uv sync --locked`, and the lock pins the project version).
- **FR-020** `Verifier._verify` is split by responsibility so that every
  function is at most 50 lines and its baseline entry is removed; the file stays
  at or below 1,100 lines throughout.

## 5. User scenarios

1. **URL identity.** Given the allowlist `["https://agent.example/keys.json"]`
   and a valid request signed with a key from that directory, when the request
   sends `Signature-Agent: sig1="https://agent.example/keys.json?v=3"`, then the
   outcome is `verified` and `operator` is `https://agent.example/keys.json`.
2. **Another path on the same host.** Given the same allowlist, when a request
   signed with the same key sends `sig1="https://agent.example/other.json"`,
   then the outcome is `unknown_operator`, `operator` is None, `claimed_agent`
   is `https://agent.example/other.json`, and nothing is fetched.
3. **Bare origin.** Given the allowlist `["https://agent.example"]`, when a
   valid request sends `sig1="https://agent.example"`, then the verifier fetches
   `https://agent.example/.well-known/http-message-signatures-directory` and the
   outcome is `verified` with `operator` `https://agent.example/`.
4. **Outage keeps keys.** Given a warm cache for an allowlisted identifier,
   when the refresh returns `200 {"error": "x"}`, then requests signed with the
   cached key keep verifying.
5. **Removal still revokes.** Given a warm cache, when the refresh returns a
   valid JWKS without the key, then the key stops verifying.
6. **Two signers.** Given a request with labels `agent` and `browser` (-01 App.
   D.2 shape), when `verify_all` runs, then each label is verified on its own
   key and attributed only to its own member, and `verify` returns the `agent`
   result.
7. **Member key mismatch.** Given a request whose label `sig2` covers
   `"signature-agent";key="agent2"`, when it is verified, then the outcome is
   `invalid`.
8. **Test key in a directory.** Given an allowlisted directory that serves the
   RFC 9421 B.1.4 key, when a request signed with that key arrives, then it is
   not `verified`; with `allow_test_keys=True` it is.
9. **Redistributed list.** Given keys added with
   `add_untrusted_directory(url, jwks)` (no `fetched=True`), when a request
   signed with one of them names `url`, then the outcome is `signed_untrusted`
   with `operator` None and `keyid` set.
10. **Signer.** Given `sign_request(req, key, agent="https://agent.example")`,
    then the request carries `Signature-Agent: sig1="https://agent.example"` and
    covers `"signature-agent";key="sig1"`; `sign_request(req, key)` without
    `agent` raises `TypeError` and `agent="http://x"` raises `ValueError`.
11. **Refusal.** Given an origin that requires signatures, when it refuses an
    unsigned request, then the docs tell it to send 403 with the value of
    `accept_signature_header()`.

## 6. Success criteria

- **SC-001** -01 E.2.1 and E.2.2 verify byte for byte with the B.1.4 key at
  `now=1735689600` (`allow_test_keys=True`, `max_lifetime=None`), with
  `operator == "https://signature-agent.test/"`; with the default denylist they
  do not verify.
- **SC-002** `cd web-bot-auth/scripts && uv run python -m unittest -v test_web_bot_auth`
  reports 0 failures and 0 errors, and more tests than the baseline 84; the run
  output is saved and the count quoted in the PR.
- **SC-003** `uv run python scripts/check_size.py` passes;
  `web_bot_auth.py` ≤ 1,100 lines; no function > 50 lines;
  `scripts/size_baseline.json` is `{}`.
- **SC-004** `test_vectors_file_is_current` passes; exactly one vector uses the
  legacy string form.
- **SC-005** In every directory attack test, the fetched URLs are a subset of
  the configured fetch URLs, and no result attributes a request to an
  identifier whose directory did not provide the key.
- **SC-006** `rg -n "architecture-05|directory-05|agent_as_dictionary|normalize_origin|directory_url" web-bot-auth/`
  finds nothing (CHANGELOG history is outside `web-bot-auth/`).
- **SC-007** `uv sync --locked` succeeds after the version bump.
- **SC-008** Every pre-existing test whose expected outcome changes is listed in
  the PR with the -01 section that changes it.

## 7. Edge cases (by category)

- Null/empty/zero: empty Signature-Agent; empty dictionary; empty `keys` list
  (valid, replaces cache); `@query-param` with empty value (`qux=` gives an
  empty component value); empty path in identifier; no `web-bot-auth` label in
  `verify_all`.
- Boundaries: identifier length 2,048 vs 2,049; `max_keys` 64 vs 65; eighth vs
  ninth signature label; port 443 vs 8443; `max_age`/expiry as today.
- Invalid data: http/data scheme; userinfo; fragment; bad port; bad
  percent-encoding; non-ASCII; member with parameters; non-String member; JSON
  that is a list or string; `keys` not a list; `@query-param` without `name` or
  with extra parameters.
- Concurrency: concurrent cold fetches for two identifiers on one host each
  reserve their own attempt; concurrent `add_untrusted_directory` and resolve;
  two labels sharing a nonce.
- Errors: fetch raises, times out or returns non-JSON while warm (cache kept);
  nonce store error per label in `verify_all`.
- State transitions: warm → failed refresh → still warm; warm → valid refresh
  without key → evicted; allowlisted → removed → untrusted → expired; unattributed
  pool re-added → replaced; pool expired → gone.
- Security: request-named URLs never fetched; path claim on an allowlisted host
  not attributed; dot-segment and percent-encoding spellings collapse to one
  identifier (so they cannot mint identities) while different paths stay
  different; test keys rejected; outer signature covering an inner one does not
  make the inner one valid.

## 8. Risks

- Line budget: the projected final size is about 1,096 of 1,100 lines (plan,
  "Line budget"). See the second clarification marker.
- Breaking changes for integrators: `operator` values gain a trailing `/` and
  path; allowlists naming the same host twice now mean two identifiers;
  `agent_as_dictionary` and `agent=None` are gone; third-party lists lose
  attribution unless marked `fetched=True`. All go into the CHANGELOG.

## Clarifications

### 2026-11-12

The user was asked five design-fork questions, each with a recommendation
(gap analysis §5, path above). The user's reply, verbatim:

> all five; the last one keeps the file under its line limit.

Interpretation recorded for correction at plan approval: "all five" accepts the
recommendation of every question, and "the last one keeps the file under its
line limit" endorses the reason given in question 5 for skipping
directory-response-signature verification. If that reading is wrong, the user
corrects it when approving the plan.

Decisions, as relayed by the lead agent on 2026-11-12:

1. Switch to -01 URL identity (normalized Signature-Agent URL without query;
   allowlist entries become full URLs) — YES.
2. Bare-origin Signature-Agent: keep the /.well-known mapping as a documented
   compatibility rule.
3. Keep accepting the legacy string Signature-Agent form: yes. Accept member
   key differing from signature label: no. Drop `agent_as_dictionary`, make
   `agent` required in sign_request: yes.
4. Multiple signatures: add `verify_all()`; `verify()` keeps first-label
   behaviour.
5. Include: test-key denylist on by default; max_keys cap;
   Accept-Signature/status-code guidance + small helper. Skip
   Policy.require_https. Skip directory-response signature checking; instead
   keys added via add_untrusted_directory without our own fetch are credited to
   no URL.

Also in scope (lead agent, same date): the §6.10 cache-eviction bug fix,
`@target-uri` acceptance, `@query-param` support, regenerated vectors, the -01
Appendix E vectors as tests, the pyproject version fix, release as 0.2.0 with a
CHANGELOG entry that flags the breaking changes and the identity fix as a
security fix, and doc updates including the README on `docs/readme`.

Choices made in this spec without a separate question (flag any you disagree
with at approval): a member with parameters gives the no-URL path, not INVALID
(§3.4); a cap of eight signatures in `verify_all` (§3.5); `max_keys=64`;
identifier length cap 2,048; static configuration with a test key raises rather
than silently dropping it; `Result.operator` uses the normalized form with a
trailing `/` for bare origins.

Open:

- [NEEDS CLARIFICATION: README sequencing. Proposal: wait for `docs/readme`
  (62de1d4) to merge, then rebase `feat/retarget-httpsig-01` onto `main` before
  its first push and do the README task (plan T14) on top. If `docs/readme` is
  still unmerged when every other task is done, ship 0.2.0 without T14 and
  update the README in a follow-up PR. The alternative, rebasing onto
  `docs/readme` now, ties this branch to an unreviewed branch.]
- [NEEDS CLARIFICATION: line-budget fallback. The estimate leaves about 4 lines
  of headroom (±10). If a task would push `web_bot_auth.py` past 1,100, the
  plan stops and asks. Proposed fallback, in order: (a) ship
  `accept_signature_header` as a copy-paste snippet in `references/adapters.md`
  instead of in the module (−7 lines); (b) move `RedisNonceStore` into
  `references/nonce-stores.md` as a snippet (−13 lines, removes a public name).
  Approve, reorder or replace.]
