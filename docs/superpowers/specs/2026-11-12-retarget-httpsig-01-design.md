# Retarget the web-bot-auth skill to draft-ietf-webbotauth-httpsig-protocol-01

- Date: 2026-11-12 (revision 1, after the analyze pass)
- Status: approved 2026-11-12 and implemented on this branch
- Branch: `feat/retarget-httpsig-01` (from `main` @ d35a52b)
- Plan: `docs/superpowers/plans/2026-11-12-retarget-httpsig-01.md`
- Target release: 0.2.0 on this branch (breaking; contains security fixes).
  Items deferred to 0.3.0 are in §9 and are not implemented on this branch.

## 1. Background

The verifier in `web-bot-auth/scripts/web_bot_auth.py` (0.1.1) targets
`draft-meunier-web-bot-auth-architecture-05` plus
`draft-meunier-http-message-signatures-directory-05`. Both were replaced. The
current document is the working-group draft
`draft-ietf-webbotauth-httpsig-protocol-01` (29 Oct 2026, "-01" below). It folds
the directory format, the well-known URI and the media type into itself, so the
retarget has one normative document plus RFC 9421, 9530, 7638, 8037, 9651 and
3986.

Sources checked for this spec:

- -01 text: `https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-01.txt`
  (2,464 lines). Read in full for revision 0; for revision 1, §4.1–§4.5, §5.2,
  §5.2.1, §5.5, §5.5.3, §6.6.1, §6.8, §6.10 and the changelog were re-read.
- RFC 9421 §2.2.8 (`@query-param`) and §5.1–5.2 (`Accept-Signature`), from
  `https://www.rfc-editor.org/rfc/rfc9421.txt` (revision 0; both now in §9).
- RFC 3986 §3.2.2–§3.4 grammar, §5.2.4 and §6.2.2–§6.2.3, from
  `https://www.rfc-editor.org/rfc/rfc3986.txt` (revision 1).
- Gap analysis (prior, read-only):
  `/home/eldan/.cache/claude-tmp/claude-1000/-home-eldan-projects-web-bot-auth-skill/b6c82dcc-11ca-4f3f-ad39-f9681656b973/scratchpad/retarget-01-plan.md`.
- Analyze pass (independent Opus, read-only):
  `/home/eldan/.cache/claude-tmp/claude-1000/-home-eldan-projects-web-bot-auth-skill/b6c82dcc-11ca-4f3f-ad39-f9681656b973/scratchpad/retarget-01-analyze.md`.
  Every finding's disposition is in the plan ("Analyze findings disposition").
- Code at `main` @ d35a52b, read directly (the codebase-memory MCP server was not
  connected). Baseline: 84 tests pass, size gate passes, `web_bot_auth.py` is
  1,017 lines, `Verifier._verify` is 113 lines and is the only baseline entry.
- Probe (scratchpad, not in the repo): the -01 E.2.1 (dictionary) and E.2.2
  (legacy string) vectors already verify with the current code under
  `Policy(max_age=10**10, max_lifetime=None)` at `now=1735689600`.
- Prototype (scratchpad `proto/norm.py`, throwaway, not in the repo): §3.1 as
  written below is 77 lines including `_directory_entry`; it produced every
  row of the §3.1 table. This is the basis of the plan's line budget.

## 2. What changes in -01 that matters to this code

| -01 | Rule | Current code | Gap | Release |
|---|---|---|---|---|
| §5.2 | At least one of `@authority`, `@target-uri` | requires `@authority` (`_verify`) | rejects valid `@target-uri`-only signatures | 0.2.0 |
| §5.2 | Agents SHOULD consider `@query-param` | any parameter on a derived component raises | `@query-param` signatures are INVALID | 0.3.0 |
| §5.2.1 | Member keyed to the signature label MUST be signed; members with parameters MUST be ignored; signers MUST send the dictionary form; verifiers MAY accept the legacy string as `{label: value}` | first covered `signature-agent` wins; any key accepted; parameters ignored; signer defaults to the legacy string | wrong member selection; signer non-conformant | 0.2.0 |
| §6.6.1 | An intermediary may relabel the Signature member; it MUST NOT alter a covered Signature-Agent member key | n/a | a relabeled signature covers a member key that no longer equals its label; must not read as hostile (§3.4 rule 3) | 0.2.0 |
| §4.3, §5.2.5 | A signed request MUST carry Signature-Agent; no URL means the identifier is the keyid thumbprint | `sign_request(agent=None)` omits it | signer non-conformant | 0.2.0 |
| §4.1, §4.4, §5.4, §5.5 | Identifier is the resolved Signature-Agent URL, query dropped, RFC 3986 §6.2.2/§6.2.3 normalized, compared octet for octet; never attribute without making the (URL, key) association; an unresolved URL is a claim and verifiers MUST NOT attach policy to it | identity is the origin; a request naming any path on an allowlisted origin is attributed to the origin | identity overclaims: "TLS authenticates the host but not the path" (§5.5) | 0.2.0 |
| changelog -01 | "Make every Signature-Agent value a direct JWK Set URI" | a bare origin is mapped to the well-known path | kept as a documented deviation (§3.2) | 0.2.0 |
| §5.2.2 | Several signatures; verifiers MUST validate each independently | only the first `web-bot-auth` label is verified | no API to verify the others | 0.3.0 |
| §5.5.3 | Redistributed keys carry no URL unless they carry a valid directory response signature | `add_untrusted_directory` attributes keys to the given URL | overclaims for third-party lists | 0.2.0 |
| §4.4, §6.10 | A failed resolution, including "not a directory", MUST NOT evict a cached entry; a resolved directory without the key is evidence and replaces it; the newer pair wins | a 200 JSON body without `keys` parses to `{}` and overwrites the cache | bug: evicts good keys | 0.2.0 |
| §6.7 | Verifiers SHOULD enforce a maximum key count | none | missing SHOULD | 0.2.0 |
| §6.8 | Verifiers SHOULD reject known test keys in directories or configuration | none | missing SHOULD | 0.2.0 |
| §5.3, §5.4 | Origin SHOULD send `Accept-Signature` when it expects signatures; refusal usually 403 with `Accept-Signature`; 400 MAY on parse failure; 429 MAY on over-used nonce | docs say "Block" | missing guidance | 0.3.0 |
| App. E | E.1.x (RSA-PSS), E.2.1, E.2.2 (Ed25519), E.2.3 (signed directory response) | RFC 9421 B.2.6 vector only | -01 vectors not run | 0.2.0 |

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

## 3. Design (0.2.0)

### 3.1 Identifier

`normalize_agent_url(url) -> str` (public) returns the -01 identifier. A private
`_split_agent_url(url) -> (identifier, query_or_None)` does the work; the query
is validated and normalized like the path, then dropped from the identifier
(-01 §5.5) and kept only for fetch URLs (§3.2). Every rejection is a
`ValueError`. The rules, in order:

1. **Type and length.** A `str` of 1 to 2,048 characters, all ASCII.
2. **Character set.** Every character is in the RFC 3986 set: unreserved
   (`A-Z a-z 0-9 - . _ ~`), sub-delims (`! $ & ' ( ) * + , ; =`),
   `: / ? @ [ ] %`. This rejects space, every control character (including
   tab and `0x7F`), `"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, `}`. The
   backslash is named on purpose: WHATWG URL parsers read it as `/`, so a port
   that accepted it would derive a different identifier.
3. **Scheme.** The value starts with `https://`, compared case-insensitively.
   Any other scheme, and a missing `//`, is rejected.
4. **Fragment and userinfo.** Any `#` is rejected (so an empty fragment `...#`
   is rejected too). Any `@` in the authority is rejected.
5. **Split.** The authority runs from after `https://` to the first `/` or `?`.
   The path runs from there to the first `?`; the rest is the query.
6. **Host.** Either an IP literal or a name:
   - IP literal: `[` ... `]`, whose content must parse as an IPv6 address
     (`ipaddress.IPv6Address`); IPvFuture and zone identifiers (`%25...`) are
     rejected. It is lowercased and kept in brackets; it is not compressed
     (RFC 3986 only defines case normalization for it).
   - Name (DNS name or IPv4): percent-encodings are decoded only where they
     encode unreserved characters (rule 9), then the host is lowercased.
     After that every character must be unreserved; sub-delims and any
     remaining percent-encoding in the host are rejected (a narrowing of RFC
     3986 `reg-name`, which no HTTPS host needs). The host must not be empty.
     A trailing dot is kept (`agent.example.` is a different identifier; RFC
     3986 does not define it).
   - `[` and `]` anywhere other than around an IP literal are rejected.
7. **Port.** After the host, either nothing, or `:` followed by an empty port
   (removed, RFC 3986 §6.2.3), or 1 to 5 ASCII digits with no leading zero
   and a value of 1 to 65535. Port 443 is removed (§6.2.3); any other port is
   kept as written. `:0443`, `:0`, `:65536`, `:+443` and `:x` are rejected.
   The port is parsed by hand, not with `urlsplit().port`, whose behaviour
   differs across Python versions.
8. **Path and query characters.** Path characters are RFC 3986 `pchar` plus
   `/`; query characters are `pchar` plus `/` and `?`.
9. **Percent-encoding (§6.2.2.1–2), in host, path and query.** Every `%` is
   followed by two hex digits (else reject). An encoding of an unreserved
   character is decoded (`%7e` → `~`, `%2E` → `.`); every other encoding keeps
   its octet and has its hex uppercased (`%2f` → `%2F`). Case is otherwise kept
   in the path and query.
10. **Dot segments (§6.2.2.3).** After rule 9, the path has its dot segments
    removed with the RFC 3986 §5.2.4 algorithm, so `%2E%2E` counts as `..`.
    `%2F` is not a separator. An empty path becomes `/` (§6.2.3). A trailing
    slash is kept: `/k` and `/k/` are different identifiers.
11. **Output.** `https://` + host + (`:` + port, unless removed) + path.

Hand-written expectations (the T8 tests and the T12 `normalization` vectors use
this table; they are not computed by the verifier):

| Input | Identifier |
|---|---|
| `HTTPS://Agent.EXAMPLE/K` | `https://agent.example/K` |
| `https://agent.example:443` | `https://agent.example/` |
| `https://a.example:/` | `https://a.example/` |
| `https://a.example:8443/x` | `https://a.example:8443/x` |
| `https://Agent.Example:443/a/./b/../%7euser/k%2fs.json?v=3` | `https://agent.example/a/~user/k%2Fs.json` |
| `https://a.example/a/..` | `https://a.example/` |
| `https://a.example/a/.` | `https://a.example/a/` |
| `https://a.example/%2E%2E/x` | `https://a.example/x` |
| `https://%61.example/` | `https://a.example/` |
| `https://[2001:DB8::1]/` | `https://[2001:db8::1]/` |
| `https://agent.example.` | `https://agent.example./` |
| `https://a.example?x=1` | `https://a.example/` |

Rejected (one row each): empty string; `agent.example`; `http://a.example`;
`data:x`; `https:///k`; `https://u@a.example/`; `https://a.example/#f`;
`https://a.example#`; `https://a.example:x/`; `https://a.example:0/`;
`https://a.example:0443/`; `https://a.example:65536/`; `https://a.example/%zz`;
`https://a.example/%4`; non-ASCII host; space; tab; `0x7F`; `\`; `"`; `{`; `|`;
`^`; `https://[v1.x]/`; `https://[fe80::1%25eth0]/`; `https://a.example/[`;
`https://a.ex%2Fample/`; `https://a!.example/`; 2,049 characters (2,048 is
accepted).

`normalize_origin` and `directory_url` are removed.

### 3.2 Allowlist and fetch location

`DirectoryKeyResolver(allowlist)` entries are full https URLs. For each entry,
`_directory_entry(entry) -> (identifier, fetch_url)`:

- identifier = `normalize_agent_url(entry)`;
- fetch URL = the identifier plus the entry's normalized query, except that an
  entry whose identifier is a bare origin (path `/`) fetches
  `https://host[:port]/.well-known/http-message-signatures-directory` plus the
  query.

**Deviation from -01 §4.1/§4.4 (bare-origin rule).** -01 makes every
Signature-Agent value a direct JWK Set URI (changelog) and says the identifier
is the URL the verifier fetched (§4.1). For a bare origin this verifier fetches
the well-known URL instead and keeps `https://host/` as the identifier, so the
fetched URL and the identifier differ. This is deliberate: the well-known path
is reserved for the domain operator (-01 §4.5, RFC 8615), so the key set it
serves endorses the bare origin as strongly as it endorses the well-known URL;
and 0.1.1 allowlists and deployed agents (including -01's own E.2 examples,
`sig2="https://signature-agent.test"`) use bare origins. The docs and the
CHANGELOG call it a deviation, not a -01 rule.

**Interop consequence.** `https://host/` and
`https://host/.well-known/http-message-signatures-directory` are two different
identifiers (-01 §5.5 compares octets). An agent that sends the explicit
well-known URL does not match a bare-origin allowlist entry and gets
`unknown_operator`. The docs and CHANGELOG tell operators to allowlist both
spellings when an agent may send either. Two such entries fetch the same URL
twice and keep two caches; this is accepted (no fetch coalescing; -01 App. C.3
only suggests it).

Other rules:

- Two entries with the same identifier but different fetch URLs (for example
  two queries) raise `ValueError` naming the identifier, in any order. Different
  paths on one host are different identifiers and do not conflict.
- `resolver.allowlist` is the set of identifiers. Its `add(value)` raises
  `ValueError` unless `value == normalize_agent_url(value)`, and the message
  names the normalized form; so the 0.1.1 idiom `allowlist.add("https://host")`
  fails loudly instead of never matching. A runtime-added identifier fetches
  itself, or the well-known URL if its path is `/`. Removing an identifier
  revokes trust immediately, as today.
- The private fetch-URL map is renamed `_fetch_urls` (it was `_directory_urls`).
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
- Custom-resolver contract change: `resolve`, `is_allowlisted` and
  `directory_unavailable` now receive normalized identifiers (not origins).
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
   dictionary, its member `L` is used (the whole field is covered); a
   dictionary without member `L` is INVALID "cannot determine Signature-Agent
   value".
3. Otherwise only `signature-agent;key=X` components with `X != L` are covered:
   the member is **ignored** and the signature takes the no-URL path of rule 5
   (Clarification 2026-11-12b, item 3). Not INVALID: an intermediary may
   relabel the Signature member (-01 §6.6.1, RFC 9421 §7.2.5) but cannot change
   the covered member key, so a relabeled signature lands here. Not
   attributed to member `X` either: -01 §5.2.1 requires the member keyed to
   the label. `claimed_agent` stays None.
4. Header present but no `signature-agent` covered: INVALID (unchanged).
5. Header absent: no URL; the identifier is the thumbprint (unchanged; -01
   §4.3). The key is looked up with `operator=None`.

The selected member:

- carries parameters → ignored (-01 §5.2.1 MUST): the no-URL path of rule 5.
- is not a String, or its value fails `normalize_agent_url` → INVALID
  (stricter than the -01 MAY-ignore; unchanged behaviour).

What the no-URL path yields depends on the resolver, exactly as for a request
without the header: with `DirectoryKeyResolver` it is `signed_untrusted`
(operator None) when the key is in an unattributed pool (§3.7) and otherwise
`unknown_operator` "no key for this operator"; with `StaticKeyResolver` it is
what its `None` entry gives. It is never INVALID because of the label mismatch
and never attributed. Settled in Clarifications 2026-11-12c (the outcome stays
`unknown_operator`).

### 3.5 Multiple signatures

Deferred to 0.3.0 (§9). `Verifier.verify(req)` keeps its contract: the first
`web-bot-auth` label only.

### 3.6 Directory parsing

`parse_directory(data, max_keys=64, allow_test_keys=False)`:

- raises `ValueError` unless the document is a JSON object whose `keys` is a
  list (a discovery failure, which `_refresh` already treats as "keep the last
  good copy");
- raises `ValueError` when `len(keys) > max_keys` (counted before filtering);
- skips JWKs whose thumbprint is in `TEST_KEY_THUMBPRINTS` unless
  `allow_test_keys`.

`TEST_KEY_THUMBPRINTS` (exported) holds, each computed with the repo's
`jwk_thumbprint` on 2026-11-12:

| Key | Source | Thumbprint |
|---|---|---|
| Ed25519 `x=JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs` | RFC 9421 App. B.1.4; -01 E.2 and §5.5.1 examples | `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U` |
| Ed25519 `x=11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` | RFC 8037 App. A.1 (a -01 normative reference) | `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` |
| `generate_vectors.KEY` (`x=SJUTQy84WjB_Cq9wkBIZ0TZmXQr7oG4Qo2SykDItiN0`) | this skill's published `assets/test-vectors.json` | `CaJn8r1wQ6jaeqa0H9w0Xw4n2xguAKi6vziTdPQqqFs` |
| `generate_vectors.OTHER` (`x=hXOBU2vlJ6UWSGIhxRtqMaa7n_9fhKVTJJtvupLHlNc`) | same | `UBQJjBYkCFLaFgwMbZIQWpA2VRag2Y4CVF51WNWQS-s` |

The RFC 8037 row: the `x` value was derived from the RFC's A.1 private key `d`
with the repo code, and its thumbprint equals the value RFC 8037 A.3 publishes
(both values confirmed against rfc8037.txt by the T13 review). -01 §6.8 says
"including", so the list is not exhaustive; the docs say so.

`StaticKeyResolver(keys, trusted=True, allow_test_keys=False)` raises
`ValueError` naming the thumbprint when configuration contains a test key (fail
fast on configuration). `DirectoryKeyResolver(..., max_keys=64,
allow_test_keys=False)` passes both through. When resolution finds no key and
the keyid is in `TEST_KEY_THUMBPRINTS`, the reason is "known test key
rejected" instead of "unknown keyid for allowlisted operator" (the outcome is
unchanged). A directory that resolves and lacks the key still replaces the
cache (-01 §6.10 "evidence"). `generate_vectors.build` and ports running the
vectors pass `allow_test_keys=True`; the vectors' description says so.

### 3.7 Redistributed keys

`add_untrusted_directory(url, data, ttl=3600, now=None, *, fetched=False)`:

- `fetched=True`: the caller fetched `url` itself over TLS (a background job or
  a control plane, -01 §5.5.3 para. 2). Keys are attributed to
  `normalize_agent_url(url)` and resolve as `signed_untrusted`, as today.
- `fetched=False` (default): the keys verify but carry no URL. They are stored
  per source (`url` is only the replacement key, so re-adding the same list
  replaces it, -01 §4.4 "newer pair wins") and expire after `ttl`. A request
  whose own identifier has no usable key falls back to these pools, subject to
  the next rule; a hit gives `signed_untrusted` with `operator=None`.
- **Removal wins** (Clarification 2026-11-12b, item 2). When the claimed
  identifier is allowlisted and has a fresh resolved directory (not expired,
  that is `directory_unavailable` is False) that lacks the key, the pools are
  not consulted and the result stays INVALID "unknown keyid for allowlisted
  operator". The operator's own, newer directory is evidence that the key was
  removed (-01 §4.4, §6.10); a stale list must not keep it verifying under
  that operator's name. When the identifier's directory is unavailable (cold
  and failed, or expired), the pools are consulted (-01 §6.10: the request
  may still verify by other means, identified by thumbprint).
- An allowlisted identifier still raises `ValueError` (fetched, not added).

### 3.8 Signer

`sign_request(req, key, *, agent, components=(..., "signature-agent"), label="sig1", ...)`:

- `agent` is required and must pass `normalize_agent_url` (`ValueError`
  otherwise); `agent_as_dictionary` is removed.
- Always sends `Signature-Agent: <label>="<agent>"` and covers
  `"signature-agent";key="<label>"`.
- `components` must include `"signature-agent"` and at least one of
  `"@authority"`, `"@target-uri"` (-01 §5.2 MUST); `ValueError` otherwise.
- The signing core moves to a private `_sign(req, key, covered, label)` that
  tests and `generate_vectors.py` use to build legacy, no-header and
  non-conformant requests.

### 3.9 Derived components

`@target-uri` satisfies the "@authority or @target-uri" rule; the reason text
becomes "@authority or @target-uri must be covered". `@query-param` is deferred
(§9).

### 3.10 Accept-Signature helper and status codes

Deferred to 0.3.0 (§9).

## 4. Requirements

FR numbers are stable across revisions. Deferred ones keep their number and say
so; they are specified in §9.

- **FR-001** The verifier accepts a signature that covers `@target-uri` and not
  `@authority`; it rejects one that covers neither.
- **FR-002** *(Deferred to 0.3.0, §9.)* `@query-param` support.
- **FR-003** The verifier selects the Signature-Agent member as in §3.4; a
  covered member whose key differs from the label is ignored (the no-URL path),
  not INVALID and not attributed; the legacy sf-string is accepted only through
  a bare `"signature-agent"` component.
- **FR-004** A selected member that carries parameters is ignored and the
  request is treated as having no Signature-Agent URL.
- **FR-005** `normalize_agent_url` implements every rule and rejection of §3.1.
- **FR-006** Attribution follows §3.3: `Result.operator` is set only from that
  identifier's own resolution; `Result.claimed_agent` carries the normalized
  claim; a request naming identifier A is never attributed using keys resolved
  for identifier B != A.
- **FR-007** A bare-origin allowlist entry fetches the well-known URL and its
  identifier is `https://host/` (documented deviation, §3.2); every other entry
  is fetched as configured.
- **FR-008** Allowlist configuration follows §3.2: identifier-level conflict
  detection, `allowlist.add` rejects non-normalized values, independent cache
  and rate limit per identifier, no fetch of any request-named URL.
- **FR-009** A directory response that is not a JSON object with a `keys` list
  is a discovery failure and does not evict a cached copy; a valid directory
  without the key replaces the cached copy.
- **FR-010** `parse_directory` rejects a directory with more than `max_keys`
  entries (default 64) as a discovery failure.
- **FR-011** The four keys of §3.6 are rejected by default: dropped from fetched
  or added directories (reason "known test key rejected"), and a `ValueError`
  for static configuration; both have an `allow_test_keys=True` opt-out.
- **FR-012** *(Deferred to 0.3.0, §9.)* `Verifier.verify_all`.
- **FR-013** `sign_request` implements §3.8, including the
  `@authority`/`@target-uri` check.
- **FR-014** `add_untrusted_directory` implements §3.7.
- **FR-015** *(Deferred to 0.3.0, §9.)* `accept_signature_header` and the
  status-code guidance.
- **FR-016** The -01 Appendix E vectors run as tests: E.2.1 and E.2.2 verify;
  E.1.1 and E.1.2 are INVALID "unsupported alg"; E.2.3's Content-Digest matches
  its body (directory response signatures are out of scope).
- **FR-017** `assets/test-vectors.json` is regenerated: dictionary form by
  default, one legacy-string vector, new cases for FR-001, FR-003, FR-004
  and FR-006 (FR-021 has no vector: the vector format has `trusted_keys` and a
  `StaticKeyResolver` but no resolver pools, so FR-021 is unit-tested in T9),
  `trusted_keys` keyed by normalized identifiers,
  `expected.operator` and `expected.claimed_agent` given for accepted outcomes,
  and a `normalization` section (input → identifier or `null` for reject) taken
  from the §3.1 table. A hand-written name → expected-outcome table in the test
  suite checks the vectors independently of `build()`.
- **FR-018** Docs describe -01 for the 0.2.0 scope: module docstring and
  docstrings, `SKILL.md`, `references/policy-decisions.md`,
  `references/adapters.md`, `references/nonce-stores.md`, and the README spec
  status (on `main` in this PR at minimum; see Clarifications).
- **FR-019** Release 0.2.0: `CHANGELOG.md` entry with Breaking, Security, Fixed
  and Added sections; `pyproject.toml` version 0.2.0 and a regenerated
  `uv.lock` (CI runs `uv sync --locked`, and the lock pins the project
  version).
- **FR-020** `Verifier._verify` is split by responsibility so that every
  function is at most 50 lines and its baseline entry is removed; the file stays
  within the line limit settled in Clarifications throughout.
- **FR-021** Removal wins (§3.7): a request naming an allowlisted identifier
  whose fresh directory lacks the key is INVALID even when an unattributed pool
  holds the key.

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
6. *(Deferred to 0.3.0: two signers through `verify_all`.)*
7. **Member key differs from the label.** Given a request whose label `sig2`
   covers only `"signature-agent";key="agent2"` (for example after an
   intermediary relabeled `agent2` to `sig2`), when it is verified, then the
   member is ignored: the outcome is not `invalid`, `operator` and
   `claimed_agent` are None, and with a `DirectoryKeyResolver` that holds the
   key only in its allowlisted directory the outcome is `unknown_operator`.
8. **Test key in a directory.** Given an allowlisted directory that serves the
   RFC 9421 B.1.4 key, when a request signed with that key arrives, then it is
   `invalid` with reason "known test key rejected"; with
   `allow_test_keys=True` it is `verified`.
9. **Redistributed list.** Given keys added with
   `add_untrusted_directory(url, jwks)` (no `fetched=True`), when a request
   signed with one of them names `url`, then the outcome is `signed_untrusted`
   with `operator` None and `keyid` set.
10. **Signer.** Given `sign_request(req, key, agent="https://agent.example")`,
    then the request carries `Signature-Agent: sig1="https://agent.example"` and
    covers `"signature-agent";key="sig1"`; `sign_request(req, key)` without
    `agent` raises `TypeError`; `agent="http://x"` raises `ValueError`;
    `components=("@method", "@path", "signature-agent")` raises `ValueError`.
11. *(Deferred to 0.3.0: refusal with `Accept-Signature`.)*
12. **Removal wins over a third-party list.** Given the allowlisted identifier
    `https://agent.example/keys.json` whose freshly fetched directory no longer
    contains key K, and a third-party list added with
    `add_untrusted_directory("https://lists.example/bots.json", ...)` that
    still contains K, when a request signed with K names
    `https://agent.example/keys.json`, then the outcome is `invalid` "unknown
    keyid for allowlisted operator". When the same identifier's directory is
    instead unavailable (cold cache, fetch fails), then the outcome is
    `signed_untrusted` with `operator` None.
13. **Explicit well-known vs bare origin.** Given the allowlist
    `["https://agent.example"]`, when a valid request sends
    `sig1="https://agent.example/.well-known/http-message-signatures-directory"`,
    then the outcome is `unknown_operator` and nothing is fetched; with both
    spellings allowlisted, both requests are `verified`, each with its own
    `operator`.
14. **Runtime add of a non-normalized value.** Given a `DirectoryKeyResolver`,
    when the code calls `resolver.allowlist.add("https://agent.example")`, then
    it raises `ValueError` naming `https://agent.example/`.

## 6. Success criteria

- **SC-001** -01 E.2.1 and E.2.2 verify byte for byte with the B.1.4 key at
  `now=1735689600` (`allow_test_keys=True`, `max_lifetime=None`), with
  `operator == "https://signature-agent.test/"`; with the default denylist they
  do not verify.
- **SC-002** `cd web-bot-auth/scripts && uv run python -m unittest -v test_web_bot_auth`
  reports 0 failures and 0 errors, and more tests than the baseline 84; the run
  output is saved and the count quoted in the PR.
- **SC-003** `uv run python scripts/check_size.py` passes;
  `web_bot_auth.py` is within the limit settled in Clarifications 2026-11-12c (1,150; it was 1,100 before that answer);
  no function > 50 lines; `scripts/size_baseline.json` is `{}`.
- **SC-004** `test_vectors_file_is_current` passes; exactly one vector uses the
  legacy string form; the hand-written expectation table and the
  `normalization` section both pass.
- **SC-005** In every directory attack test, the fetched URLs are a subset of
  the configured fetch URLs, and no result attributes a request to an
  identifier whose directory did not provide the key (one assertion helper,
  used by every `DirectorySecurity` and `DirectoryTrust` test).
- **SC-006** `rg -n "architecture-05|directory-05|agent_as_dictionary|\bnormalize_origin\b|\bdirectory_url\b" web-bot-auth/`
  finds nothing (CHANGELOG history is outside `web-bot-auth/`; `\b` keeps
  `_directory_urls`-style names from matching, and that attribute is renamed
  anyway).
- **SC-007** `uv sync --locked` succeeds after the version bump.
- **SC-008** Every pre-existing test whose expected outcome changes is listed in
  the PR with the -01 section that changes it. The list also names the
  behaviours that changed against revision 0 of this spec: §3.4 rule 3 (ignored,
  was INVALID) and FR-021 (removal wins, was a pool fallback). FR-021 keeps the
  0.1.1 outcome for this case (INVALID), so it is in the CHANGELOG under
  Security, not Breaking.

## 7. Edge cases (by category)

- Null/empty/zero: empty Signature-Agent; empty dictionary; empty `keys` list
  (valid, replaces cache); empty path and empty port in an identifier; port 0.
- Boundaries: identifier length 2,048 vs 2,049; `max_keys` 64 vs 65; port 443
  vs 8443 vs 65535 vs 65536; pool `ttl` edge; `max_age`/expiry as today.
- Invalid data: http/data scheme; userinfo; fragment; bad port; leading-zero
  port; bad percent-encoding; non-ASCII; every rejected character of §3.1;
  member with parameters; non-String member; JSON that is a list or string;
  `keys` not a list; non-normalized `allowlist.add`.
- Concurrency: concurrent cold fetches for two identifiers on one host each
  reserve their own attempt; concurrent `add_untrusted_directory` and resolve.
- Errors: fetch raises, times out or returns non-JSON while warm (cache kept);
  fetch fails cold while a pool holds the key (pool used).
- State transitions: warm → failed refresh → still warm; warm → valid refresh
  without key → evicted, and pools not consulted (FR-021); allowlisted →
  removed → untrusted → expired; unattributed pool re-added → replaced; pool
  expired → gone.
- Security: request-named URLs never fetched; path claim on an allowlisted host
  not attributed; dot-segment and percent-encoding spellings collapse to one
  identifier while different paths stay different; backslash rejected; test
  keys rejected; relabeled member not attributed to the other member; removal
  not undone by a third-party list.

## 8. Risks

- Line budget: the honest projection for 0.2.0 exceeds 1,100 lines (plan, "Line
  budget": about 1,136 without cuts). Settled in Clarifications 2026-11-12c:
  limit raised to 1,150 and `RedisNonceStore` moved out (about 1,123, margin
  27).
- Breaking changes for integrators: `operator` values gain a trailing `/` and
  path; allowlists naming the same host twice now mean two identifiers;
  `allowlist.add` needs normalized identifiers; custom resolvers receive
  identifiers; `agent_as_dictionary` and `agent=None` are gone; third-party
  lists lose attribution unless marked `fetched=True`; test keys rejected by
  default. All go into the CHANGELOG.
- `docs/readme` (62de1d4) quick-start calls
  `sign_request(..., agent_as_dictionary=True)`, which raises `TypeError`
  against 0.2.0. It must be changed before or when that branch merges after
  this one (plan T14).

## 9. Deferred to 0.3.0 (not implemented on this branch)

Each item keeps its FR number. A later plan specifies the tasks.

- **FR-002 `@query-param`** (RFC 9421 §2.2.8). Design as in revision 0 (parse
  the query as HTML form data with blank values kept, encode names and values
  with the urlencoded percent-encode set and `%20` for space, match the encoded
  name, error on a missing, non-String or duplicated name, other parameters,
  or a name absent from the query). Open for 0.3.0 (analyze U6):
  `urllib.parse.parse_qsl` on Python 3.9.0–3.9.1 also splits on `;`; either
  split on `&` by hand or state Python 3.9.2 as the minimum.
- **FR-012 `Verifier.verify_all`** (-01 §5.2.2). One `Result` per
  `web-bot-auth` label, at most eight, each verified independently. Open for
  0.3.0 (analyze U10): `verify()` then `verify_all()` on one request records
  the first nonce twice and reports REPLAY; document "call one of them per
  request" or share the per-label path.
- **FR-015 `accept_signature_header` and status codes** (-01 §5.3, §5.4). The
  helper must raise unless `@authority` or `@target-uri` is in the components
  (analyze I3: -01 §5.3 requires requests consistent with §5.2). The 400 guidance
  must be limited to parse failures in RFC 9421 §3.2 steps 1–3, not every
  "malformed" reason (analyze A3).
- Scenarios 6 and 11, and the vectors `verified_query_param` and
  `two_signatures`, move with them.

## Clarifications

### 2026-11-12

The user was asked five design-fork questions, each with a recommendation
(gap analysis §5, path above). The user's reply, verbatim:

> all five; the last one keeps the file under its line limit.

Interpretation recorded for correction at plan approval: "all five" accepts the
recommendation of every question, and "the last one keeps the file under its
line limit" endorses the reason given in question 5 for skipping
directory-response-signature verification.

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

Choices made in this spec without a separate question (flag any you disagree
with at approval): a member with parameters gives the no-URL path, not INVALID
(§3.4); `max_keys=64`; identifier length cap 2,048; static configuration with a
test key raises rather than silently dropping it; `Result.operator` uses the
normalized form with a trailing `/` for bare origins; ports with a leading zero
are rejected; host characters are limited to unreserved after decoding;
`allowlist.add` raises rather than normalizes.

### 2026-11-12b (after the analyze pass)

The user's reply to the three analyze questions, verbatim:

> 1a 2 rec 3rec

Meaning, as relayed by the lead agent:

1. **(1a) Split the release.** 0.2.0 = the -01 core plus the security fixes:
   URL identity (with the bare-origin compatibility rule), the §6.10
   non-JWKS-no-evict fix, Signature-Agent member selection by label and
   ignoring parameterised members, signer dictionary form with `agent`
   required, `@target-uri`, `max_keys`, the test-key denylist, keys added
   without our own fetch credited to no URL, vectors, docs and CHANGELOG.
   0.3.0 (separate later plan, not on this branch): `verify_all()`,
   `@query-param`, `accept_signature_header` and the
   Accept-Signature/status-code guidance. Those FRs move to §9 with stable
   numbers. The per-task line budget for 0.2.0 is re-estimated honestly and
   the projected total shown against 1,100.
2. **(2, recommendation; analyze U1) Removal wins.** If an allowlisted
   operator's freshly resolved directory lacks the key, the result is invalid
   even if a third-party or untrusted list contains it (§3.7, FR-021,
   scenario 12).
3. **(3, recommendation; analyze U2) Member key differing from the label is
   ignored**, treated as no agent URL, not invalid (§3.4 rule 3, FR-003,
   scenario 7).

The earlier open marker on the line-budget fallback is superseded by the open
marker below, which uses the re-estimate.

Open: none. The three markers that stood here were answered in 2026-11-12c.

### 2026-11-12c (answers to the three open markers; plan approved)

The user's reply, verbatim:

> A, rec, rec, approved

Meaning, in the order of the three markers and the plan:

1. **Line limit: option A.** Raise the `web_bot_auth.py` exception in the repo
   `AGENTS.md` and in `scripts/check_size.py` (`FILE_LIMIT_OVERRIDES`) from
   1,100 to 1,150, and move `RedisNonceStore` to a snippet in
   `references/nonce-stores.md` (removes a public name; Breaking in the
   CHANGELOG). Options B and C are dropped.
2. **No-URL outcome for an ignored member (rec).** The outcome stays
   `unknown_operator` "no key for this operator" when the key is held only in
   an allowlisted identifier's cache (§3.4 rule 3); `signed_untrusted` only
   from an unattributed pool (§3.7). The no-URL lookup does not search
   allowlisted caches by keyid.
3. **README sequencing (rec).** The default applies: T14a always; T14b only if
   `docs/readme` merges first, otherwise the CHANGELOG and PR body say
   "README quick-start update pending" and a follow-up issue is filed.
4. **Plan approved** (`docs/superpowers/plans/2026-11-12-retarget-httpsig-01.md`,
   with the pre-flight rulings R1–R24 applied).
