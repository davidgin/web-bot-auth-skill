# Nonce stores

A nonce store needs one operation: atomically record a key with a TTL, and report whether it was already there. Two properties matter:

- **Shared:** every instance that serves the same origin uses the same store. Otherwise a replay sent to another worker or region goes undetected.
- **Strongly consistent for that operation:** a write is visible to the next read anywhere. Eventually consistent stores let two near-simultaneous copies of a request both succeed.

Keys are `"{keyid}:{nonce}"`, and the TTL is `min(expires, created + max_age) - now + clock_skew`. Nonces are recorded only after the signature verifies.

## Suitable

| Store | How |
| --- | --- |
| Redis / Valkey (single primary) | `SET key 1 NX PX ttl`. Use the included `RedisNonceStore`. |
| Redis Cluster | Same; keys hash to one slot each, so it's fine. Avoid reading from replicas. |
| Memcached | `add` with expiry (atomic set-if-absent). |
| PostgreSQL | Table with a unique key and `expires_at`; `INSERT ... ON CONFLICT DO NOTHING` and check the row count; delete expired rows periodically. |
| Cloudflare Durable Objects | One object per keyid (or a shard of keys) holding a TTL'd map; operations on one object are serialized. |
| DynamoDB | `PutItem` with `attribute_not_exists(pk)` and a TTL attribute. TTL deletion is lazy, so also compare `expires_at` on read. |

## Not suitable

- **In-process memory** with more than one process (`InMemoryNonceStore` is for tests and single-process tools).
- **Cloudflare Workers KV**, or any eventually consistent cache. A replay can land before the first write propagates.
- **Per-region stores** for a multi-region origin, unless agents are pinned to one region.

## Sizing

With the default `max_age` of 300 s, the store holds about `signed requests per second × 305` live keys. At 1,000 signed requests per second that is about 305,000 keys. In Redis, at roughly 150 bytes per key including overhead, that comes to about 45 MB. Lowering `max_age` shrinks the store proportionally.

## When the store is down

The verifier raises `NonceStoreError` inside the store and applies `Policy.fail_closed_methods`. Unsafe methods become `invalid`; safe methods verify with `replay_protected=False`. Alert on this; it should be rare.
