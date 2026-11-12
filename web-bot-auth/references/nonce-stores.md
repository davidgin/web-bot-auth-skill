# Nonce stores

A nonce store needs one operation: atomically record a key with a TTL, and report whether it was already there. Two properties matter:

- **Shared:** every instance that serves the same origin uses the same store. Otherwise a replay sent to another worker or region goes undetected.
- **Strongly consistent for that operation:** a write is visible to the next read anywhere. Eventually consistent stores let two near-simultaneous copies of a request both succeed.

Keys are `"{keyid}:{nonce}"`, and the TTL is `min(expires, created + max_age) - now + clock_skew`. Nonces are recorded only after the signature verifies.

Basis: replay protection and the `nonce` parameter are defined in RFC 9421 section 7.2.2, and -01 section 5.2.3 adds no nonce requirements. -01 Appendix C.6 gives the operational guidance this page follows: rejecting duplicate nonces needs an atomic check-and-record across the enforcement scope, retention and admission of nonce state must be bounded, and if the state is unavailable the verifier must not treat signature validation as evidence that replay was detected or prevented (which is why `replay_protected` is `False` then).

## Suitable

| Store | How |
| --- | --- |
| Redis / Valkey (single primary) | `SET key 1 NX PX ttl`. Use the `RedisNonceStore` snippet below. |
| Redis Cluster | Same; keys hash to one slot each, so it's fine. Avoid reading from replicas. |
| Memcached | `add` with expiry (atomic set-if-absent). |
| PostgreSQL | Table with a unique key and `expires_at`; `INSERT ... ON CONFLICT DO NOTHING` and check the row count; delete expired rows periodically. |
| Cloudflare Durable Objects | One object per keyid (or a shard of keys) holding a TTL'd map; operations on one object are serialized. |
| DynamoDB | `PutItem` with `attribute_not_exists(pk)` and a TTL attribute. TTL deletion is lazy, so also compare `expires_at` on read. |

### Redis snippet

`RedisNonceStore` is not part of `web_bot_auth.py` and cannot be imported from it; copy this snippet into your application. It takes any redis-py compatible client and raises `NonceStoreError` on connection errors, which the verifier turns into `Policy.fail_closed_methods` handling.

```python
from web_bot_auth import NonceStoreError


class RedisNonceStore:
    """Shared store using SET NX PX. Takes any redis-py compatible client."""

    def __init__(self, client, prefix: str = "wba:nonce:"):
        self.client, self.prefix = client, prefix

    def add_if_absent(self, key, ttl_seconds):
        try:
            return bool(self.client.set(self.prefix + key, b"1", nx=True, px=int(ttl_seconds * 1000)))
        except Exception as e:  # connection errors etc.
            raise NonceStoreError(str(e)) from e
```

## Not suitable

- **In-process memory** with more than one process (`InMemoryNonceStore` is for tests and single-process tools).
- **Cloudflare Workers KV**, or any eventually consistent cache. A replay can land before the first write propagates.
- **Per-region stores** for a multi-region origin, unless agents are pinned to one region.

## Sizing

With the default `max_age` of 300 s, the store holds about `signed requests per second × 305` live keys. At 1,000 signed requests per second that is about 305,000 keys. In Redis, at roughly 150 bytes per key including overhead, that comes to about 45 MB. Lowering `max_age` shrinks the store proportionally.

## When the store is down

The verifier raises `NonceStoreError` inside the store and applies `Policy.fail_closed_methods`. Unsafe methods become `invalid`; safe methods verify with `replay_protected=False`. Alert on this; it should be rare.
