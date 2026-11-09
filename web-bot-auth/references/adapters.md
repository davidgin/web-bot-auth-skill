# Building `Request` correctly

The verifier rebuilds exactly the bytes the agent signed. If the adapter changes anything — a lowercased method, a normalized path, a decoded body, the internal hostname instead of the public one — valid signatures fail. In the worst case, a spoofed value gets trusted.

## What each field must be

| Field | Must be | Common mistake |
| --- | --- | --- |
| `method` | As sent, e.g. `POST` | Framework-normalized or overridden by `X-HTTP-Method-Override` |
| `url` | Absolute URL as the client requested it: public scheme, public host[:port], raw path, raw query | Internal host or port behind a proxy; percent-decoded path; reordered query |
| `headers` | Every occurrence of every field, in order | A dict that keeps only the last occurrence |
| `body` | Raw bytes as received | Parsed JSON re-serialized; body already consumed by the framework; decompressed bytes when the agent digested the compressed ones |

## Behind a proxy or CDN

The client signed the public authority (e.g. `shop.example`), but your app may see `app:8080`. Rebuild the URL from `X-Forwarded-Proto` / `X-Forwarded-Host` (or `Forwarded`) **only when the request came from a proxy you trust**, which is usually checked by the peer IP. Otherwise an attacker sets those headers. If the deployment has a fixed public origin, hardcoding it is simpler and safer.

If a CDN in front of you already verifies Web Bot Auth, decide with the user whether to verify again at the origin or trust the CDN's result header. Trusting the header is only safe if the origin accepts traffic from the CDN alone.

## Framework notes

**FastAPI / Starlette:** in middleware, `await request.body()` caches the body, so downstream handlers can still read it. Use `request.method` and `request.headers.raw` (a list of byte pairs, decoded as latin-1). Build the URL from `request.url.path` plus `request.scope["query_string"]` to keep the raw query, and take the scheme and host from your trusted-proxy logic.

**Flask:** `request.get_data(cache=True)` for the body; `request.headers` iterates every pair. For the raw path and query, use `request.environ["RAW_URI"]` (gunicorn) or `REQUEST_URI` when present, else `request.full_path`, which may normalize. Use werkzeug's `ProxyFix` only with the correct trusted hop count.

**Django:** `request.body` gives raw bytes, but read it before anything touches `request.POST`. `request.get_full_path_info()` returns the path and query; `request.META` holds headers as `HTTP_*`, so convert them back. Set `USE_X_FORWARDED_HOST` only behind a trusted proxy.

**Express / Node:** this is a port, so run it against `assets/test-vectors.json`. Capture the raw body with `express.raw()` or the `verify` callback of `express.json()`. `req.rawHeaders` keeps every occurrence. `req.originalUrl` holds the raw path and query. Set `trust proxy` correctly before using `req.protocol` and `req.hostname`.

**Cloudflare Workers / edge runtimes:** this is a port. `request.url` is already the public absolute URL. Read the body with `await request.clone().arrayBuffer()` so it can still be forwarded. For the nonce store, see `nonce-stores.md`; Workers KV is not suitable.

**nginx / OpenResty / Envoy:** verify in a small sidecar or auth subrequest service written with this code. Pass the original method, `$scheme://$host$request_uri` and the body. Make sure the proxy forwards the body to the auth service for methods that have one.

## Testing the adapter

Through the framework's own test client, send:

1. a request produced by `sign_request`, which must give `verified`;
2. the same request again, which must give `replay`;
3. a signed POST with one body byte changed, which must give `invalid`;
4. a valid request with a query string, which must still give `verified` (this catches query normalization bugs);
5. when behind a proxy, a request with a forged `X-Forwarded-Host` from an untrusted peer, which must not verify.
