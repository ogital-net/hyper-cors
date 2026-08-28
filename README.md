# hyper-cors

CORS middleware for [hyper 1.x](https://docs.rs/hyper/1).

`Cors` is a [`hyper::service::Service`](https://docs.rs/hyper/1/hyper/service/trait.Service.html)
that wraps an inner service and applies the Fetch
[Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
protocol to every request. Preflight requests (`OPTIONS` with
`Access-Control-Request-Method`) are short-circuited by default, so the inner service never
sees them.

## Example

```rust
use std::{convert::Infallible, time::Duration};
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::Full;
use hyper::service::Service;
use hyper_cors::{builder, Any};

async fn handle(_req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("ok"))))
}

let svc = builder()
    .allow_origin(Any)
    .allow_methods([Method::GET, Method::POST])
    .max_age(Duration::from_secs(600))
    .build(handle);
```

## Configuration

All knobs are chainable on [`CorsBuilder`]. Defaults:

| Knob | Default |
|---|---|
| `allow_origin` | empty list (non-CORS requests still pass through) |
| `allow_credentials` | `false` |
| `allow_methods` | mirror request (`Access-Control-Request-Method`) |
| `allow_headers` | mirror request (`Access-Control-Request-Headers`) |
| `expose_headers` | empty |
| `max_age` | not emitted |
| `vary` | `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers` |
| `deliver_preflight` | `false` (preflight is short-circuited) |
| `deliver_non_allowed_origin` | `true` |
| `deliver_non_allowed_origin_websocket_upgrade` | `false` |
| `rejection_status` | `400 Bad Request` |

Per-tenant origins can be served from a cached sync predicate
([`AllowOrigin::predicate`]) or, when the lookup is not in memory, an async predicate
([`AllowOrigin::async_predicate`]).

`CorsBuilder::build` panics on Fetch-mandated incompatibilities: `allow_credentials: true`
combined with `*` in `allow_origin`, `allow_methods`, `allow_headers`, or `expose_headers`.
Use [`CorsBuilder::try_build`] to receive the same diagnostics as a `Result` and surface
them as a startup error instead.

## Examples

Runnable examples live in the `examples/` directory:

- [`server.rs`](examples/server.rs) &mdash; minimal hyper server bound to `127.0.0.1:3000`,
  exercising both simple and preflight requests with `curl`.
- [`multitenant.rs`](examples/multitenant.rs) &mdash; per-tenant origin allow-list backed
  by an `Arc<RwLock<HashSet<_>>>` and resolved via `AllowOrigin::async_predicate`.

Run with `cargo run --example <name>`.

## License

BSD 2-Clause

[`AllowOrigin::predicate`]: https://docs.rs/hyper-cors/latest/hyper_cors/struct.AllowOrigin.html#method.predicate
[`AllowOrigin::async_predicate`]: https://docs.rs/hyper-cors/latest/hyper_cors/struct.AllowOrigin.html#method.async_predicate
[`CorsBuilder`]: https://docs.rs/hyper-cors/latest/hyper_cors/struct.CorsBuilder.html
[`CorsBuilder::try_build`]: https://docs.rs/hyper-cors/latest/hyper_cors/struct.CorsBuilder.html#method.try_build
