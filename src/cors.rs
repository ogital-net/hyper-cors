//! The [`Cors`] middleware.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use http::{header, request::Parts, HeaderMap, HeaderValue, Method, Request, Response};
use hyper::body::Body;
use hyper::service::Service;
use pin_project_lite::pin_project;

use crate::{allow_origin::AllowOriginFuture, config::CorsBuilder, header_buf::HeaderBuf};

/// CORS middleware.
///
/// Construct via [`builder`].
#[derive(Debug, Clone)]
#[must_use]
pub struct Cors<S> {
    inner: S,
    // `Arc`, not `Box`: cloning the middleware is a common pattern (every accepted
    // connection in a hyper-util server clone()s the service, see `examples/server.rs`),
    // and the configuration is read-only through `&Cors`. `Arc::clone` is a single atomic
    // increment; cloning `CorsBuilder` directly would also bump the refcount on every
    // `HeaderValue`/`HeaderName` it holds. The wrapper also keeps `Cors<S>` small for
    // callers that wrap it in an enum variant.
    config: Arc<CorsBuilder>,
}

impl<S> Cors<S> {
    /// Returns a reference to the inner service.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Returns the configured builder.
    pub fn config(&self) -> &CorsBuilder {
        &self.config
    }

    pub(crate) fn from_parts(inner: S, config: CorsBuilder) -> Self {
        Self {
            inner,
            config: Arc::new(config),
        }
    }
}

/// Returns a new [`CorsBuilder`] with default settings.
pub fn builder() -> CorsBuilder {
    CorsBuilder::new()
}

impl<S, ReqB, ResB> Service<Request<ReqB>> for Cors<S>
where
    S: Service<Request<ReqB>, Response = Response<ResB>> + Clone,
    ResB: Body<Data = Bytes> + Default + Send + 'static,
{
    type Response = Response<ResB>;
    type Error = S::Error;
    type Future = CorsFuture<S, ReqB, S::Future, ResB>;

    fn call(&self, req: Request<ReqB>) -> Self::Future {
        let (parts, body) = req.into_parts();
        let origin = parts.headers.get(&header::ORIGIN).cloned();
        let is_preflight = is_preflight_request(&parts);
        let is_websocket_upgrade = is_websocket_upgrade_request(&parts);

        let allow_origin_future = self.config.allow_origin.to_future(origin.as_ref(), &parts);
        let has_origin = allow_origin_future.has_origin();

        // `Vary` applies to every CORS-shaped response regardless of origin match, so caches
        // don't conflate responses for different origins.
        let mut common_headers = HeaderBuf::default();
        common_headers.push_opt(self.config.vary.to_header());

        let lazy_factory = LazyHeaders {
            allow_credentials: self.config.allow_credentials.clone(),
            allow_methods: self.config.allow_methods.clone(),
            allow_headers: self.config.allow_headers.clone(),
            expose_headers: self.config.expose_headers.clone(),
            max_age: self.config.max_age.clone(),
        };

        if is_preflight && !self.config.deliver_preflight {
            CorsFuture::Preflight {
                allow_origin_future,
                headers: common_headers,
                lazy: lazy_factory,
                parts,
                has_origin,
                origin,
                deliver_non_allowed_origin: self.config.deliver_non_allowed_origin,
                rejection_status: self.config.rejection_status,
                _body: std::marker::PhantomData,
            }
        } else {
            // The inner service is not invoked here. Calling it before the origin decision
            // is known would defeat `deliver_non_allowed_origin(false)`: a rejected origin
            // would still run the handler. We hold the service and unconsumed request and
            // dispatch from `poll` once the verdict is in. For synchronous origin variants
            // this costs nothing; only the async-predicate path gives up overlap with the
            // inner call.
            CorsFuture::Forward {
                allow_origin_future,
                allow_origin_complete: false,
                service: Some(self.inner.clone()),
                body: Some(body),
                inner: None,
                headers: common_headers,
                lazy: Some(lazy_factory),
                parts: Some(parts),
                is_preflight,
                has_origin,
                origin,
                deliver_non_allowed_origin: self.config.deliver_non_allowed_origin,
                rejection_status: self.config.rejection_status,
                reject_websocket_upgrade: is_websocket_upgrade
                    && !self.config.deliver_non_allowed_origin_websocket_upgrade,
                _body: std::marker::PhantomData,
            }
        }
    }
}

/// CORS configuration knobs whose headers depend on the `allow_origin` decision.
#[derive(Clone)]
struct LazyHeaders {
    allow_credentials: crate::AllowCredentials,
    allow_methods: crate::AllowMethods,
    allow_headers: crate::AllowHeaders,
    expose_headers: crate::ExposeHeaders,
    max_age: crate::MaxAge,
}

impl LazyHeaders {
    /// Appends the CORS headers appropriate for an allowed-origin request into `out`.
    fn compute_into(
        &self,
        out: &mut HeaderBuf,
        parts: &Parts,
        origin: Option<&HeaderValue>,
        is_preflight: bool,
    ) {
        out.push_opt(self.allow_credentials.to_header(origin, parts));
        if is_preflight {
            out.push_opt(self.allow_methods.to_header(parts));
            out.push_opt(self.allow_headers.to_header(parts));
            out.push_opt(self.max_age.to_header(origin, parts));
        } else {
            out.push_opt(self.expose_headers.to_header(parts));
        }
    }
}

pin_project! {
    /// Future returned by [`Cors::call`].
    #[project = CorsFutureProj]
    pub enum CorsFuture<S, ReqB, F, B> {
        Forward {
            #[pin]
            allow_origin_future: AllowOriginFuture,
            allow_origin_complete: bool,
            service: Option<S>,
            // Body is held apart from `parts` so `parts` can be borrowed for header
            // computation and then recombined via `Request::from_parts` without cloning
            // the request head.
            body: Option<ReqB>,
            #[pin]
            inner: Option<F>,
            headers: HeaderBuf,
            lazy: Option<LazyHeaders>,
            parts: Option<Parts>,
            is_preflight: bool,
            has_origin: bool,
            origin: Option<HeaderValue>,
            deliver_non_allowed_origin: bool,
            rejection_status: http::StatusCode,
            reject_websocket_upgrade: bool,
            _body: std::marker::PhantomData<fn() -> B>,
        },
        Preflight {
            #[pin]
            allow_origin_future: AllowOriginFuture,
            headers: HeaderBuf,
            lazy: LazyHeaders,
            parts: Parts,
            has_origin: bool,
            origin: Option<HeaderValue>,
            deliver_non_allowed_origin: bool,
            rejection_status: http::StatusCode,
            _body: std::marker::PhantomData<fn() -> B>,
        },
    }
}

impl<S, ReqB, F, B, E> Future for CorsFuture<S, ReqB, F, B>
where
    S: Service<Request<ReqB>, Response = Response<B>, Future = F>,
    F: Future<Output = Result<Response<B>, E>>,
    B: Body<Data = Bytes> + Default + Send + 'static,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CorsFutureProj::Forward {
                allow_origin_future,
                allow_origin_complete,
                service,
                body,
                mut inner,
                headers,
                lazy,
                parts,
                is_preflight,
                has_origin,
                origin,
                deliver_non_allowed_origin,
                rejection_status,
                reject_websocket_upgrade,
                _body: _,
            } => {
                if !*allow_origin_complete {
                    let origin_allowed = match ready!(allow_origin_future.poll(cx)) {
                        Some((name, value)) => {
                            headers.push((name, value));
                            true
                        }
                        None => false,
                    };
                    *allow_origin_complete = true;

                    // Reject when the request has an `Origin` and either
                    // `deliver_non_allowed_origin` is off, or this is a WebSocket upgrade and
                    // WebSocket upgrades are not exempted. The WebSocket case applies even
                    // when ordinary requests are being delivered, because browsers don't
                    // enforce CORS on WebSocket handshakes.
                    if !origin_allowed
                        && *has_origin
                        && (!*deliver_non_allowed_origin || *reject_websocket_upgrade)
                    {
                        // Drop the pending request and service handle: no application code
                        // runs for a disallowed origin.
                        service.take();
                        body.take();
                        parts.take();
                        let mut response = Response::new(B::default());
                        *response.status_mut() = *rejection_status;
                        // Only `Vary` (already in `headers`) survives.
                        merge_headers(response.headers_mut(), headers);
                        return Poll::Ready(Ok(response));
                    }

                    // Allowed origin (or non-CORS request). Compute the lazy CORS headers.
                    if origin_allowed {
                        if let (Some(lazy), Some(parts)) = (lazy.take(), parts.as_ref()) {
                            lazy.compute_into(headers, parts, origin.as_ref(), *is_preflight);
                        }
                    }

                    if let (Some(svc), Some(parts), Some(body)) =
                        (service.take(), parts.take(), body.take())
                    {
                        inner.set(Some(svc.call(Request::from_parts(parts, body))));
                    }
                }
                let inner_pinned = inner
                    .as_mut()
                    .as_pin_mut()
                    .expect("polled after completion");
                let mut response = ready!(inner_pinned.poll(cx))?;
                merge_headers(response.headers_mut(), headers);
                Poll::Ready(Ok(response))
            }
            CorsFutureProj::Preflight {
                allow_origin_future,
                headers,
                lazy,
                parts,
                has_origin,
                origin,
                deliver_non_allowed_origin,
                rejection_status,
                _body: _,
            } => {
                let origin_allowed = match ready!(allow_origin_future.poll(cx)) {
                    Some((name, value)) => {
                        headers.push((name, value));
                        true
                    }
                    None => false,
                };
                if !origin_allowed && *has_origin {
                    let mut response = Response::new(B::default());
                    if !*deliver_non_allowed_origin {
                        *response.status_mut() = *rejection_status;
                    }
                    merge_headers(response.headers_mut(), headers);
                    return Poll::Ready(Ok(response));
                }
                lazy.compute_into(headers, parts, origin.as_ref(), true);
                let mut response = Response::new(B::default());
                merge_headers(response.headers_mut(), headers);
                Poll::Ready(Ok(response))
            }
        }
    }
}

/// Returns `true` if `parts` is a CORS preflight request (`OPTIONS` carrying
/// `Access-Control-Request-Method`), per [Fetch Sec. 3.1.3][fetch].
///
/// [fetch]: https://fetch.spec.whatwg.org/#cors-preflight-request
fn is_preflight_request(parts: &Parts) -> bool {
    parts.method == Method::OPTIONS
        && parts
            .headers
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

/// Returns `true` if `parts` is a WebSocket handshake request (carries
/// `Sec-WebSocket-Version`).
///
/// Browsers do not apply CORS to WebSocket handshakes, so these are handled separately; see
/// [`CorsBuilder::deliver_non_allowed_origin_websocket_upgrade`].
///
/// [`CorsBuilder::deliver_non_allowed_origin_websocket_upgrade`]: crate::CorsBuilder::deliver_non_allowed_origin_websocket_upgrade
fn is_websocket_upgrade_request(parts: &Parts) -> bool {
    parts.headers.contains_key("sec-websocket-version")
}

/// Merge `(name, value)` pairs into `target`, *appending* any `Vary` value (so an inner
/// service's `Vary` is not clobbered) and overwriting the rest.
///
/// `Vary` tokens already present on the response are skipped so an inner service that itself
/// emits e.g. `Vary: Origin` does not end up with a redundant duplicate.
fn merge_headers(target: &mut HeaderMap, headers: &HeaderBuf) {
    for (name, value) in headers.iter() {
        if name == header::VARY {
            if let Some(value) = dedup_vary(target, value) {
                target.append(name.clone(), value);
            }
        } else {
            target.insert(name.clone(), value.clone());
        }
    }
}

/// Inline capacity for [`dedup_vary`]'s output buffer. Sized to comfortably hold the default
/// CORS `Vary` (~62 bytes) plus one or two inner-service tokens.
const DEDUP_VARY_STACK: usize = 128;

/// Returns `value` with tokens already present in `target`'s `Vary` removed, or `None` when
/// every token is already covered.
fn dedup_vary(target: &HeaderMap, value: &HeaderValue) -> Option<HeaderValue> {
    fn already_listed(target: &HeaderMap, tok: &[u8]) -> bool {
        target
            .get_all(header::VARY)
            .iter()
            .flat_map(|v| v.as_bytes().split(|&b| b == b','))
            .any(|e| e.trim_ascii().eq_ignore_ascii_case(tok))
    }

    // Fast path: nothing to deduplicate against.
    if target.get(header::VARY).is_none() {
        return Some(value.clone());
    }

    let mut stack = [0u8; DEDUP_VARY_STACK];
    let mut len = 0usize;
    // Set when the output outgrows the stack buffer; subsequent writes go to `heap` instead.
    let mut heap: Option<Vec<u8>> = None;

    for tok in value.as_bytes().split(|&b| b == b',') {
        let tok = tok.trim_ascii();
        if tok.is_empty() || already_listed(target, tok) {
            continue;
        }
        let needs_sep = match &heap {
            Some(v) => !v.is_empty(),
            None => len > 0,
        };
        let sep_len = if needs_sep { 2 } else { 0 };
        let total = sep_len + tok.len();

        if heap.is_none() {
            // Fast path: still in stack buffer.
            if len + total <= DEDUP_VARY_STACK {
                if needs_sep {
                    stack[len..len + 2].copy_from_slice(b", ");
                }
                stack[len + sep_len..len + total].copy_from_slice(tok);
                len += total;
                continue;
            }
            // Spill to heap, copying what we already have.
            let mut v = Vec::with_capacity(len + total);
            v.extend_from_slice(&stack[..len]);
            heap = Some(v);
        }

        let v = heap.as_mut().expect("set on spill");
        if needs_sep {
            v.extend_from_slice(b", ");
        }
        v.extend_from_slice(tok);
    }

    let bytes: &[u8] = match &heap {
        Some(v) => v.as_slice(),
        None => &stack[..len],
    };
    if bytes.is_empty() {
        return None;
    }
    HeaderValue::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::Request;
    use http_body_util::{Empty, Full};
    use hyper::service::Service;
    use std::future::{ready, Ready};

    #[derive(Clone)]
    struct Marker;
    impl Service<Request<Empty<Bytes>>> for Marker {
        type Response = Response<Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;
        fn call(&self, _req: Request<Empty<Bytes>>) -> Self::Future {
            ready(Ok(Response::new(Full::new(Bytes::new()))))
        }
    }

    #[test]
    fn inner_accessor_returns_shared_reference() {
        let svc: Cors<Marker> = crate::builder().allow_origin(crate::Any).build(Marker);
        // `inner` returns a shared reference; calling it must not consume the middleware.
        let _r: &Marker = svc.inner();
    }

    #[test]
    fn config_accessor_returns_builder_reference() {
        let svc: Cors<Marker> = crate::builder().allow_origin(crate::Any).build(Marker);
        // `config` exposes the builder for inspection. The fields are `pub(crate)`, so
        // we just confirm we get a valid reference back.
        let _cfg: &CorsBuilder = svc.config();
    }

    #[test]
    fn inner_mut_returns_exclusive_mutable_reference() {
        let mut svc: Cors<Marker> = crate::builder().allow_origin(crate::Any).build(Marker);
        // The returned reference is exclusive (`&mut`); `mem::replace` proves it.
        let r: &mut Marker = svc.inner_mut();
        let prev = std::mem::replace(r, Marker);
        // Avoid an unused-variable lint while confirming the swap happened.
        let _ = prev;
    }

    #[test]
    fn cors_layout_is_arc_backed() {
        // The config field is an `Arc<CorsBuilder>`. This pins the shape so a future
        // refactor that re-inlines the config (and silently brings back the 272-byte
        // per-`Cors::clone` cost) gets caught at test time. Concretely: with `Arc`,
        // `Cors<()>` is 8 bytes (one pointer) plus the unit struct. Without `Arc` it
        // would be `size_of::<CorsBuilder>()` (272 on this target as of writing).
        let size = std::mem::size_of::<Cors<()>>();
        assert_eq!(
            size,
            std::mem::size_of::<usize>(),
            "Cors<()> should be one pointer (Arc-backed config); got {size} bytes. \
             Did someone inline CorsBuilder back into Cors?"
        );
    }

    #[test]
    fn clone_shares_the_config_arc() {
        // Two `Cors::clone` calls must point at the same `Arc` allocation; if they
        // don't, the `Arc` indirection was bypassed (e.g. someone added `Box<CorsBuilder>`
        // by accident).
        let svc: Cors<Marker> = crate::builder().allow_origin(crate::Any).build(Marker);
        let clone = svc.clone();
        let p1: *const CorsBuilder = Arc::as_ptr(&svc.config);
        let p2: *const CorsBuilder = Arc::as_ptr(&clone.config);
        assert_eq!(
            p1, p2,
            "Cors::clone must share the underlying Arc<CorsBuilder>; got distinct allocations"
        );
    }
}
