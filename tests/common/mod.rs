//! Test helpers shared across the integration tests. Not built as its own test binary -- each
//! integration test file does `mod common;` to pull this in.

#![allow(dead_code)]

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::{Empty, Full};
use hyper::body::Body;
use hyper::service::Service;

/// An inner service used by the tests. Counts how many times it was actually invoked and
/// replies with a recognisable body, so each test can assert whether the request reached the
/// inner service at all -- asserting on the response body alone is not sufficient, because a
/// middleware may start the inner call and then discard its response.
#[derive(Clone, Debug)]
pub struct EchoService {
    pub response_body: Bytes,
    calls: Arc<AtomicUsize>,
}

impl EchoService {
    pub fn ok() -> Self {
        Self {
            response_body: Bytes::from_static(b"ok"),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Number of times `Service::call` has been invoked on this service (or any clone of it).
    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Service<Request<Empty<Bytes>>> for EchoService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, _req: Request<Empty<Bytes>>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(Response::new(Full::new(self.response_body.clone()))))
    }
}

/// Returns the `Access-Control-*` headers from a response as a `Vec<(name, value)>` for easy
/// assertion.
pub fn ac_headers<B>(resp: &Response<B>) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .filter(|(n, _)| n.as_str().starts_with("access-control-"))
        .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect()
}

/// Returns all `Vary` header values concatenated with `, ` (if present).
pub fn vary<B>(resp: &Response<B>) -> Option<String> {
    let values: Vec<_> = resp
        .headers()
        .get_all("vary")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// Convenience: build a GET request with an optional Origin header.
pub fn get(origin: Option<&str>) -> Request<Empty<Bytes>> {
    let mut b = Request::builder().method(Method::GET).uri("/");
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    b.body(Empty::new()).unwrap()
}

/// Convenience: build a CORS preflight OPTIONS request.
pub fn preflight(
    origin: &str,
    method: &str,
    request_headers: Option<&str>,
) -> Request<Empty<Bytes>> {
    let mut b = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header("origin", origin)
        .header("access-control-request-method", method);
    if let Some(h) = request_headers {
        b = b.header("access-control-request-headers", h);
    }
    b.body(Empty::new()).unwrap()
}

/// Asserts that the response body collects to a given string.
pub async fn body_to_string<B>(body: B) -> String
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    use http_body_util::BodyExt;
    let collected = body.collect().await.expect("body collect");
    String::from_utf8_lossy(&collected.to_bytes()).into_owned()
}
