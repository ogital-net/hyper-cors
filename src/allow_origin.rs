//! Configuration for the `Access-Control-Allow-Origin` response header.

use std::{future::Future, pin::Pin, sync::Arc};

use http::{
    header::{self, HeaderName, HeaderValue},
    request::Parts as RequestParts,
};
use pin_project_lite::pin_project;

use crate::headers::WILDCARD;

/// Sentinel for the wildcard `*` origin.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Any;

/// Configuration for the `Access-Control-Allow-Origin` header.
#[derive(Clone, Default)]
#[must_use]
pub struct AllowOrigin(OriginInner);

impl AllowOrigin {
    /// Allows any origin by responding with `*`.
    pub fn any() -> Self {
        Self(OriginInner::Const(WILDCARD))
    }

    /// Allows a single, fixed origin.
    ///
    /// # Panics
    ///
    /// Panics if `origin` is the wildcard (`*`); use [`AllowOrigin::any`] for that.
    pub fn exact(origin: HeaderValue) -> Self {
        assert_ne!(
            origin, WILDCARD,
            "wildcard origin must be configured via AllowOrigin::any(), not AllowOrigin::exact()"
        );
        Self(OriginInner::Const(origin))
    }

    /// Allows origins from a list. The response carries the request's `Origin` verbatim if
    /// (and only if) it appears in the list.
    ///
    /// # Panics
    ///
    /// Panics if `origins` contains the wildcard (`*`); use [`AllowOrigin::any`] for that.
    pub fn list<I>(origins: I) -> Self
    where
        I: IntoIterator<Item = HeaderValue>,
    {
        let origins: Vec<HeaderValue> = origins.into_iter().collect();
        assert!(
            !origins.contains(&WILDCARD),
            "wildcard origin must be configured via AllowOrigin::any(), not AllowOrigin::list()"
        );
        Self(OriginInner::List(origins))
    }

    /// Allows origins decided by a synchronous predicate. The predicate receives the
    /// request's `Origin` header (if any) and the request [`Parts`](http::request::Parts),
    /// and returns `true` to allow.
    pub fn predicate<F>(f: F) -> Self
    where
        F: Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static,
    {
        Self(OriginInner::Predicate(Arc::new(f)))
    }

    /// Allows origins decided by an async predicate.
    ///
    /// Use this when the origin decision depends on data that is not already cached in
    /// memory (for example, a database lookup per tenant). Choosing the sync
    /// [`AllowOrigin::predicate`] path instead carries no cost.
    pub fn async_predicate<F, Fut>(f: F) -> Self
    where
        F: Fn(HeaderValue, RequestParts) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        Self(OriginInner::AsyncPredicate(Arc::new(move |v, p| {
            Box::pin(f(v, p))
        })))
    }

    /// Always echoes the request's `Origin` header. Equivalent to
    /// [`AllowOrigin::predicate`] returning `true` for every input.
    pub fn mirror_request() -> Self {
        Self::predicate(|_, _| true)
    }

    /// Returns `true` when this policy responds with the literal `*` (incompatible with
    /// credentials).
    pub(crate) fn is_wildcard(&self) -> bool {
        matches!(&self.0, OriginInner::Const(v) if *v == WILDCARD)
    }

    /// Returns a future yielding the `(header::ACCESS_CONTROL_ALLOW_ORIGIN, value)` pair, or
    /// `None` if the origin is not allowed.
    ///
    /// The future is `Ready` for the sync variants and only allocates a boxed future for the
    /// async variant.
    ///
    /// The future additionally carries a `has_origin` flag distinguishing a same-origin or
    /// non-CORS request from a cross-origin request with a disallowed origin; see
    /// [`CorsBuilder::deliver_non_allowed_origin`].
    ///
    /// [`CorsBuilder::deliver_non_allowed_origin`]: crate::CorsBuilder::deliver_non_allowed_origin
    pub(crate) fn to_future(
        &self,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) -> AllowOriginFuture {
        let name = header::ACCESS_CONTROL_ALLOW_ORIGIN;
        let has_origin = origin.is_some();
        match &self.0 {
            OriginInner::Const(v) => AllowOriginFuture::ready(has_origin, Some((name, v.clone()))),
            OriginInner::List(l) => AllowOriginFuture::ready(
                has_origin,
                origin
                    .filter(|o| origin_list_matches(l, o))
                    .map(|o| (name, o.clone())),
            ),
            OriginInner::Predicate(f) => AllowOriginFuture::ready(
                has_origin,
                origin.filter(|o| f(o, parts)).map(|o| (name, o.clone())),
            ),
            OriginInner::AsyncPredicate(f) => origin.cloned().map_or_else(
                || AllowOriginFuture::ready(has_origin, None),
                |origin| {
                    let parts = parts.clone();
                    let fut = f(origin.clone(), parts);
                    AllowOriginFuture::pending(
                        has_origin,
                        Box::pin(async move { fut.await.then_some((name, origin)) }),
                    )
                },
            ),
        }
    }
}

/// Matches a request `Origin` header against an allow-list.
///
/// `Origin` is usually a single serialized origin but may be a space-separated list. Every
/// non-empty token must appear in `allowed`: accepting a list because one of its entries is
/// allowed would let an attacker smuggle a disallowed origin alongside an allowed one.
fn origin_list_matches(allowed: &[HeaderValue], origin: &HeaderValue) -> bool {
    let mut saw_token = false;
    for token in origin.as_bytes().split(|&b| b == b' ') {
        let token = token.trim_ascii();
        if token.is_empty() {
            continue;
        }
        saw_token = true;
        if !allowed.iter().any(|a| a.as_bytes() == token) {
            return false;
        }
    }
    saw_token
}

impl std::fmt::Debug for AllowOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            OriginInner::Const(inner) => f.debug_tuple("Const").field(inner).finish(),
            OriginInner::List(inner) => f.debug_tuple("List").field(inner).finish(),
            OriginInner::Predicate(_) => f.debug_tuple("Predicate").finish(),
            OriginInner::AsyncPredicate(_) => f.debug_tuple("AsyncPredicate").finish(),
        }
    }
}

impl From<Any> for AllowOrigin {
    fn from(_: Any) -> Self {
        Self::any()
    }
}

impl From<HeaderValue> for AllowOrigin {
    fn from(v: HeaderValue) -> Self {
        Self::exact(v)
    }
}

impl<const N: usize> From<[HeaderValue; N]> for AllowOrigin {
    fn from(arr: [HeaderValue; N]) -> Self {
        Self::list(arr)
    }
}

impl From<Vec<HeaderValue>> for AllowOrigin {
    fn from(vec: Vec<HeaderValue>) -> Self {
        Self::list(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn single_origin_matches() {
        let allowed = [hv("https://a.example")];
        assert!(origin_list_matches(&allowed, &hv("https://a.example")));
        assert!(!origin_list_matches(&allowed, &hv("https://b.example")));
    }

    #[test]
    fn space_separated_all_allowed_matches() {
        let allowed = [hv("https://a.example"), hv("https://b.example")];
        assert!(origin_list_matches(
            &allowed,
            &hv("https://a.example https://b.example")
        ));
    }

    #[test]
    fn space_separated_partially_allowed_is_rejected() {
        let allowed = [hv("https://a.example")];
        assert!(!origin_list_matches(
            &allowed,
            &hv("https://a.example https://evil.example")
        ));
    }

    #[test]
    fn empty_or_whitespace_origin_does_not_match() {
        let allowed = [hv("https://a.example")];
        assert!(!origin_list_matches(&allowed, &hv("")));
        assert!(!origin_list_matches(&allowed, &hv("   ")));
    }

    #[test]
    fn empty_allow_list_matches_nothing() {
        assert!(!origin_list_matches(&[], &hv("https://a.example")));
    }
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
enum OriginInner {
    Const(HeaderValue),
    List(Vec<HeaderValue>),
    Predicate(Arc<dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> bool + Send + Sync>),
    AsyncPredicate(
        Arc<
            dyn Fn(HeaderValue, RequestParts) -> Pin<Box<dyn Future<Output = bool> + Send>>
                + Send
                + Sync,
        >,
    ),
}

impl Default for OriginInner {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

pin_project! {
    /// Future returned by [`AllowOrigin::to_future`].
    ///
    /// `Ready` for all sync variants; holds a boxed future only for the async variant. The
    /// `has_origin` flag records whether the request had an `Origin` header at all.
    #[project = AllowOriginFutureProj]
    #[allow(clippy::type_complexity)]
    pub(crate) struct AllowOriginFuture {
        has_origin: bool,
        #[pin]
        state: AllowOriginFutureState,
    }
}

pin_project! {
    #[project = AllowOriginFutureStateProj]
    enum AllowOriginFutureState {
        Ready { res: Option<(HeaderName, HeaderValue)> },
        Pending { #[pin] fut: Pin<Box<dyn Future<Output = Option<(HeaderName, HeaderValue)>> + Send>> },
    }
}

impl AllowOriginFuture {
    fn ready(has_origin: bool, res: Option<(HeaderName, HeaderValue)>) -> Self {
        Self {
            has_origin,
            state: AllowOriginFutureState::Ready { res },
        }
    }

    #[allow(clippy::type_complexity)]
    fn pending(
        has_origin: bool,
        fut: Pin<Box<dyn Future<Output = Option<(HeaderName, HeaderValue)>> + Send>>,
    ) -> Self {
        Self {
            has_origin,
            state: AllowOriginFutureState::Pending { fut },
        }
    }

    /// Returns `true` if the request carried an `Origin` header (i.e. it was a CORS request).
    pub(crate) fn has_origin(&self) -> bool {
        self.has_origin
    }
}

impl Future for AllowOriginFuture {
    type Output = Option<(HeaderName, HeaderValue)>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project().state.project() {
            AllowOriginFutureStateProj::Ready { res } => std::task::Poll::Ready(res.take()),
            AllowOriginFutureStateProj::Pending { fut } => fut.poll(cx),
        }
    }
}
