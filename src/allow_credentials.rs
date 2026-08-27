//! Configuration for the `Access-Control-Allow-Credentials` response header.

use std::sync::Arc;

use http::{
    header::{self, HeaderName, HeaderValue},
    request::Parts as RequestParts,
};

use crate::headers::ALLOW_CREDENTIALS_TRUE;

/// Configuration for the `Access-Control-Allow-Credentials` header.
#[derive(Clone, Default)]
#[must_use]
pub struct AllowCredentials(AllowCredentialsInner);

impl AllowCredentials {
    /// Allows credentials for every cross-origin request.
    pub fn yes() -> Self {
        Self(AllowCredentialsInner::Yes)
    }

    /// Allows credentials per request, based on a synchronous predicate. The predicate
    /// receives the request's `Origin` header (if any) and the request
    /// [`Parts`](http::request::Parts).
    pub fn predicate<F>(f: F) -> Self
    where
        F: Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static,
    {
        Self(AllowCredentialsInner::Predicate(Arc::new(f)))
    }

    /// Returns `true` if credentials are unconditionally allowed. Used to enforce the Fetch
    /// spec's incompatibility with wildcard origin / method / header / expose-headers values
    /// at configuration time.
    pub(crate) fn is_true(&self) -> bool {
        matches!(&self.0, AllowCredentialsInner::Yes)
    }

    /// Returns the header pair to set, or `None` if credentials are not allowed for this
    /// request. When the `Origin` header is absent (no CORS request), credentials are never
    /// emitted.
    pub(crate) fn to_header(
        &self,
        origin: Option<&HeaderValue>,
        parts: &RequestParts,
    ) -> Option<(HeaderName, HeaderValue)> {
        let allow_creds = match &self.0 {
            AllowCredentialsInner::Yes => true,
            AllowCredentialsInner::No => false,
            AllowCredentialsInner::Predicate(f) => origin.is_some() && f(origin?, parts),
        };
        allow_creds.then_some((
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            ALLOW_CREDENTIALS_TRUE,
        ))
    }
}

impl std::fmt::Debug for AllowCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            AllowCredentialsInner::Yes => f.debug_tuple("Yes").finish(),
            AllowCredentialsInner::No => f.debug_tuple("No").finish(),
            AllowCredentialsInner::Predicate(_) => f.debug_tuple("Predicate").finish(),
        }
    }
}

impl From<bool> for AllowCredentials {
    fn from(v: bool) -> Self {
        if v {
            Self::yes()
        } else {
            Self(AllowCredentialsInner::No)
        }
    }
}

#[derive(Clone, Default)]
enum AllowCredentialsInner {
    Yes,
    #[default]
    No,
    #[allow(clippy::type_complexity)]
    Predicate(Arc<dyn for<'a> Fn(&'a HeaderValue, &'a RequestParts) -> bool + Send + Sync>),
}
