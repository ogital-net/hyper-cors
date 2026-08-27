//! Configuration for the `Access-Control-Expose-Headers` response header.

use http::{
    header::{self, HeaderName, HeaderValue},
    request::Parts as RequestParts,
};

use crate::{headers::WILDCARD, util::separated_by_commas};

/// Configuration for the `Access-Control-Expose-Headers` header.
#[derive(Clone, Default)]
#[must_use]
pub struct ExposeHeaders(ExposeHeadersInner);

impl ExposeHeaders {
    /// Responds with `*`. Incompatible with credentials; see [`CorsBuilder::build`].
    ///
    /// [`CorsBuilder::build`]: crate::CorsBuilder::build
    pub fn any() -> Self {
        Self(ExposeHeadersInner::Const(Some(WILDCARD)))
    }

    /// Responds with the given set of response header names.
    pub fn list<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        Self(ExposeHeadersInner::Const(separated_by_commas(
            headers.into_iter().map(Into::into),
        )))
    }

    pub(crate) fn is_wildcard(&self) -> bool {
        matches!(&self.0, ExposeHeadersInner::Const(Some(v)) if *v == WILDCARD)
    }

    pub(crate) fn to_header(&self, _parts: &RequestParts) -> Option<(HeaderName, HeaderValue)> {
        let value = match &self.0 {
            ExposeHeadersInner::Const(v) => v.clone()?,
        };
        Some((header::ACCESS_CONTROL_EXPOSE_HEADERS, value))
    }
}

impl std::fmt::Debug for ExposeHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ExposeHeadersInner::Const(inner) => f.debug_tuple("Const").field(inner).finish(),
        }
    }
}

impl<const N: usize> From<[HeaderName; N]> for ExposeHeaders {
    fn from(arr: [HeaderName; N]) -> Self {
        Self::list(arr)
    }
}

impl From<Vec<HeaderName>> for ExposeHeaders {
    fn from(vec: Vec<HeaderName>) -> Self {
        Self::list(vec)
    }
}

#[derive(Clone)]
enum ExposeHeadersInner {
    Const(Option<HeaderValue>),
}

impl Default for ExposeHeadersInner {
    fn default() -> Self {
        Self::Const(None)
    }
}
