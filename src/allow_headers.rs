//! Configuration for the `Access-Control-Allow-Headers` response header.

use http::{
    header::{self, HeaderName, HeaderValue, ACCESS_CONTROL_REQUEST_HEADERS},
    request::Parts as RequestParts,
};

use crate::{
    headers::WILDCARD,
    util::{is_valid_token, separated_by_commas},
};

/// Configuration for the `Access-Control-Allow-Headers` header.
#[derive(Clone, Default)]
#[must_use]
pub struct AllowHeaders(AllowHeadersInner);

impl AllowHeaders {
    /// Responds with `*`. Incompatible with credentials; see [`CorsBuilder::build`].
    ///
    /// [`CorsBuilder::build`]: crate::CorsBuilder::build
    pub fn any() -> Self {
        Self(AllowHeadersInner::Const(Some(WILDCARD)))
    }

    /// Responds with a fixed set of header names.
    pub fn list<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        Self(AllowHeadersInner::Const(separated_by_commas(
            headers.into_iter().map(Into::into),
        )))
    }

    /// Echoes the request's `Access-Control-Request-Headers` header verbatim, with each
    /// token validated as an HTTP token.
    pub fn mirror_request() -> Self {
        Self(AllowHeadersInner::MirrorRequest)
    }

    pub(crate) fn is_wildcard(&self) -> bool {
        matches!(&self.0, AllowHeadersInner::Const(Some(v)) if *v == WILDCARD)
    }

    pub(crate) fn varies_with_request_headers(&self) -> bool {
        matches!(&self.0, AllowHeadersInner::MirrorRequest)
    }

    pub(crate) fn to_header(&self, parts: &RequestParts) -> Option<(HeaderName, HeaderValue)> {
        let value = match &self.0 {
            AllowHeadersInner::Const(v) => v.clone()?,
            AllowHeadersInner::MirrorRequest => {
                let raw = parts.headers.get(ACCESS_CONTROL_REQUEST_HEADERS)?;
                mirror_sanitized(raw)?
            }
        };
        Some((header::ACCESS_CONTROL_ALLOW_HEADERS, value))
    }
}

impl std::fmt::Debug for AllowHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            AllowHeadersInner::Const(inner) => f.debug_tuple("Const").field(inner).finish(),
            AllowHeadersInner::MirrorRequest => f.debug_tuple("MirrorRequest").finish(),
        }
    }
}

impl<const N: usize> From<[HeaderName; N]> for AllowHeaders {
    fn from(arr: [HeaderName; N]) -> Self {
        Self::list(arr)
    }
}

impl From<Vec<HeaderName>> for AllowHeaders {
    fn from(vec: Vec<HeaderName>) -> Self {
        Self::list(vec)
    }
}

/// Filters `Access-Control-Request-Headers` to valid tokens, preserving their order.
fn mirror_sanitized(raw: &HeaderValue) -> Option<HeaderValue> {
    let bytes = raw.as_bytes();

    // Fast path: when every token is already valid, the sanitized output is byte-for-byte
    // identical to the input.
    if bytes.split(|&b| b == b',').all(is_valid_token) {
        return Some(raw.clone());
    }

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    for tok in bytes.split(|&b| b == b',') {
        let cleaned = tok.trim_ascii();
        if !is_valid_token(cleaned) {
            continue;
        }
        if !out.is_empty() {
            out.push(b',');
        }
        out.extend_from_slice(cleaned);
    }
    if out.is_empty() {
        return None;
    }
    HeaderValue::from_bytes(&out).ok()
}

#[derive(Clone, Default)]
enum AllowHeadersInner {
    Const(Option<HeaderValue>),
    #[default]
    MirrorRequest,
}
