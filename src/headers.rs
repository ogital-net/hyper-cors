//! Pre-encoded header constants.

use http::HeaderValue;

/// Pre-encoded `*`.
pub(crate) const WILDCARD: HeaderValue = HeaderValue::from_static("*");

/// Pre-encoded `true` for `Access-Control-Allow-Credentials`.
pub(crate) const ALLOW_CREDENTIALS_TRUE: HeaderValue = HeaderValue::from_static("true");
