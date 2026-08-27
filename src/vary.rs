//! Configuration for the `Vary` response header.
//!
//! The set of names is derived from the other CORS knobs unless the user pins it via
//! [`CorsBuilder::vary`].
//!
//! [`CorsBuilder::vary`]: crate::CorsBuilder::vary

use http::header::{
    self, HeaderName, HeaderValue, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
    ORIGIN,
};

/// Configuration for the `Vary` header.
///
/// The joined value is computed once at construction; the set of names never changes after
/// [`crate::CorsBuilder::build`].
#[derive(Clone, Debug)]
#[must_use]
pub struct Vary(Option<HeaderValue>);

impl Vary {
    /// Sets the list of header names returned in `Vary`.
    pub fn list<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        Self(join_names(headers))
    }

    pub(crate) fn to_header(&self) -> Option<(HeaderName, HeaderValue)> {
        self.0.clone().map(|v| (header::VARY, v))
    }

    /// Returns the default set of header names.
    pub(crate) fn default_header_names() -> Vec<HeaderName> {
        vec![
            ORIGIN,
            ACCESS_CONTROL_REQUEST_METHOD,
            ACCESS_CONTROL_REQUEST_HEADERS,
        ]
    }
}

impl Default for Vary {
    fn default() -> Self {
        Self::list(Self::default_header_names())
    }
}

fn join_names<I>(headers: I) -> Option<HeaderValue>
where
    I: IntoIterator<Item = HeaderName>,
{
    let mut iter = headers.into_iter();
    let first = iter.next()?;
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(first.as_str().as_bytes());
    for name in iter {
        buf.extend_from_slice(b", ");
        buf.extend_from_slice(name.as_str().as_bytes());
    }
    Some(
        HeaderValue::from_bytes(&buf)
            .expect("comma-separated list of header names is always a valid HeaderValue"),
    )
}

impl<const N: usize> From<[HeaderName; N]> for Vary {
    fn from(arr: [HeaderName; N]) -> Self {
        Self::list(arr)
    }
}

impl From<Vec<HeaderName>> for Vary {
    fn from(vec: Vec<HeaderName>) -> Self {
        Self::list(vec)
    }
}
