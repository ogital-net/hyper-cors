//! Configuration for the `Access-Control-Max-Age` response header.

use std::time::Duration;

use http::{
    header::{self, HeaderName, HeaderValue},
    request::Parts as RequestParts,
};

/// Configuration for the `Access-Control-Max-Age` header.
#[derive(Clone, Default)]
#[must_use]
pub struct MaxAge(MaxAgeInner);

impl MaxAge {
    /// Sets a fixed max-age value.
    pub fn exact(max_age: Duration) -> Self {
        Self(MaxAgeInner::Exact(seconds_to_header_value(
            max_age.as_secs(),
        )))
    }

    /// Omits `Access-Control-Max-Age` from responses, so browsers re-preflight every time.
    pub fn none() -> Self {
        Self(MaxAgeInner::Exact(None))
    }

    pub(crate) fn to_header(
        &self,
        _origin: Option<&HeaderValue>,
        _parts: &RequestParts,
    ) -> Option<(HeaderName, HeaderValue)> {
        match &self.0 {
            MaxAgeInner::Exact(v) => v.clone().map(|v| (header::ACCESS_CONTROL_MAX_AGE, v)),
        }
    }
}

impl std::fmt::Debug for MaxAge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            MaxAgeInner::Exact(inner) => f.debug_tuple("Exact").field(inner).finish(),
        }
    }
}

impl From<Duration> for MaxAge {
    fn from(d: Duration) -> Self {
        Self::exact(d)
    }
}

#[derive(Clone)]
enum MaxAgeInner {
    Exact(Option<HeaderValue>),
}

impl Default for MaxAgeInner {
    fn default() -> Self {
        Self::Exact(None)
    }
}

fn seconds_to_header_value(seconds: u64) -> Option<HeaderValue> {
    let mut buf = Vec::with_capacity(20);
    let mut n = seconds;
    if n == 0 {
        buf.push(b'0');
    } else {
        let mut tmp = [0u8; 20];
        let mut i = 0;
        while n > 0 {
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            buf.push(tmp[i]);
        }
    }
    HeaderValue::from_bytes(&buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn formats_known_values() {
        assert_eq!(seconds_to_header_value(0).unwrap(), "0");
        assert_eq!(seconds_to_header_value(60).unwrap(), "60");
        assert_eq!(seconds_to_header_value(600).unwrap(), "600");
        assert_eq!(
            seconds_to_header_value(u64::MAX).unwrap(),
            u64::MAX.to_string()
        );
    }

    #[test]
    fn none_emits_no_header() {
        let ma = MaxAge::none();
        let req = Request::builder()
            .method(http::Method::OPTIONS)
            .uri("/")
            .header(http::header::ORIGIN, "https://x.example")
            .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(())
            .unwrap();
        let parts = req.into_parts().0;
        let origin = parts.headers.get(http::header::ORIGIN).cloned();
        assert!(ma.to_header(origin.as_ref(), &parts).is_none());
    }

    #[test]
    fn default_equals_none() {
        // `Default` and `none()` produce the same "no header" configuration.
        assert!(MaxAge::default().to_header(None, &empty_parts()).is_none());
        assert!(MaxAge::none().to_header(None, &empty_parts()).is_none());
    }

    fn empty_parts() -> http::request::Parts {
        Request::builder()
            .method(http::Method::GET)
            .uri("/")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }
}
