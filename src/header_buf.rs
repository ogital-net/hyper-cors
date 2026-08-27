//! Fixed-capacity, stack-allocated buffer of CORS response headers.

use http::{HeaderName, HeaderValue};

/// Maximum number of CORS headers that can appear on a single response.
///
/// `Vary` + `Allow-Origin` + `Allow-Credentials` + `Allow-Methods` + `Allow-Headers` +
/// (`Max-Age` on preflight | `Expose-Headers` on simple requests) = 6.
const CAPACITY: usize = 6;

#[derive(Debug, Default)]
pub(crate) struct HeaderBuf {
    slots: [Option<(HeaderName, HeaderValue)>; CAPACITY],
    len: usize,
}

impl HeaderBuf {
    /// Appends a header pair.
    ///
    /// # Panics
    ///
    /// Panics if more than [`CAPACITY`] pairs are pushed. The set of CORS headers is fixed
    /// and known at compile time, so exceeding this is a bug in this crate.
    pub(crate) fn push(&mut self, pair: (HeaderName, HeaderValue)) {
        assert!(
            self.len < CAPACITY,
            "HeaderBuf overflow: more than {CAPACITY} CORS headers on one response"
        );
        self.slots[self.len] = Some(pair);
        self.len += 1;
    }

    /// Append a header pair if present; a no-op for `None`.
    pub(crate) fn push_opt(&mut self, pair: Option<(HeaderName, HeaderValue)>) {
        if let Some(pair) = pair {
            self.push(pair);
        }
    }

    /// Iterate over the stored pairs in insertion order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(HeaderName, HeaderValue)> {
        self.slots[..self.len].iter().filter_map(Option::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header;

    fn pair(n: HeaderName) -> (HeaderName, HeaderValue) {
        (n, HeaderValue::from_static("x"))
    }

    #[test]
    fn preserves_insertion_order() {
        let mut buf = HeaderBuf::default();
        buf.push(pair(header::VARY));
        buf.push(pair(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        let names: Vec<_> = buf.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(
            names,
            vec![header::VARY, header::ACCESS_CONTROL_ALLOW_ORIGIN]
        );
    }

    #[test]
    fn push_opt_skips_none() {
        let mut buf = HeaderBuf::default();
        buf.push_opt(None);
        buf.push_opt(Some(pair(header::VARY)));
        assert_eq!(buf.iter().count(), 1);
    }

    #[test]
    fn empty_buffer_iterates_empty() {
        assert_eq!(HeaderBuf::default().iter().count(), 0);
    }

    #[test]
    fn accepts_full_capacity() {
        let mut buf = HeaderBuf::default();
        for _ in 0..CAPACITY {
            buf.push(pair(header::VARY));
        }
        assert_eq!(buf.iter().count(), CAPACITY);
    }

    #[test]
    #[should_panic(expected = "HeaderBuf overflow")]
    fn panics_past_capacity() {
        let mut buf = HeaderBuf::default();
        for _ in 0..=CAPACITY {
            buf.push(pair(header::VARY));
        }
    }
}
