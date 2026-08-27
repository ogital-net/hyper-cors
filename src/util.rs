//! Helpers for assembling `HeaderValue`s.

use bytes::{BufMut, BytesMut};
use http::HeaderValue;

/// Joins an iterator of `HeaderValue`s with `,`. Returns `None` if the iterator is empty.
pub(crate) fn separated_by_commas<I>(mut iter: I) -> Option<HeaderValue>
where
    I: Iterator<Item = HeaderValue>,
{
    let fst = iter.next()?;
    let mut result = BytesMut::from(fst.as_bytes());
    for val in iter {
        result.reserve(val.len() + 1);
        result.put_u8(b',');
        result.extend_from_slice(val.as_bytes());
    }
    Some(HeaderValue::from_maybe_shared(result.freeze()).unwrap())
}

/// Returns `true` if `s` is a valid HTTP token (RFC 7230 Sec. 3.2.6).
pub(crate) fn is_valid_token(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_with_commas() {
        let v = separated_by_commas(
            [HeaderValue::from_static("a"), HeaderValue::from_static("b")].into_iter(),
        )
        .unwrap();
        assert_eq!(v, "a,b");
    }

    #[test]
    fn empty_iterator_yields_none() {
        assert!(separated_by_commas(std::iter::empty::<HeaderValue>()).is_none());
    }

    #[test]
    fn valid_token_recognised() {
        assert!(is_valid_token(b"content-type"));
        assert!(is_valid_token(b"X-Foo"));
        assert!(!is_valid_token(b""));
        assert!(!is_valid_token(b"with space"));
        assert!(!is_valid_token(b"with,comma"));
    }
}
