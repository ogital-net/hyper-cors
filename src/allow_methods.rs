//! Configuration for the `Access-Control-Allow-Methods` response header.

use http::{
    header::{self, HeaderName, HeaderValue, ACCESS_CONTROL_REQUEST_METHOD},
    request::Parts as RequestParts,
    Method,
};

use crate::{
    headers::WILDCARD,
    util::{is_valid_token, separated_by_commas},
};

/// Configuration for the `Access-Control-Allow-Methods` header.
#[derive(Clone, Default)]
#[must_use]
pub struct AllowMethods(AllowMethodsInner);

impl AllowMethods {
    /// Responds with `*`. Incompatible with credentials; see [`CorsBuilder::build`].
    ///
    /// [`CorsBuilder::build`]: crate::CorsBuilder::build
    pub fn any() -> Self {
        Self(AllowMethodsInner::Const(Some(WILDCARD)))
    }

    /// Responds with a fixed set of methods.
    pub fn list<I>(methods: I) -> Self
    where
        I: IntoIterator<Item = Method>,
    {
        Self(AllowMethodsInner::Const(separated_by_commas(
            methods.into_iter().map(|m| method_to_value(&m)),
        )))
    }

    /// Echoes the request's `Access-Control-Request-Method` header.
    ///
    /// The reflected value is validated as an HTTP token; non-token values are dropped so a
    /// malformed request header cannot inject control characters into the response.
    pub fn mirror_request() -> Self {
        Self(AllowMethodsInner::MirrorRequest)
    }

    /// Returns `true` if the configured value is the literal `*` (incompatible with
    /// credentials).
    pub(crate) fn is_wildcard(&self) -> bool {
        matches!(&self.0, AllowMethodsInner::Const(Some(v)) if *v == WILDCARD)
    }

    /// Returns `true` if the value depends on the request's `Access-Control-Request-Method`
    /// (so `Vary: Access-Control-Request-Method` is required).
    pub(crate) fn varies_with_request_method(&self) -> bool {
        matches!(&self.0, AllowMethodsInner::MirrorRequest)
    }

    pub(crate) fn to_header(&self, parts: &RequestParts) -> Option<(HeaderName, HeaderValue)> {
        let value = match &self.0 {
            AllowMethodsInner::Const(v) => v.clone()?,
            AllowMethodsInner::MirrorRequest => {
                let raw = parts.headers.get(ACCESS_CONTROL_REQUEST_METHOD)?;
                if !is_valid_token(raw.as_bytes()) {
                    return None;
                }
                raw.clone()
            }
        };
        Some((header::ACCESS_CONTROL_ALLOW_METHODS, value))
    }
}

impl std::fmt::Debug for AllowMethods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            AllowMethodsInner::Const(inner) => f.debug_tuple("Const").field(inner).finish(),
            AllowMethodsInner::MirrorRequest => f.debug_tuple("MirrorRequest").finish(),
        }
    }
}

impl<const N: usize> From<[Method; N]> for AllowMethods {
    fn from(arr: [Method; N]) -> Self {
        Self::list(arr)
    }
}

impl From<Vec<Method>> for AllowMethods {
    fn from(vec: Vec<Method>) -> Self {
        Self::list(vec)
    }
}

fn method_to_value(m: &Method) -> HeaderValue {
    // Every `Method` is a valid HTTP token, so `as_str()` always yields bytes that satisfy
    // `HeaderValue::from_bytes`.
    HeaderValue::from_bytes(m.as_str().as_bytes()).expect("Method is always a valid HeaderValue")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn parts_with_request_method(value: &str) -> RequestParts {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header(ACCESS_CONTROL_REQUEST_METHOD, value)
            .body(())
            .unwrap();
        req.into_parts().0
    }

    #[test]
    fn mirror_request_echoes_valid_token() {
        let am = AllowMethods::mirror_request();
        let parts = parts_with_request_method("DELETE");
        let (_, value) = am.to_header(&parts).expect("ACAM present");
        assert_eq!(value, "DELETE");
    }

    #[test]
    fn mirror_request_drops_non_token_value() {
        let am = AllowMethods::mirror_request();
        let parts = parts_with_request_method("bad method"); // contains space
        assert!(am.to_header(&parts).is_none());
    }

    #[test]
    fn const_value_does_not_depend_on_parts() {
        let am = AllowMethods::list([Method::GET, Method::POST]);
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .body(())
            .unwrap();
        let parts = req.into_parts().0;
        let (_, value) = am.to_header(&parts).expect("ACAM present");
        assert_eq!(value, "GET,POST");
    }
}

#[derive(Clone, Default)]
enum AllowMethodsInner {
    Const(Option<HeaderValue>),
    #[default]
    MirrorRequest,
}
