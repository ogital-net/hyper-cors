//! Builder for the [`Cors`] middleware.

use std::time::Duration;

use crate::{
    AllowCredentials, AllowHeaders, AllowMethods, AllowOrigin, ExposeHeaders, MaxAge, Vary,
};

/// Builder for [`Cors`].
///
/// Construct one with [`CorsBuilder::new`] (or [`builder`](crate::builder)), chain the
/// configuration methods, and call [`CorsBuilder::build`] to produce the middleware.
///
/// # Defaults
///
/// | Field | Default |
/// |---|---|
/// | `allow_origin` | empty list (no origins allowed; non-CORS requests still pass through) |
/// | `allow_credentials` | `false` |
/// | `allow_methods` | mirror request (`Access-Control-Request-Method`) |
/// | `allow_headers` | mirror request (`Access-Control-Request-Headers`) |
/// | `expose_headers` | empty |
/// | `max_age` | not emitted |
/// | `vary` | derived from the other knobs |
/// | `deliver_preflight` | `false` (preflight is short-circuited) |
/// | `deliver_non_allowed_origin` | `true` |
/// | `deliver_non_allowed_origin_websocket_upgrade` | `false` |
/// | `rejection_status` | `400 Bad Request` |
///
/// [`Cors`]: crate::Cors
#[derive(Clone, Debug)]
#[must_use]
#[allow(clippy::struct_excessive_bools)]
pub struct CorsBuilder {
    pub(crate) allow_origin: AllowOrigin,
    pub(crate) allow_credentials: AllowCredentials,
    pub(crate) allow_methods: AllowMethods,
    pub(crate) allow_headers: AllowHeaders,
    pub(crate) expose_headers: ExposeHeaders,
    pub(crate) max_age: MaxAge,
    pub(crate) vary: Vary,
    pub(crate) vary_pinned: bool,
    pub(crate) deliver_preflight: bool,
    pub(crate) deliver_non_allowed_origin: bool,
    pub(crate) deliver_non_allowed_origin_websocket_upgrade: bool,
    pub(crate) rejection_status: http::StatusCode,
}

impl Default for CorsBuilder {
    fn default() -> Self {
        Self {
            allow_origin: AllowOrigin::default(),
            allow_credentials: AllowCredentials::default(),
            allow_methods: AllowMethods::default(),
            allow_headers: AllowHeaders::default(),
            expose_headers: ExposeHeaders::default(),
            max_age: MaxAge::default(),
            vary: Vary::default(),
            vary_pinned: false,
            deliver_preflight: false,
            deliver_non_allowed_origin: true,
            // Browsers do not enforce CORS on WebSocket handshakes, so an unchecked upgrade
            // is a cross-site hijacking vector; reject by default.
            deliver_non_allowed_origin_websocket_upgrade: false,
            rejection_status: http::StatusCode::BAD_REQUEST,
        }
    }
}

impl CorsBuilder {
    /// Returns a builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `Access-Control-Allow-Origin` policy.
    pub fn allow_origin<T>(mut self, allow_origin: T) -> Self
    where
        T: Into<AllowOrigin>,
    {
        self.allow_origin = allow_origin.into();
        self
    }

    /// Sets whether to send `Access-Control-Allow-Credentials`.
    pub fn allow_credentials<T>(mut self, allow_credentials: T) -> Self
    where
        T: Into<AllowCredentials>,
    {
        self.allow_credentials = allow_credentials.into();
        self
    }

    /// Sets the methods advertised in `Access-Control-Allow-Methods`.
    pub fn allow_methods<T>(mut self, allow_methods: T) -> Self
    where
        T: Into<AllowMethods>,
    {
        self.allow_methods = allow_methods.into();
        self
    }

    /// Sets the headers advertised in `Access-Control-Allow-Headers`.
    pub fn allow_headers<T>(mut self, allow_headers: T) -> Self
    where
        T: Into<AllowHeaders>,
    {
        self.allow_headers = allow_headers.into();
        self
    }

    /// Sets the headers advertised in `Access-Control-Expose-Headers`.
    pub fn expose_headers<T>(mut self, expose_headers: T) -> Self
    where
        T: Into<ExposeHeaders>,
    {
        self.expose_headers = expose_headers.into();
        self
    }

    /// Sets the `Access-Control-Max-Age` value.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = MaxAge::exact(max_age);
        self
    }

    /// Pins `Vary` to a specific list of header names, disabling automatic derivation.
    pub fn vary<T>(mut self, headers: T) -> Self
    where
        T: Into<Vary>,
    {
        self.vary = headers.into();
        self.vary_pinned = true;
        self
    }

    /// If `false` (default), preflight requests are short-circuited and answered with a
    /// synthetic `200 OK` carrying the CORS headers. If `true`, preflight is forwarded to
    /// the inner service after CORS headers are added.
    pub fn deliver_preflight(mut self, deliver: bool) -> Self {
        self.deliver_preflight = deliver;
        self
    }

    /// If `true` (default), requests whose `Origin` is not allowed are still passed to the
    /// inner service (the response just won't carry CORS headers). If `false`, such requests
    /// are rejected with [`Self::rejection_status`] directly.
    pub fn deliver_non_allowed_origin(mut self, deliver: bool) -> Self {
        self.deliver_non_allowed_origin = deliver;
        self
    }

    /// If `false` (default), disallowed-origin WebSocket upgrade requests (those carrying
    /// `Sec-WebSocket-Version`) are rejected, even when [`Self::deliver_non_allowed_origin`]
    /// is `true`.
    ///
    /// Browsers do not apply CORS to WebSocket handshakes, so an unchecked upgrade is a
    /// cross-site hijacking vector: the browser opens the socket with the user's cookies
    /// attached.
    pub fn deliver_non_allowed_origin_websocket_upgrade(mut self, deliver: bool) -> Self {
        self.deliver_non_allowed_origin_websocket_upgrade = deliver;
        self
    }

    /// Sets the status code used to reject disallowed-origin requests when
    /// [`Self::deliver_non_allowed_origin`] is `false`.
    ///
    /// Defaults to `400 Bad Request`. Use `403 Forbidden` to signal the rejection as a
    /// refusal.
    pub fn rejection_status(mut self, status: http::StatusCode) -> Self {
        self.rejection_status = status;
        self
    }

    /// Builds the [`Cors`] middleware wrapping `inner`.
    ///
    /// # Panics
    ///
    /// Panics if any of the Fetch-mandated incompatibilities are violated:
    /// `allow_credentials: true` combined with `allow_origin: *`, `allow_methods: *`,
    /// `allow_headers: *`, or `expose_headers: *`.
    ///
    /// [`Cors`]: crate::Cors
    pub fn build<S>(self, inner: S) -> crate::Cors<S> {
        self.validate();
        let mut me = self;
        me.update_vary();
        crate::Cors::from_parts(inner, me)
    }

    fn validate(&self) {
        if self.allow_credentials.is_true() {
            assert!(
                !self.allow_origin.is_wildcard(),
                "Invalid CORS configuration: cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Allow-Origin: *`. Echo the request origin instead."
            );
            assert!(
                !self.allow_methods.is_wildcard(),
                "Invalid CORS configuration: cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Allow-Methods: *`."
            );
            assert!(
                !self.allow_headers.is_wildcard(),
                "Invalid CORS configuration: cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Allow-Headers: *`."
            );
            assert!(
                !self.expose_headers.is_wildcard(),
                "Invalid CORS configuration: cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Expose-Headers: *`."
            );
        }
    }

    /// Recompute the default `Vary` header set, unless the user pinned it via [`Self::vary`].
    pub(crate) fn update_vary(&mut self) {
        if self.vary_pinned {
            return;
        }
        let vary_method = self.allow_methods.varies_with_request_method();
        let vary_headers = self.allow_headers.varies_with_request_headers();

        let mut names = Vec::with_capacity(3);
        // `Origin` is always included: the response is always potentially origin-dependent
        // when a CORS middleware is installed, so caches must not serve one origin's response
        // to another.
        names.push(http::header::ORIGIN);
        if vary_method {
            names.push(http::header::ACCESS_CONTROL_REQUEST_METHOD);
        }
        if vary_headers {
            names.push(http::header::ACCESS_CONTROL_REQUEST_HEADERS);
        }
        self.vary = Vary::list(names);
    }
}
