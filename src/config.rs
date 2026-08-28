//! Builder for the [`Cors`] middleware.

use std::fmt;
use std::time::Duration;

use crate::{
    AllowCredentials, AllowHeaders, AllowMethods, AllowOrigin, ExposeHeaders, MaxAge, Vary,
};

/// Error returned by [`CorsBuilder::try_build`] when the configuration violates a
/// Fetch-mandated incompatibility.
///
/// Mirrors the panics produced by [`CorsBuilder::build`], so callers can choose to surface
/// the message as a startup error rather than a process abort.
///
/// [`CorsBuilder::build`]: CorsBuilder::build
/// [`CorsBuilder::try_build`]: CorsBuilder::try_build
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct ConfigError {
    message: &'static str,
}

impl ConfigError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Prefix with `Invalid CORS configuration:` to match the wording of the legacy
        // `assert!` messages, so existing log-grep tooling keeps working.
        write!(f, "Invalid CORS configuration: {}", self.message)
    }
}

impl std::error::Error for ConfigError {}

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

    /// Builds the [`Cors`] middleware wrapping `inner`, validating the configuration.
    ///
    /// # Panics
    ///
    /// Panics if any of the Fetch-mandated incompatibilities are violated. Use
    /// [`Self::try_build`] to receive the same diagnostics as a `Result` and translate them
    /// into a startup error instead of a panic.
    ///
    /// [`Cors`]: crate::Cors
    pub fn build<S>(self, inner: S) -> crate::Cors<S> {
        match self.try_build(inner) {
            Ok(cors) => cors,
            Err(e) => panic!("{e}"),
        }
    }

    /// Builds the [`Cors`] middleware wrapping `inner`, validating the configuration.
    ///
    /// Use this in startup paths so misconfiguration surfaces as a regular error rather
    /// than a process abort. [`Self::build`] panics with the same message.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when any Fetch-mandated incompatibility is violated:
    /// `allow_credentials: true` combined with `*` in `allow_origin`, `allow_methods`,
    /// `allow_headers`, or `expose_headers`.
    ///
    /// [`Cors`]: crate::Cors
    pub fn try_build<S>(self, inner: S) -> Result<crate::Cors<S>, ConfigError> {
        self.validate()?;
        let mut me = self;
        me.update_vary();
        Ok(crate::Cors::from_parts(inner, me))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.allow_credentials.is_true() {
            return Ok(());
        }
        if self.allow_origin.is_wildcard() {
            return Err(ConfigError::new(
                "cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Allow-Origin: *`. Echo the request origin instead.",
            ));
        }
        if self.allow_methods.is_wildcard() {
            return Err(ConfigError::new(
                "cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Allow-Methods: *`.",
            ));
        }
        if self.allow_headers.is_wildcard() {
            return Err(ConfigError::new(
                "cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Allow-Headers: *`.",
            ));
        }
        if self.expose_headers.is_wildcard() {
            return Err(ConfigError::new(
                "cannot combine `Access-Control-Allow-Credentials: true` \
                 with `Access-Control-Expose-Headers: *`.",
            ));
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> AllowOrigin {
        // Pick any non-wildcard origin so credentials can be combined safely.
        AllowOrigin::exact(http::HeaderValue::from_static("https://app.example.com"))
    }

    #[test]
    fn try_build_succeeds_for_default_config() {
        // Default config has credentials disabled; no incompatibilities to trip.
        let builder = CorsBuilder::new();
        let result: Result<crate::Cors<()>, ConfigError> = builder.try_build(());
        assert!(result.is_ok());
    }

    #[test]
    fn try_build_succeeds_for_credentials_with_concrete_origin_and_headers() {
        let builder = CorsBuilder::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(origin());
        let result: Result<crate::Cors<()>, ConfigError> = builder.try_build(());
        assert!(result.is_ok());
    }

    #[test]
    fn try_build_rejects_credentials_with_wildcard_origin() {
        let builder = CorsBuilder::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(crate::Any);
        let err = builder
            .try_build::<()>(())
            .expect_err("wildcard origin must be rejected");
        assert!(err.to_string().contains("Allow-Origin: *"));
    }

    #[test]
    fn try_build_rejects_credentials_with_wildcard_methods() {
        let builder = CorsBuilder::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(origin())
            .allow_methods(crate::AllowMethods::any());
        let err = builder
            .try_build::<()>(())
            .expect_err("wildcard methods must be rejected");
        assert!(err.to_string().contains("Allow-Methods: *"));
    }

    #[test]
    fn try_build_rejects_credentials_with_wildcard_headers() {
        let builder = CorsBuilder::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(origin())
            .allow_headers(crate::AllowHeaders::any());
        let err = builder
            .try_build::<()>(())
            .expect_err("wildcard headers must be rejected");
        assert!(err.to_string().contains("Allow-Headers: *"));
    }

    #[test]
    fn try_build_rejects_credentials_with_wildcard_expose_headers() {
        let builder = CorsBuilder::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(origin())
            .expose_headers(crate::ExposeHeaders::any());
        let err = builder
            .try_build::<()>(())
            .expect_err("wildcard expose-headers must be rejected");
        assert!(err.to_string().contains("Expose-Headers: *"));
    }

    #[test]
    fn build_still_panics_on_incompatible_config() {
        // `build` is the legacy panic-on-error path. Pin its behavior so a future refactor
        // can't silently swap it to a Result-returning signature.
        //
        // `AssertUnwindSafe` is required because `CorsBuilder` holds an `Arc<dyn Fn(...)>`
        // for the optional sync-predicate origin path, which is not `RefUnwindSafe`. The
        // predicate doesn't actually mutate any captured state in this test, so opting out
        // of the check is sound.
        let builder = CorsBuilder::new()
            .allow_credentials(AllowCredentials::yes())
            .allow_origin(crate::Any);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.build::<()>(())));
        assert!(result.is_err(), "build must panic on wildcard origin");
    }
}
