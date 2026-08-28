//! CORS middleware for hyper 1.x.
//!
//! [`Cors`] is a [`hyper::service::Service`] that wraps an inner service and applies the
//! [Cross-Origin Resource Sharing][mdn] protocol to every request.
//!
//! Preflight requests (`OPTIONS` with `Access-Control-Request-Method`) are short-circuited
//! by default, so the inner service never sees them.
//!
//! # Example
//!
//! ```
//! use std::{convert::Infallible, time::Duration};
//! use http::Method;
//! use hyper::{Request, Response, service::Service, body::Incoming};
//! use http_body_util::Full;
//! use bytes::Bytes;
//! use hyper_cors::{Any, Cors};
//!
//! async fn handle(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
//!     Ok(Response::new(Full::new(Bytes::from("ok"))))
//! }
//!
//! # async fn run() {
//! let svc = hyper_cors::builder()
//!     .allow_origin(Any)
//!     .allow_methods([Method::GET, Method::POST])
//!     .max_age(Duration::from_secs(600))
//!     .build(handle);
//! # }
//! ```
//!
//! [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

mod allow_credentials;
mod allow_headers;
mod allow_methods;
mod allow_origin;
mod config;
mod cors;
mod expose_headers;
mod header_buf;
mod headers;
mod max_age;
mod util;
mod vary;

pub use allow_credentials::AllowCredentials;
pub use allow_headers::AllowHeaders;
pub use allow_methods::AllowMethods;
pub use allow_origin::{AllowOrigin, Any};
pub use config::{ConfigError, CorsBuilder};
pub use cors::{builder, Cors};
pub use expose_headers::ExposeHeaders;
pub use max_age::MaxAge;
pub use vary::Vary;
