//! Per-tenant origin allow-list using `AllowOrigin::async_predicate`.
//!
//! The "database" here is an in-memory map guarded by `tokio::sync::RwLock`, repopulated
//! from a real source on startup. The async predicate looks up the request's `Origin` on
//! every preflight. In a real deployment you would replace the map with a Redis or
//! database lookup; the `Cors` middleware is agnostic to which.

use std::{collections::HashSet, convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::Service;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use hyper_cors::{AllowOrigin, Cors};

#[derive(Clone)]
struct Tenants(Arc<RwLock<HashSet<String>>>);

#[derive(Clone)]
struct Echo;

impl Service<Request<Incoming>> for Echo {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, _req: Request<Incoming>) -> Self::Future {
        std::future::ready(Ok(Response::new(Full::new(Bytes::from_static(b"ok\n")))))
    }
}

#[tokio::main]
async fn main() {
    // Simulated database: set of allowed origins. Real deployments would load this from
    // Postgres / Redis / etc.
    let mut origins: HashSet<String> = HashSet::new();
    origins.insert("https://acme.example.com".to_owned());
    origins.insert("https://umbrella.example.com".to_owned());
    let tenants = Tenants(Arc::new(RwLock::new(origins)));

    // The async predicate holds an `Arc` clone of the cache so the lookup is cheap and
    // stays live for the lifetime of the middleware.
    let policy = {
        let tenants = tenants.clone();
        AllowOrigin::async_predicate(move |origin, _parts| {
            let tenants = tenants.clone();
            async move {
                let origin = origin.to_str().unwrap_or("").to_owned();
                tenants.0.read().await.contains(&origin)
            }
        })
    };

    let cors: Cors<Echo> = hyper_cors::builder()
        .allow_origin(policy)
        .allow_methods([Method::GET, Method::POST])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600))
        .build(Echo);

    let addr: std::net::SocketAddr = ([127, 0, 0, 1], 3001).into();
    let listener = TcpListener::bind(addr).await.expect("bind 127.0.0.1:3001");
    eprintln!("listening on http://{addr}");

    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        // `serve_connection` takes the service by value (hyper 1.x API), so we clone
        // per accepted connection. The clone is cheap: `Cors<S>` holds the configuration
        // behind an `Arc<CorsBuilder>`, and the `Tenants` cache is itself behind an `Arc`
        // shared with the async predicate, so the only per-connection work is two atomic
        // refcount bumps.
        let svc = cors.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = Http1Builder::new().serve_connection(io, svc).await {
                eprintln!("connection error: {err}");
            }
        });
    }
}
