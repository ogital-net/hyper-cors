//! Minimal hyper 1.x server with `hyper-cors` middleware.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example server
//! ```
//!
//! In another terminal, exercise it with curl:
//!
//! ```sh
//! # Simple request from an allowed origin:
//! curl -i -H 'Origin: https://app.example.com' http://127.0.0.1:3000/
//!
//! # Preflight:
//! curl -i -X OPTIONS -H 'Origin: https://app.example.com' \
//!      -H 'Access-Control-Request-Method: POST' \
//!      -H 'Access-Control-Request-Headers: content-type' \
//!      http://127.0.0.1:3000/
//! ```

use std::{convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::Service;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use hyper_cors::Cors;

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
    let cors: Cors<Echo> = hyper_cors::builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_methods([Method::GET, Method::POST])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(600))
        .build(Echo);

    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();
    let listener = TcpListener::bind(addr).await.expect("bind 127.0.0.1:3000");
    eprintln!("listening on http://{addr}");

    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let svc = cors.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = Http1Builder::new().serve_connection(io, svc).await {
                eprintln!("connection error: {err}");
            }
        });
    }
}
