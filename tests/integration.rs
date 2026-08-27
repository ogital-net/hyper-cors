//! Integration tests covering the canonical CORS scenarios ported from Jetty's
//! `CrossOriginHandlerTest` and tower-http's `cors::tests`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use http::{header, HeaderName, Method, Request};
use http_body_util::Empty;
use hyper::service::Service;

use bytes::Bytes;
use hyper_cors::{
    builder, AllowCredentials, AllowHeaders, AllowMethods, AllowOrigin, Any, ExposeHeaders, MaxAge,
};

use common::{ac_headers, body_to_string, get, preflight, vary, EchoService};

// ---------------------------------------------------------------------------
// Same-origin / no-origin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_origin_header_passes_through_with_vary() {
    let svc = builder().allow_origin(Any).build(EchoService::ok());
    let resp = svc.call(get(None)).await.unwrap();
    assert_eq!(resp.status(), 200);
    // Vary: Origin is always emitted once a CORS middleware is installed -- Jetty-aligned.
    let v = vary(&resp).expect("vary present");
    assert!(v.to_ascii_lowercase().contains("origin"));
    // The response carries the inner service's body.
    assert_eq!(body_to_string(resp.into_body()).await, "ok");
}

#[tokio::test]
async fn no_origin_still_emits_vary_when_origin_dependent() {
    let svc = builder()
        .allow_origin(AllowOrigin::list(["https://app.example.com"
            .parse()
            .unwrap()]))
        .build(EchoService::ok());
    let resp = svc.call(get(None)).await.unwrap();
    let v = vary(&resp).expect("vary present");
    assert!(v.to_ascii_lowercase().contains("origin"));
}

#[tokio::test]
async fn vary_always_includes_origin_even_with_any() {
    // Jetty's behavior: `Vary: Origin` is always emitted by a configured CORS handler, even when
    // the origin policy is a constant (`Any`, exact, list-of-one). Emitting an extra Vary value is
    // safe and prevents cache-poisoning regressions if the config later becomes request-dependent.
    let svc = builder().allow_origin(Any).build(EchoService::ok());
    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    let v = vary(&resp).expect("vary present");
    let v_lower = v.to_ascii_lowercase();
    assert!(v_lower.contains("origin"));
}

#[tokio::test]
async fn vary_omitted_when_pinned_to_empty_list() {
    // Users can pin `Vary` to suppress it (or to set their own value).
    let svc = builder()
        .allow_origin(Any)
        .vary(Vec::<http::HeaderName>::new())
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    // Pinned empty list -> no Vary header at all.
    assert!(vary(&resp).is_none(), "pinned empty Vary should be omitted");
}

// ---------------------------------------------------------------------------
// Simple cross-origin requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn matching_origin_returns_acao_and_vary() {
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(EchoService::ok());
    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    let h = ac_headers(&resp);
    assert_eq!(
        h,
        vec![(
            "access-control-allow-origin".to_string(),
            "https://app.example.com".to_string()
        )]
    );
    assert!(vary(&resp).unwrap().to_ascii_lowercase().contains("origin"));
}

#[tokio::test]
async fn non_matching_origin_omits_acao_but_reaches_inner_service() {
    // Default `deliver_non_allowed_origin = true`.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(ac_headers(&resp), vec![]);
    assert_eq!(body_to_string(resp.into_body()).await, "ok");
}

#[tokio::test]
async fn wildcard_origin_sends_star_without_creds() {
    let svc = builder().allow_origin(Any).build(EchoService::ok());
    let resp = svc.call(get(Some("https://anything.test"))).await.unwrap();
    let h = ac_headers(&resp);
    assert_eq!(
        h,
        vec![("access-control-allow-origin".to_string(), "*".to_string())]
    );
}

#[tokio::test]
async fn list_origin_echoes_request_origin() {
    let svc = builder()
        .allow_origin([
            "https://a.example".parse().unwrap(),
            "https://b.example".parse().unwrap(),
        ])
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://b.example"))).await.unwrap();
    assert_eq!(
        ac_headers(&resp),
        vec![(
            "access-control-allow-origin".to_string(),
            "https://b.example".to_string()
        )]
    );
}

#[tokio::test]
async fn expose_headers_emitted_on_simple_request() {
    let svc = builder()
        .allow_origin(Any)
        .expose_headers([header::CONTENT_ENCODING])
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    assert!(ac_headers(&resp)
        .iter()
        .any(|(n, v)| n == "access-control-expose-headers" && v.contains("content-encoding")));
}

#[tokio::test]
async fn expose_headers_from_array_emits_list() {
    // `ExposeHeaders::From<[HeaderName; N]>` -- the array-into impl is used when callers
    // write `.expose_headers([...])`. Round-trips through the public builder path.
    let svc = builder()
        .allow_origin(Any)
        .expose_headers([
            HeaderName::from_static("x-trace-id"),
            HeaderName::from_static("x-rate-limit"),
        ])
        .build(EchoService::ok());

    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    let v = acs
        .get("access-control-expose-headers")
        .expect("ACEH present");
    assert!(v.contains("x-trace-id"));
    assert!(v.contains("x-rate-limit"));
}

#[tokio::test]
async fn expose_headers_from_vec_constructor() {
    // `ExposeHeaders::list(Vec<HeaderName>)` -- explicit constructor path for callers who
    // build the value programmatically.
    let svc = builder()
        .allow_origin(Any)
        .expose_headers(ExposeHeaders::list(vec![HeaderName::from_static("x-a")]))
        .build(EchoService::ok());

    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-expose-headers").map(String::as_str),
        Some("x-a")
    );
}

#[tokio::test]
async fn allow_origin_mirror_request_echoes_request_origin() {
    // `AllowOrigin::mirror_request` always echoes the request's `Origin` header, so even
    // a previously-disallowed origin is reflected when this policy is configured.
    let svc = builder()
        .allow_origin(AllowOrigin::mirror_request())
        .build(EchoService::ok());

    let resp = svc
        .call(get(Some("https://anything.example")))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://anything.example")
    );

    let resp = svc.call(get(Some("https://other.example"))).await.unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://other.example")
    );
}

// ---------------------------------------------------------------------------
// Preflight (OPTIONS + Access-Control-Request-Method)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preflight_with_matching_origin_short_circuits() {
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_methods([Method::GET, Method::POST])
        .max_age(Duration::from_secs(60))
        .build(EchoService::ok());

    let resp = svc
        .call(preflight(
            "https://app.example.com",
            "POST",
            Some("content-type"),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://app.example.com")
    );
    assert_eq!(
        acs.get("access-control-allow-methods").map(String::as_str),
        Some("GET,POST")
    );
    assert_eq!(
        acs.get("access-control-max-age").map(String::as_str),
        Some("60")
    );
    assert_eq!(
        acs.get("access-control-allow-headers").map(String::as_str),
        Some("content-type")
    );
    // Preflight is short-circuited -- the inner service's body is NOT returned.
    let body = body_to_string(resp.into_body()).await;
    assert_eq!(body, "", "preflight body should be empty");
}

#[tokio::test]
async fn preflight_with_non_matching_origin_omits_acao_and_skips_inner() {
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://evil.example", "POST", None))
        .await
        .unwrap();

    // Default `deliver_non_allowed_origin = true` plus `deliver_preflight = false` means:
    // preflight is still short-circuited (the inner service never sees it), but no ACAO.
    assert_eq!(resp.status(), 200);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
    assert_eq!(body_to_string(resp.into_body()).await, "");
}

#[tokio::test]
async fn preflight_delivered_when_configured() {
    // When deliver_preflight is true, the preflight goes to the inner service after headers
    // are added. The inner service's body should come through.
    let svc = builder()
        .allow_origin(Any)
        .deliver_preflight(true)
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(body_to_string(resp.into_body()).await, "ok");
}

#[tokio::test]
async fn preflight_mirror_request_methods() {
    let svc = builder()
        .allow_origin(Any)
        .allow_methods(hyper_cors::AllowMethods::mirror_request())
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://x.example", "DELETE", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-methods").map(String::as_str),
        Some("DELETE")
    );
}

#[tokio::test]
async fn preflight_mirror_request_headers_sanitised() {
    let svc = builder()
        .allow_origin(Any)
        .allow_headers(AllowHeaders::mirror_request())
        .build(EchoService::ok());

    let resp = svc
        .call(preflight(
            "https://x.example",
            "POST",
            Some("content-type, x-custom"),
        ))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    let ach = acs
        .get("access-control-allow-headers")
        .expect("ACAH present");
    assert!(ach.contains("content-type"));
    assert!(ach.contains("x-custom"));
}

#[tokio::test]
async fn preflight_mirror_request_headers_drops_invalid_tokens() {
    use http::HeaderValue;
    let svc = builder()
        .allow_origin(Any)
        .allow_headers(AllowHeaders::mirror_request())
        .build(EchoService::ok());

    // Build the request manually because the header value contains raw whitespace which
    // `Request::builder().header()` rejects.
    let bad_value = HeaderValue::from_bytes(b"ok-header, with space, , ,bad-token")
        .expect("header value with commas and spaces is valid");
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header("origin", "https://x.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", bad_value)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = svc.call(req).await.unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    let ach = acs
        .get("access-control-allow-headers")
        .expect("ACAH present");
    let parts: Vec<&str> = ach.split(',').map(str::trim).collect();
    assert!(parts.contains(&"ok-header"));
    assert!(parts.contains(&"bad-token"));
    assert!(!parts.contains(&"with space"));
    // Empty entries (consecutive commas) should be collapsed away.
    assert!(
        !parts.contains(&""),
        "empty entries should be filtered, got parts: {parts:?}"
    );
}

#[tokio::test]
async fn deliver_preflight_true_emits_preflight_headers_on_response() {
    // `preflight_delivered_when_configured` only checks that the inner service's body
    // comes through. It does NOT verify the CORS layer still adds the preflight headers
    // (ACAO, ACAM, ACAH, ACMA) on the response. This test pins that contract.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_methods([Method::GET, Method::POST])
        .max_age(Duration::from_secs(120))
        .deliver_preflight(true)
        .build(EchoService::ok());

    let resp = svc
        .call(preflight(
            "https://app.example.com",
            "POST",
            Some("content-type"),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://app.example.com"),
        "deliver_preflight=true must still set ACAO"
    );
    assert_eq!(
        acs.get("access-control-allow-methods").map(String::as_str),
        Some("GET,POST"),
        "deliver_preflight=true must still set ACAM"
    );
    assert_eq!(
        acs.get("access-control-allow-headers").map(String::as_str),
        Some("content-type"),
        "deliver_preflight=true must still set ACAH"
    );
    assert_eq!(
        acs.get("access-control-max-age").map(String::as_str),
        Some("120"),
        "deliver_preflight=true must still set ACMA on preflights"
    );
}

#[tokio::test]
async fn deliver_preflight_true_with_mirror_request_methods() {
    // The delivered-preflight path must honour `AllowMethods::mirror_request` too,
    // not just an explicit method list.
    let svc = builder()
        .allow_origin(Any)
        .allow_methods(AllowMethods::mirror_request())
        .deliver_preflight(true)
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://x.example", "DELETE", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-methods").map(String::as_str),
        Some("DELETE")
    );
}

#[tokio::test]
async fn allow_headers_list_const_emits_comma_joined() {
    // `AllowHeaders::list` constructor path: a fixed list of header names is joined by
    // `,` and emitted as ACAH on preflights. The literal header-name form is used (not
    // the value), preserving order.
    let svc = builder()
        .allow_origin(Any)
        .allow_headers(AllowHeaders::list(vec![
            HeaderName::from_static("x-custom"),
            HeaderName::from_static("content-type"),
        ]))
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    let ach = acs
        .get("access-control-allow-headers")
        .expect("ACAH present");
    let parts: Vec<&str> = ach.split(',').map(str::trim).collect();
    assert_eq!(parts, vec!["x-custom", "content-type"]);
}

#[tokio::test]
async fn allow_headers_from_vec_delegates_to_list() {
    // `AllowHeaders::from(Vec<HeaderName>)` delegates to `list`. An empty `Vec` produces
    // a `None` header value -- no ACAH on the response.
    let svc = builder()
        .allow_origin(Any)
        .allow_headers(Vec::<HeaderName>::new())
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(
        !acs.contains_key("access-control-allow-headers"),
        "empty allow_headers must not emit ACAH"
    );
}

#[tokio::test]
async fn non_options_with_request_method_is_not_a_preflight() {
    // A POST carrying `Access-Control-Request-Method` is not a preflight and must reach
    // the inner service. `OPTIONS` is the only valid preflight method per the Fetch
    // spec.
    let inner = EchoService::ok();
    let svc = builder().allow_origin(Any).build(inner.clone());
    let req = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("origin", "https://x.example")
        .header("access-control-request-method", "POST")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let _ = svc.call(req).await.unwrap();
    assert_eq!(
        inner.call_count(),
        1,
        "POST + ACRM must reach inner service"
    );
}

// ---------------------------------------------------------------------------
// Wildcard / credentials validation (panics at build time)
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Access-Control-Allow-Credentials: true")]
fn credentials_with_wildcard_origin_panics() {
    let _ = builder()
        .allow_credentials(true)
        .allow_origin(Any)
        .build(EchoService::ok());
}

#[test]
#[should_panic(expected = "Access-Control-Allow-Credentials: true")]
fn credentials_with_wildcard_methods_panics() {
    let _ = builder()
        .allow_credentials(true)
        .allow_origin("https://x".parse::<http::HeaderValue>().unwrap())
        .allow_methods(hyper_cors::AllowMethods::any())
        .build(EchoService::ok());
}

#[test]
#[should_panic(expected = "Access-Control-Allow-Credentials: true")]
fn credentials_with_wildcard_headers_panics() {
    let _ = builder()
        .allow_credentials(true)
        .allow_origin("https://x".parse::<http::HeaderValue>().unwrap())
        .allow_headers(AllowHeaders::any())
        .build(EchoService::ok());
}

#[test]
#[should_panic(expected = "Access-Control-Allow-Credentials: true")]
fn credentials_with_wildcard_expose_headers_panics() {
    let _ = builder()
        .allow_credentials(true)
        .allow_origin("https://x".parse::<http::HeaderValue>().unwrap())
        .expose_headers(hyper_cors::ExposeHeaders::any())
        .build(EchoService::ok());
}

// ---------------------------------------------------------------------------
// Credentials in actual responses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credentials_true_with_matching_origin_sends_acac() {
    let svc = builder()
        .allow_credentials(true)
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(EchoService::ok());

    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-credentials")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn credentials_predicate_emits_only_when_allowed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Counter so we can assert the predicate was actually invoked (and exactly once)
    // and not silently short-circuited.
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_credentials(AllowCredentials::predicate(move |origin, _parts| {
            calls2.fetch_add(1, Ordering::SeqCst);
            origin.to_str().unwrap_or("") == "https://app.example.com"
        }))
        .build(EchoService::ok());

    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-credentials")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "predicate must be invoked exactly once per allowed-origin request"
    );
}

#[tokio::test]
async fn credentials_predicate_denies_when_predicate_returns_false() {
    // Predicate always denies, even when the origin is otherwise allowed.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_credentials(AllowCredentials::predicate(|_, _| false))
        .build(EchoService::ok());

    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(
        !acs.contains_key("access-control-allow-credentials"),
        "predicate returning false must suppress ACAC, got {acs:?}"
    );
}

#[tokio::test]
async fn credentials_predicate_not_emitted_without_origin() {
    // A request with no `Origin` is not a CORS request, so ACAC must never appear,
    // even when the predicate would otherwise allow credentials.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_credentials(AllowCredentials::predicate(|_, _| true))
        .build(EchoService::ok());

    let resp = svc.call(get(None)).await.unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-credentials"));
}

// ---------------------------------------------------------------------------
// max_age
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_age_only_emitted_on_preflight() {
    let svc = builder()
        .allow_origin(Any)
        .max_age(Duration::from_secs(42))
        .build(EchoService::ok());

    let actual = svc.call(get(Some("https://x.example"))).await.unwrap();
    assert!(!ac_headers(&actual)
        .iter()
        .any(|(n, _)| n == "access-control-max-age"));

    let pre = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&pre).into_iter().collect();
    assert_eq!(
        acs.get("access-control-max-age").map(String::as_str),
        Some("42")
    );
}

#[tokio::test]
async fn no_max_age_does_not_emit_header() {
    let svc = builder().allow_origin(Any).build(EchoService::ok());
    let pre = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&pre).into_iter().collect();
    assert!(!acs.contains_key("access-control-max-age"));
    let _ = MaxAge::default(); // exercise the type
}

#[tokio::test]
async fn max_age_round_trips_through_builder() {
    // Confirms `builder.max_age(d)` correctly converts `Duration` -> `MaxAge` and emits
    // the seconds value as ACMA. The impl is `pub(crate)`, so we exercise the related
    // observable behaviour via the builder.
    let svc = builder()
        .allow_origin(Any)
        .max_age(Duration::from_secs(3600))
        .build(EchoService::ok());
    let resp = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-max-age").map(String::as_str),
        Some("3600")
    );
}

// ---------------------------------------------------------------------------
// deliver_non_allowed_origin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deliver_non_allowed_origin_false_simple_rejects_with_400() {
    // With `deliver_non_allowed_origin(false)`, a cross-origin request whose Origin is not in the
    // allow-list must be rejected with 400 and never reach the inner service.
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(false)
        .build(inner.clone());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(resp.status(), 400);
    // No CORS response headers on a rejection -- only Vary should be present.
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
    assert!(!acs.contains_key("access-control-allow-credentials"));
    // Inner service body must NOT appear.
    assert_eq!(body_to_string(resp.into_body()).await, "");
    // ...and crucially the inner service must never have been *invoked*: the whole point of
    // this option is to keep disallowed origins away from application side effects.
    assert_eq!(
        inner.call_count(),
        0,
        "inner service must not be invoked for a rejected origin"
    );
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_async_predicate_does_not_invoke_inner() {
    // Same guarantee, but where the origin decision is only available asynchronously -- the
    // tempting optimisation of starting the inner call concurrently would break this.
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(AllowOrigin::async_predicate(|origin, _parts| async move {
            origin.to_str().unwrap_or("") == "https://allowed.example"
        }))
        .deliver_non_allowed_origin(false)
        .build(inner.clone());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(
        inner.call_count(),
        0,
        "inner service must not be invoked for a rejected origin"
    );
}

#[tokio::test]
async fn preflight_short_circuit_does_not_invoke_inner() {
    // `deliver_preflight = false` (the default) must not invoke the inner service at all, even
    // for an allowed origin -- the preflight is answered entirely by the middleware.
    let inner = EchoService::ok();
    let svc = builder().allow_origin(Any).build(inner.clone());
    let resp = svc
        .call(preflight("https://x.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        inner.call_count(),
        0,
        "short-circuited preflight must not reach the inner service"
    );
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_simple_allows_matching_origin() {
    // Sanity check: matching origins still get full CORS treatment.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());
    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://app.example.com")
    );
    assert_eq!(body_to_string(resp.into_body()).await, "ok");
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_no_origin_passes_through() {
    // A request with no Origin header is not a CORS request at all -- it must always be forwarded,
    // regardless of `deliver_non_allowed_origin`.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());
    let resp = svc.call(get(None)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_to_string(resp.into_body()).await, "ok");
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_preflight_short_circuit_returns_400() {
    // `deliver_preflight = false` (default) + disallowed origin + `deliver_non_allowed_origin(false)`
    // -> short-circuit 400 with no CORS response headers.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());
    let resp = svc
        .call(preflight("https://evil.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
    assert!(!acs.contains_key("access-control-allow-methods"));
}

#[tokio::test]
async fn deliver_non_allowed_origin_true_preflight_short_circuit_returns_200_no_cors() {
    // `deliver_preflight = false` (default) + disallowed origin + `deliver_non_allowed_origin(true)`
    // -> short-circuit 200 with no CORS response headers (Jetty's default behaviour).
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(true)
        .build(EchoService::ok());
    let resp = svc
        .call(preflight("https://evil.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
    assert_eq!(body_to_string(resp.into_body()).await, "");
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_preflight_deliver_rejects_with_400() {
    // `deliver_preflight = true` + disallowed origin + `deliver_non_allowed_origin(false)`
    // -> 400, even though we'd otherwise forward to the inner service.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_preflight(true)
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());
    let resp = svc
        .call(preflight("https://evil.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
    assert_eq!(body_to_string(resp.into_body()).await, "");
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_credentials_not_emitted_on_rejection() {
    // Even when credentials are configured, a rejected request must not carry ACAC.
    let svc = builder()
        .allow_credentials(true)
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(resp.status(), 400);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-credentials"));
}

// ---------------------------------------------------------------------------
// WebSocket upgrades
// ---------------------------------------------------------------------------

/// Build a WebSocket handshake request with the given Origin.
fn websocket_upgrade(origin: &str) -> Request<Empty<Bytes>> {
    Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("origin", origin)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .body(Empty::new())
        .unwrap()
}

#[tokio::test]
async fn websocket_upgrade_with_disallowed_origin_is_rejected_by_default() {
    // Browsers don't apply CORS to WebSocket handshakes, so a disallowed origin must be
    // rejected even though `deliver_non_allowed_origin` defaults to true -- otherwise the
    // handshake completes with the user's cookies attached. Matches Jetty.
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(inner.clone());

    let resp = svc
        .call(websocket_upgrade("https://evil.example"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert_eq!(
        inner.call_count(),
        0,
        "disallowed WebSocket upgrade must not reach the inner service"
    );
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn websocket_upgrade_with_allowed_origin_passes_through() {
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(inner.clone());

    let resp = svc
        .call(websocket_upgrade("https://app.example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(inner.call_count(), 1);
}

#[tokio::test]
async fn websocket_upgrade_can_be_opted_into_delivery() {
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin_websocket_upgrade(true)
        .build(inner.clone());

    let resp = svc
        .call(websocket_upgrade("https://evil.example"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(inner.call_count(), 1);
    // Still no CORS headers, since the origin wasn't allowed.
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn websocket_upgrade_without_origin_passes_through() {
    // Non-browser WebSocket clients (and many proxies) send no `Origin` at all. Such a request
    // is not a CORS request, so it must never be rejected -- otherwise installing this
    // middleware would break every native WebSocket client.
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(inner.clone());

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = svc.call(req).await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "originless upgrade must not be rejected"
    );
    assert_eq!(inner.call_count(), 1);
}

#[tokio::test]
async fn websocket_upgrade_with_allowed_origin_still_emits_cors() {
    // Sanity: a *matching*-origin WebSocket upgrade must still get the CORS layer's
    // headers (ACAO, ACAC when configured), just like a normal allowed-origin request.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_credentials(true)
        .build(EchoService::ok());

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("origin", "https://app.example.com")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = svc.call(req).await.unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://app.example.com")
    );
    assert_eq!(
        acs.get("access-control-allow-credentials")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn options_preflight_with_websocket_version_header_short_circuits() {
    // An `OPTIONS` request with both `Access-Control-Request-Method` and
    // `Sec-WebSocket-Version` is *primarily* a preflight. The short-circuit path does
    // not consult the WebSocket-upgrade rejection logic, so it should answer with the
    // preflight headers and 200 -- not be rejected as a disallowed WebSocket upgrade.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(EchoService::ok());
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "POST")
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = svc.call(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert_eq!(
        acs.get("access-control-allow-origin").map(String::as_str),
        Some("https://app.example.com")
    );
    assert_eq!(body_to_string(resp.into_body()).await, "");
}

#[tokio::test]
async fn request_extensions_survive_to_inner_service() {
    use http_body_util::Full;
    // `Cors::call` reconstructs the request from cloned `Parts`. hyper carries the WebSocket
    // upgrade handle as a request *extension* (`hyper::upgrade::OnUpgrade`), and
    // `hyper::upgrade::on()` *removes* it from the request -- so if the middleware were to
    // forward a request whose extensions had been dropped, the handshake would silently never
    // complete. This asserts extensions reach the inner service intact.
    #[derive(Clone, Debug, PartialEq)]
    struct Marker(u32);

    #[derive(Clone)]
    struct ExtensionChecker {
        saw: std::sync::Arc<std::sync::Mutex<Option<Marker>>>,
    }

    impl Service<Request<Empty<Bytes>>> for ExtensionChecker {
        type Response = http::Response<Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn call(&self, req: Request<Empty<Bytes>>) -> Self::Future {
            *self.saw.lock().unwrap() = req.extensions().get::<Marker>().cloned();
            std::future::ready(Ok(http::Response::new(Full::new(Bytes::from_static(
                b"ok",
            )))))
        }
    }

    let saw = std::sync::Arc::new(std::sync::Mutex::new(None));
    let svc = builder()
        .allow_origin(Any)
        .build(ExtensionChecker { saw: saw.clone() });

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("origin", "https://x.example")
        .body(Empty::<Bytes>::new())
        .unwrap();
    req.extensions_mut().insert(Marker(7));

    let _ = svc.call(req).await.unwrap();
    assert_eq!(
        *saw.lock().unwrap(),
        Some(Marker(7)),
        "request extensions (e.g. hyper's OnUpgrade handle) must reach the inner service"
    );
}

#[tokio::test]
async fn non_websocket_request_unaffected_by_websocket_setting() {
    // A plain request with a disallowed origin is still delivered by default.
    let inner = EchoService::ok();
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(inner.clone());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(inner.call_count(), 1);
}

#[tokio::test]
async fn rejection_status_is_configurable() {
    // The default is Jetty's 400, but callers who prefer to signal a refusal can opt into 403.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .deliver_non_allowed_origin(false)
        .rejection_status(http::StatusCode::FORBIDDEN)
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(resp.status(), 403);

    // ...and it applies to short-circuited preflights too.
    let pre = svc
        .call(preflight("https://evil.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(pre.status(), 403);
}

#[tokio::test]
async fn origin_list_rejects_partially_allowed_space_separated_list() {
    // A space-separated `Origin` must not be accepted just because one token is allowed.
    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(EchoService::ok());
    let resp = svc
        .call(get(Some("https://app.example.com https://evil.example")))
        .await
        .unwrap();
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(
        !acs.contains_key("access-control-allow-origin"),
        "smuggled origin must not be allowed, got {acs:?}"
    );
}

#[tokio::test]
async fn deliver_non_allowed_origin_false_async_predicate_rejects() {
    // The rejection must still fire when the origin decision came from an async predicate.
    let svc = builder()
        .allow_origin(AllowOrigin::async_predicate(|origin, _parts| async move {
            origin.to_str().unwrap_or("") == "https://allowed.example"
        }))
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert_eq!(resp.status(), 400);
}

// ---------------------------------------------------------------------------
// Vary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vary_appended_not_overwritten() {
    // The inner service sets a `Vary: Accept-Encoding`; the CORS middleware must append rather
    // than overwrite.
    #[derive(Clone)]
    struct WithVary;
    impl Service<Request<Empty<Bytes>>> for WithVary {
        type Response = http::Response<http_body_util::Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn call(&self, _req: Request<Empty<Bytes>>) -> Self::Future {
            use bytes::Bytes as B;
            use http_body_util::Full;
            std::future::ready(Ok(http::Response::builder()
                .header("vary", "Accept-Encoding")
                .body(Full::new(B::from_static(b"")))
                .unwrap()))
        }
    }

    let svc = builder()
        // Non-wildcard origin so the layer adds `Vary: Origin`.
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .build(WithVary);
    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    let v = vary(&resp).unwrap_or_default().to_ascii_lowercase();
    assert!(
        v.contains("accept-encoding"),
        "vary should include accept-encoding, got {v:?}"
    );
    assert!(
        v.contains("origin"),
        "vary should include origin, got {v:?}"
    );
}

#[tokio::test]
async fn vary_origin_not_duplicated() {
    // An inner service that already varies on Origin must not end up with `Origin` listed
    // twice once the middleware adds its own Vary values.
    #[derive(Clone)]
    struct VaryOrigin;
    impl Service<Request<Empty<Bytes>>> for VaryOrigin {
        type Response = http::Response<http_body_util::Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn call(&self, _req: Request<Empty<Bytes>>) -> Self::Future {
            use http_body_util::Full;
            std::future::ready(Ok(http::Response::builder()
                // Deliberately differing in case, to exercise case-insensitive matching.
                .header("vary", "origin")
                .body(Full::new(Bytes::from_static(b"")))
                .unwrap()))
        }
    }

    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_headers(AllowHeaders::mirror_request())
        .build(VaryOrigin);
    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();

    let joined = vary(&resp).unwrap_or_default().to_ascii_lowercase();
    let occurrences = joined.split(',').filter(|t| t.trim() == "origin").count();
    assert_eq!(
        occurrences, 1,
        "`Origin` should appear exactly once, got {joined:?}"
    );
    // The other CORS-relevant Vary values must still be present.
    assert!(
        joined.contains("access-control-request-headers"),
        "other vary values should survive dedup, got {joined:?}"
    );
}

#[tokio::test]
async fn vary_appends_only_when_inner_does_not_cover_token() {
    // Inner service emits `Vary: ACCEPT-ENCODING, ORIGIN` (case-mangled to exercise
    // case-insensitive matching). The CORS layer adds `Origin` (already listed) and
    // `Access-Control-Request-Method` (new). Expected: a single Vary header value
    // listing all three distinct tokens.
    #[derive(Clone)]
    struct VaryOriginAcceptEncoding;
    impl Service<Request<Empty<Bytes>>> for VaryOriginAcceptEncoding {
        type Response = http::Response<http_body_util::Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn call(&self, _req: Request<Empty<Bytes>>) -> Self::Future {
            use http_body_util::Full;
            std::future::ready(Ok(http::Response::builder()
                .header("vary", "ACCEPT-ENCODING, ORIGIN")
                .body(Full::new(Bytes::from_static(b"")))
                .unwrap()))
        }
    }

    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_methods(AllowMethods::mirror_request())
        .build(VaryOriginAcceptEncoding);
    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();
    let v = vary(&resp).expect("vary present").to_ascii_lowercase();
    let tokens: Vec<&str> = v.split(',').map(str::trim).collect();
    let count_token = |needle: &str| tokens.iter().filter(|t| **t == needle).count();
    assert_eq!(
        count_token("origin"),
        1,
        "Origin must appear once, got {v:?}"
    );
    assert_eq!(
        count_token("accept-encoding"),
        1,
        "Accept-Encoding must appear once, got {v:?}"
    );
    assert_eq!(
        count_token("access-control-request-method"),
        1,
        "Access-Control-Request-Method must appear once, got {v:?}"
    );
}

#[tokio::test]
async fn vary_omitted_when_all_tokens_already_listed_by_inner() {
    // The CORS layer's default Vary (with mirror_request on both methods/headers) is
    // `Origin, Access-Control-Request-Method, Access-Control-Request-Headers`. The inner
    // service emits exactly those three tokens (case-mangled). The middleware must drop
    // its own Vary entry rather than append an empty value.
    #[derive(Clone)]
    struct AllTokensListed;
    impl Service<Request<Empty<Bytes>>> for AllTokensListed {
        type Response = http::Response<http_body_util::Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn call(&self, _req: Request<Empty<Bytes>>) -> Self::Future {
            use http_body_util::Full;
            std::future::ready(Ok(http::Response::builder()
                .header(
                    "vary",
                    "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
                )
                .body(Full::new(Bytes::from_static(b"")))
                .unwrap()))
        }
    }

    let svc = builder()
        .allow_origin(["https://app.example.com".parse().unwrap()])
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
        .build(AllTokensListed);
    let resp = svc
        .call(get(Some("https://app.example.com")))
        .await
        .unwrap();

    let v = vary(&resp).expect("vary present").to_ascii_lowercase();
    let tokens: Vec<&str> = v.split(',').map(str::trim).collect();
    let count_token = |needle: &str| tokens.iter().filter(|t| **t == needle).count();
    assert_eq!(
        count_token("origin"),
        1,
        "Origin should appear exactly once, got {v:?}"
    );
    assert_eq!(
        count_token("access-control-request-method"),
        1,
        "Access-Control-Request-Method should appear exactly once, got {v:?}"
    );
    assert_eq!(
        count_token("access-control-request-headers"),
        1,
        "Access-Control-Request-Headers should appear exactly once, got {v:?}"
    );
    // No empty tokens / extra commas.
    assert!(
        tokens.iter().all(|t| !t.is_empty()),
        "no empty tokens should appear, got {v:?}"
    );
}

#[tokio::test]
async fn vary_from_array_round_trips_through_response() {
    // `Vary::From<[HeaderName; N]>` -- the array-into impl is used when callers write
    // `.vary([HeaderName::from_static("..."), ...])`. Round-trips through the public
    // builder path: the response's Vary must include both names.
    let svc = builder()
        .allow_origin(Any)
        .vary([
            HeaderName::from_static("origin"),
            HeaderName::from_static("accept-encoding"),
        ])
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    let v = vary(&resp).expect("vary present").to_ascii_lowercase();
    assert!(v.contains("origin"));
    assert!(v.contains("accept-encoding"));
}

#[tokio::test]
async fn vary_pinned_to_empty_array_emits_no_vary_header() {
    // An array (rather than a `Vec`) of length 0 pinned via `vary()` must emit no
    // Vary header at all, just like the existing `Vec` case in `vary_omitted_when_pinned_to_empty_list`.
    let svc = builder()
        .allow_origin(Any)
        .vary(Vec::<HeaderName>::new())
        .build(EchoService::ok());
    let resp = svc.call(get(Some("https://x.example"))).await.unwrap();
    assert!(
        vary(&resp).is_none(),
        "pinned empty Vary must not emit a header"
    );
}

// ---------------------------------------------------------------------------
// Async predicate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn async_predicate_allows_matching_origin() {
    let svc = builder()
        .allow_origin(AllowOrigin::async_predicate(|origin, _parts| async move {
            origin
                .to_str()
                .unwrap_or("")
                .starts_with("https://allowed.")
        }))
        .build(EchoService::ok());

    let ok = svc.call(get(Some("https://allowed.x"))).await.unwrap();
    assert!(ac_headers(&ok)
        .iter()
        .any(|(n, v)| n == "access-control-allow-origin" && v == "https://allowed.x"));

    let denied = svc.call(get(Some("https://evil.example"))).await.unwrap();
    assert!(!ac_headers(&denied)
        .iter()
        .any(|(n, _)| n == "access-control-allow-origin"));
}

#[tokio::test]
async fn async_predicate_preflight_waits_for_future() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let counter = Arc::new(AtomicUsize::new(0));
    let counter2 = counter.clone();
    let svc = builder()
        .allow_origin(AllowOrigin::async_predicate(move |origin, _parts| {
            let counter = counter2.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                origin
                    .to_str()
                    .unwrap_or("")
                    .starts_with("https://allowed.")
            }
        }))
        .build(EchoService::ok());

    let _ = svc
        .call(preflight("https://allowed.x", "POST", None))
        .await
        .unwrap();
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "predicate must have been awaited"
    );
}

#[tokio::test]
async fn async_predicate_pending_future_does_not_invoke_inner_early() {
    // `async_predicate_preflight_waits_for_future` (and the matching-origin test) use a
    // future that's `Ready` on first poll (it's a literal `bool` expression). They never
    // exercise the `Pending` branch in `CorsFuture::Forward::poll` -- the path where the
    // middleware sees a genuinely pending future and must not invoke the inner service
    // until the predicate resolves. This test fills that gap: the async predicate awaits
    // a oneshot channel, so the future stays `Pending` until we send through it.
    //
    // The contract is verified via two assertions:
    //   1. While the predicate is pending, the CORS future cannot complete (a short
    //      `tokio::time::timeout` fires first).
    //   2. Once the predicate resolves, the future completes and the inner service runs
    //      (using a *second* `svc` instance, because the first future was consumed by
    //      the timeout and its oneshot receiver was dropped).
    let (_tx1, rx1) = tokio::sync::oneshot::channel::<bool>();
    let rx1 = Arc::new(tokio::sync::Mutex::new(Some(rx1)));
    let (tx2, rx2) = tokio::sync::oneshot::channel::<bool>();
    let rx2 = Arc::new(tokio::sync::Mutex::new(Some(rx2)));

    let svc = builder()
        .allow_origin(AllowOrigin::async_predicate(move |_origin, _parts| {
            let rx = rx1.clone();
            async move {
                let mut guard = rx.lock().await;
                let r = guard.take().expect("polled twice");
                r.await.unwrap_or(false)
            }
        }))
        .build(EchoService::ok());

    let svc2 = builder()
        .allow_origin(AllowOrigin::async_predicate(move |_origin, _parts| {
            let rx = rx2.clone();
            async move {
                let mut guard = rx.lock().await;
                let r = guard.take().expect("polled twice");
                r.await.unwrap_or(false)
            }
        }))
        .build(EchoService::ok());

    // 1) Predicate pending -> future stays pending.
    let resp_fut = svc.call(get(Some("https://anywhere.example")));
    let timed_out = tokio::time::timeout(std::time::Duration::from_millis(50), resp_fut).await;
    assert!(
        timed_out.is_err(),
        "future must remain pending while the async predicate is pending"
    );
    // The first future was dropped; the oneshot receiver inside it was also dropped,
    // so `_tx1` would now error. Don't use it further.

    // 2) Resolve predicate -> future completes.
    tx2.send(true).unwrap();
    let resp = svc2
        .call(get(Some("https://anywhere.example")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn preflight_async_predicate_disallowed_with_reject_returns_400() {
    // Complements `deliver_non_allowed_origin_false_async_predicate_does_not_invoke_inner`
    // (which exercises the Forward branch) by covering the Preflight branch: a
    // short-circuited preflight with an async predicate that returns false must reject
    // with the configured status (400 by default).
    let svc = builder()
        .allow_origin(AllowOrigin::async_predicate(|origin, _parts| async move {
            origin.to_str().unwrap_or("") == "https://allowed.example"
        }))
        .deliver_non_allowed_origin(false)
        .build(EchoService::ok());

    let resp = svc
        .call(preflight("https://evil.example", "POST", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let acs: std::collections::HashMap<_, _> = ac_headers(&resp).into_iter().collect();
    assert!(!acs.contains_key("access-control-allow-origin"));
}

// ---------------------------------------------------------------------------
// Sync predicate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sync_predicate_with_suffix_pattern() {
    let svc = builder()
        .allow_origin(AllowOrigin::predicate(|origin, _parts| {
            origin.to_str().unwrap_or("").ends_with(".app.example.com")
        }))
        .build(EchoService::ok());

    let ok = svc
        .call(get(Some("https://x.app.example.com")))
        .await
        .unwrap();
    assert_eq!(
        ac_headers(&ok),
        vec![(
            "access-control-allow-origin".to_string(),
            "https://x.app.example.com".to_string()
        )]
    );

    let denied = svc.call(get(Some("https://x.evil.example"))).await.unwrap();
    assert_eq!(ac_headers(&denied), vec![]);
}

// ---------------------------------------------------------------------------
// Pin the inner service and ensure `Service` impl is usable through `&self`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn service_call_works_through_shared_reference() {
    let svc = builder().allow_origin(Any).build(EchoService::ok());
    let svc_ref = &svc;
    // hyper 1.x Service::call takes &self, so this must compile.
    let r1 = svc_ref.call(get(Some("https://x.example"))).await.unwrap();
    let r2 = svc_ref.call(get(Some("https://x.example"))).await.unwrap();
    assert_eq!(r1.status(), 200);
    assert_eq!(r2.status(), 200);
}
