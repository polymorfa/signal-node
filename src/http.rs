// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! The local application API. Every route except `/healthz` requires
//! `Authorization: Bearer <http.secret>`. See README for the reference.

use crate::message::SendRequest;
use crate::node::Node;
use crate::send::{self, SendError};
use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}

pub fn router(node: Arc<Node>) -> Router {
    let api = Router::new()
        .route("/v1/sessions", get(list_sessions))
        .route("/v1/sessions/{id}/messages", post(send_message))
        .route("/v1/events", get(events))
        .route("/v1/events/{id}/ack", post(ack))
        .layer(middleware::from_fn_with_state(node.clone(), authenticate));
    Router::new()
        .route("/healthz", get(health))
        .merge(api)
        .with_state(node)
}

async fn authenticate(State(node): State<Arc<Node>>, request: Request, next: Next) -> Response {
    if request.headers().contains_key(header::ORIGIN) {
        return error(
            StatusCode::FORBIDDEN,
            "origin_forbidden",
            "the application API accepts server clients only",
        );
    }
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let expected = node.cfg.http_secret.expose().as_bytes();
    if bool::from(presented.as_bytes().ct_eq(expected)) {
        next.run(request).await
    } else {
        error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or wrong bearer secret",
        )
    }
}

async fn health(State(node): State<Arc<Node>>) -> Response {
    let _ = node;
    Json(json!({ "status": "ok" })).into_response()
}

#[derive(Serialize)]
struct SessionInfo {
    id: String,
    lease_generation: u64,
    claimed: bool,
    has_device_keys: bool,
    #[serde(flatten)]
    view: crate::node::SessionView,
}

async fn list_sessions(State(node): State<Arc<Node>>) -> Response {
    let sessions: Vec<SessionInfo> = node
        .sessions()
        .into_iter()
        .map(|s| SessionInfo {
            id: s.id.clone(),
            lease_generation: s.generation,
            claimed: s.is_claimed(),
            has_device_keys: s.ops().is_some(),
            view: s.view(),
        })
        .collect();
    Json(json!({ "node_id": node.cfg.node_id, "sessions": sessions })).into_response()
}

async fn send_message(
    State(node): State<Arc<Node>>,
    Path(id): Path<String>,
    body: Result<Json<SendRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(b) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request", e.body_text()),
    };
    if !node.is_configured(&id) {
        return error(
            StatusCode::NOT_FOUND,
            "unknown_session",
            "session is not configured",
        );
    }
    let Some(session) = node.session(&id) else {
        return error(
            StatusCode::CONFLICT,
            "not_lease_holder",
            "another node serves this session; send through that node",
        );
    };
    match send::send(&node, &session, request).await {
        Ok(outcome) => (StatusCode::OK, Json(outcome)).into_response(),
        Err(e) => {
            let (status, code) = match &e {
                SendError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
                SendError::NotLeaseHolder => (StatusCode::CONFLICT, "not_lease_holder"),
                SendError::NotPaired => (StatusCode::CONFLICT, "session_not_paired"),
                SendError::Disconnected => (StatusCode::SERVICE_UNAVAILABLE, "disconnected"),
                SendError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
                SendError::Refused(err) => match err.code_enum() {
                    crate::proto::Code::SessionUnavailable => {
                        (StatusCode::CONFLICT, "session_unavailable")
                    }
                    crate::proto::Code::Refused => (StatusCode::FORBIDDEN, "refused"),
                    crate::proto::Code::Unavailable => {
                        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
                    }
                    _ => (StatusCode::BAD_GATEWAY, "send_failed"),
                },
                SendError::Build => (StatusCode::BAD_GATEWAY, "send_failed"),
            };
            error(status, code, e.to_string())
        }
    }
}

#[derive(Deserialize)]
struct EventFilter {
    session_id: Option<String>,
}

// An error Response is the standard axum handler shape; it is built only on refusal.
#[allow(clippy::result_large_err)]
async fn events(
    State(node): State<Arc<Node>>,
    Query(filter): Query<EventFilter>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, Response> {
    let Some(rx) = node.delivery.subscribe() else {
        return Err(error(
            StatusCode::NOT_FOUND,
            "stream_disabled",
            "the event stream is turned off (delivery.sse = false)",
        ));
    };
    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        // A lagging client misses events; they are not acknowledged, so the
        // receive fails and the message is redelivered later.
        let event = item.ok()?;
        if filter
            .session_id
            .as_ref()
            .is_some_and(|s| *s != event.session_id)
        {
            return None;
        }
        let data = serde_json::to_string(&*event).ok()?;
        Some(Ok(SseEvent::default()
            .id(event.id.clone())
            .event(event.kind)
            .data(data)))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn ack(State(node): State<Arc<Node>>, Path(id): Path<String>) -> Response {
    if node.delivery.acknowledge(&id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error(
            StatusCode::NOT_FOUND,
            "unknown_event",
            "no delivery is waiting for that event; it was acknowledged already or timed out",
        )
    }
}
