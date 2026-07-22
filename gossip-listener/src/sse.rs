use axum::{
    extract::Query,
    response::{sse::{Event, KeepAlive, Sse}, IntoResponse},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

#[derive(Debug, Deserialize, Default)]
pub struct EventFilter {
    pub medium: Option<String>,
    pub reason: Option<String>,
    pub sender: Option<String>,
}

/// Start the SSE server. Creates a broadcast channel, spawns the axum server
/// via tokio::spawn, and returns the Sender half.
pub fn start_sse_server(
    addr: SocketAddr,
    buffer_size: usize,
) -> broadcast::Sender<String> {
    let (tx, _rx) = broadcast::channel::<String>(buffer_size);
    let tx_for_router = tx.clone();

    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(health_handler))
            .route("/events", get(move |query| sse_handler(query, tx_for_router.clone())));

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "\x1b[1;31m[FATAL] Cannot bind SSE server on {}: {}\x1b[0m",
                    addr, e
                );
                return;
            }
        };
        println!("  SSE server listening on {}", addr);
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("\x1b[1;31m[FATAL] SSE server error: {}\x1b[0m", e);
        }
    });

    tx
}

async fn health_handler() -> impl IntoResponse {
    format!("gossip-listener SSE v{}", env!("CARGO_PKG_VERSION"))
}

async fn sse_handler(
    Query(filter): Query<EventFilter>,
    tx: broadcast::Sender<String>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        match result {
            Ok(json_str) => {
                if matches_filter(&json_str, &filter) {
                    Some(Ok(Event::default().event("podping").data(json_str)))
                } else {
                    None // filtered out
                }
            }
            Err(_) => None, // Lagged or closed — skip silently
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn matches_filter(json_str: &str, filter: &EventFilter) -> bool {
    // No filters = pass everything
    if filter.medium.is_none() && filter.reason.is_none() && filter.sender.is_none() {
        return true;
    }
    // Minimal deserialization to check filter fields
    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return true, // can't parse, let it through
    };
    if let Some(ref medium) = filter.medium {
        if parsed.get("medium").and_then(|v| v.as_str()) != Some(medium.as_str()) {
            return false;
        }
    }
    if let Some(ref reason) = filter.reason {
        if parsed.get("reason").and_then(|v| v.as_str()) != Some(reason.as_str()) {
            return false;
        }
    }
    if let Some(ref sender_prefix) = filter.sender {
        match parsed.get("sender").and_then(|v| v.as_str()) {
            Some(sender) if sender.starts_with(sender_prefix.as_str()) => {}
            _ => return false,
        }
    }
    true
}
