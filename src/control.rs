use std::sync::Arc;

use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Build, Rocket, State};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{binlog, receipt, util};
use crate::state::DaemonState;

type SharedState = Arc<Mutex<DaemonState>>;
type SharedLogWriter = Option<Arc<binlog::LogWriter>>;

// ── Request / Response types ────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActionStartRequest {
    command: String,
}

#[derive(Serialize)]
pub struct ActionStartResponse {
    ok: bool,
    action_id: u64,
}

#[derive(Serialize)]
pub struct ContainerInfo {
    container_id: String,
    processes: usize,
    influence_edges: usize,
    active_action: Option<u64>,
    completed_actions: usize,
}

#[derive(Serialize)]
pub struct StatusResponse {
    ok: bool,
    containers: Vec<ContainerInfo>,
    pid_cache_size: usize,
}

// ── Routes ──────────────────────────────────────────────────────────

#[get("/status")]
async fn status(state: &State<SharedState>) -> Json<StatusResponse> {
    let state = state.lock().await;
    let containers = state
        .containers
        .iter()
        .map(|(id, cs)| ContainerInfo {
            container_id: id.clone(),
            processes: cs.process_table.processes.len(),
            influence_edges: cs.taint_graph.edges.len(),
            active_action: cs.current_action.as_ref().map(|a| a.action_id),
            completed_actions: cs.completed_actions.len(),
        })
        .collect();

    Json(StatusResponse {
        ok: true,
        containers,
        pid_cache_size: state.pid_cache.len(),
    })
}

#[get("/containers")]
async fn list_containers(state: &State<SharedState>) -> Json<Vec<ContainerInfo>> {
    let state = state.lock().await;
    let containers = state
        .containers
        .iter()
        .map(|(id, cs)| ContainerInfo {
            container_id: id.clone(),
            processes: cs.process_table.processes.len(),
            influence_edges: cs.taint_graph.edges.len(),
            active_action: cs.current_action.as_ref().map(|a| a.action_id),
            completed_actions: cs.completed_actions.len(),
        })
        .collect();

    Json(containers)
}

#[delete("/containers/<id>")]
async fn delete_container(id: &str, state: &State<SharedState>) -> Json<serde_json::Value> {
    let mut state = state.lock().await;
    state.pid_cache.retain(|_, v| v.as_deref() != Some(id));
    let removed = state.containers.remove(id).is_some();
    tracing::info!(container = %id, removed, "delete container");
    Json(serde_json::json!({ "ok": true, "removed": removed }))
}

/// Start a new action for a container.
#[post("/containers/<id>/actions", format = "json", data = "<req>")]
async fn action_start(
    id: &str,
    req: Json<ActionStartRequest>,
    state: &State<SharedState>,
    log_writer: &State<SharedLogWriter>,
) -> Json<ActionStartResponse> {
    let mut state = state.lock().await;
    let container = state.ensure_container(id);
    let now = util::monotonic_ns();

    let action_id = container.completed_actions.len() as u64 + 1;
    let action_log = crate::events::ActionLog::new(action_id, req.command.clone(), now);
    container.current_action = Some(action_log);
    container.current_action_id = action_id;

    tracing::info!(
        action_id,
        container = %id,
        command = %req.command,
        "action_start",
    );

    if let Some(writer) = log_writer.inner() {
        writer.send(binlog::LogEntry::ActionStart {
            action_id,
            command: req.command.clone(),
            timestamp_ns: now,
        });
    }

    Json(ActionStartResponse {
        ok: true,
        action_id,
    })
}

/// End the current action and return its receipt.
#[post("/containers/<id>/actions/<action_id>/end")]
async fn action_end(
    id: &str,
    action_id: u64,
    state: &State<SharedState>,
    log_writer: &State<SharedLogWriter>,
) -> Json<serde_json::Value> {
    // Yield briefly to let any in-flight audit events reach the processor.
    tokio::task::yield_now().await;

    let now = util::monotonic_ns();
    let receipt_text;

    {
        let mut state = state.lock().await;

        let container = match state.containers.get_mut(id) {
            Some(c) => c,
            None => {
                return Json(serde_json::json!({
                    "ok": false,
                    "error": format!("unknown container: {}", id),
                }));
            }
        };

        // Build file flow edges and propagate taint
        container.build_file_flow_edges();
        container
            .taint_graph
            .propagate_taint(&mut container.process_table);

        receipt_text = receipt::generate_receipt(container, action_id);

        if let Some(mut action) = container.current_action.take() {
            action.end_time = Some(now);
            container.completed_actions.push(action);
        }
        container.last_receipt_time = now;
    } // lock released here, before logging and binlog send

    tracing::info!(
        action_id,
        container = %id,
        receipt_len = receipt_text.len(),
        "action_end",
    );

    if let Some(writer) = log_writer.inner() {
        writer.send(binlog::LogEntry::ActionEnd {
            action_id,
            timestamp_ns: now,
        });
    }

    Json(serde_json::json!({
        "ok": true,
        "action_id": action_id,
        "receipt": receipt_text,
    }))
}

/// List completed actions for a container.
#[get("/containers/<id>/actions")]
async fn list_actions(id: &str, state: &State<SharedState>) -> Json<serde_json::Value> {
    let state = state.lock().await;
    let container = match state.containers.get(id) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("unknown container: {}", id),
            }));
        }
    };

    let actions: Vec<serde_json::Value> = container
        .completed_actions
        .iter()
        .map(|a| {
            serde_json::json!({
                "action_id": a.action_id,
                "command": a.command,
                "total_events": a.total_events,
            })
        })
        .collect();

    let current = container.current_action.as_ref().map(|a| {
        serde_json::json!({
            "action_id": a.action_id,
            "command": a.command,
            "total_events": a.total_events,
        })
    });

    Json(serde_json::json!({
        "ok": true,
        "completed": actions,
        "current": current,
    }))
}

/// Get receipt for a specific completed action.
#[get("/containers/<id>/actions/<action_id>/receipt")]
async fn action_receipt(
    id: &str,
    action_id: u64,
    state: &State<SharedState>,
) -> Json<serde_json::Value> {
    let state = state.lock().await;
    let container = match state.containers.get(id) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("unknown container: {}", id),
            }));
        }
    };

    let action = container
        .completed_actions
        .iter()
        .find(|a| a.action_id == action_id);

    match action {
        Some(action) => {
            let receipt_text = receipt::generate_receipt_from_action(container, action);
            Json(serde_json::json!({
                "ok": true,
                "action_id": action_id,
                "receipt": receipt_text,
            }))
        }
        None => Json(serde_json::json!({
            "ok": false,
            "error": format!("action {} not found", action_id),
        })),
    }
}

/// Snapshot receipt: returns a receipt of everything accumulated so far.
#[get("/containers/<id>/receipt")]
async fn snapshot_receipt(id: &str, state: &State<SharedState>) -> Json<serde_json::Value> {
    let mut state = state.lock().await;

    let container = match state.containers.get_mut(id) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("unknown container: {}", id),
            }));
        }
    };

    // Propagate taint for snapshot (may not have had an action_end yet)
    container.build_file_flow_edges();
    container
        .taint_graph
        .propagate_taint(&mut container.process_table);

    let action_id = container
        .current_action
        .as_ref()
        .map(|a| a.action_id)
        .unwrap_or(0);
    let receipt_text = receipt::generate_receipt(container, action_id);

    Json(serde_json::json!({
        "ok": true,
        "receipt": receipt_text,
    }))
}

/// DOT source for the influence graph (rendered client-side via viz.js).
#[get("/containers/<id>/graph")]
async fn influence_graph(id: &str, state: &State<SharedState>) -> (rocket::http::ContentType, String) {
    let state = state.lock().await;

    let container = match state.containers.get(id) {
        Some(c) => c,
        None => {
            return (
                rocket::http::ContentType::Plain,
                format!("unknown container: {}", id),
            );
        }
    };

    let dot = crate::graph::render_dot(container);
    (rocket::http::ContentType::new("text", "vnd.graphviz"), dot)
}

/// Serve viz.js for client-side graphviz rendering.
#[get("/viz.js")]
async fn viz_js() -> (rocket::http::ContentType, &'static str) {
    (rocket::http::ContentType::JavaScript, include_str!("viz.js"))
}

/// Raw DOT source for the influence graph.
#[get("/containers/<id>/graph.dot")]
async fn influence_graph_dot(id: &str, state: &State<SharedState>) -> (rocket::http::ContentType, String) {
    let state = state.lock().await;

    let container = match state.containers.get(id) {
        Some(c) => c,
        None => {
            return (
                rocket::http::ContentType::Plain,
                format!("unknown container: {}", id),
            );
        }
    };

    let dot = crate::graph::render_dot(container);
    (rocket::http::ContentType::new("text", "vnd.graphviz"), dot)
}

/// Serve the dashboard UI.
#[get("/")]
async fn index() -> (rocket::http::ContentType, &'static str) {
    (rocket::http::ContentType::HTML, include_str!("index.html"))
}

/// Build the Rocket instance with shared state.
pub fn rocket(state: SharedState, log_writer: SharedLogWriter) -> Rocket<Build> {
    rocket::build()
        .manage(state)
        .manage(log_writer)
        .mount(
            "/",
            routes![
                status,
                list_containers,
                delete_container,
                action_start,
                action_end,
                list_actions,
                action_receipt,
                snapshot_receipt,
                influence_graph,
                influence_graph_dot,
                viz_js,
                index,
            ],
        )
}
