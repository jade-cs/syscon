use std::sync::Arc;

use rocket::serde::json::Json;
use rocket::{delete, get, post, routes, Build, Rocket, State};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{receipt, util};
use crate::state::DaemonState;

type SharedState = Arc<Mutex<DaemonState>>;

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
        container.build_ipc_flow_edges();
        container
            .taint_graph
            .propagate_taint(&mut container.process_table);

        if let Some(mut action) = container.current_action.take() {
            action.end_time = Some(now);
            action.wall_end_ms = Some(crate::events::wall_clock_ms());
            container.completed_actions.push(action);
        }
        container.last_receipt_time = now;

        // Generate receipt (immutable borrows only)
        let container = state.containers.get(id).unwrap();
        receipt_text = receipt::generate_receipt(container, action_id, &state.ip_to_container);
    }

    tracing::info!(
        action_id,
        container = %id,
        receipt_len = receipt_text.len(),
        "action_end",
    );

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
                "total_events": a.total_events(),
            })
        })
        .collect();

    let current = container.current_action.as_ref().map(|a| {
        serde_json::json!({
            "action_id": a.action_id,
            "command": a.command,
            "total_events": a.total_events(),
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
            let receipt_text = receipt::generate_receipt_from_action(container, action, &state.ip_to_container);
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

    // Re-borrow immutably for receipt generation (needs ip_to_container too)
    let container = state.containers.get(id).unwrap();
    let receipt_text = receipt::generate_receipt(container, action_id, &state.ip_to_container);

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

// ── Experiment endpoints ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateExperimentRequest {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
pub struct AddContainerRequest {
    container_id: String,
    /// Optional IP addresses for this container. If provided, skips
    /// the /proc/{pid}/net/fib_trie lookup (useful when the harness
    /// already knows the container's IPs from Docker inspect).
    #[serde(default)]
    ips: Vec<String>,
}

/// Create a new experiment.
#[post("/experiments", format = "json", data = "<req>")]
async fn create_experiment(
    req: Json<CreateExperimentRequest>,
    state: &State<SharedState>,
) -> Json<serde_json::Value> {
    let mut state = state.lock().await;
    let id = state.create_experiment(req.name.clone());
    tracing::info!(experiment = %id, name = %req.name, "experiment created");
    Json(serde_json::json!({ "ok": true, "experiment_id": id }))
}

/// Add a container to an experiment.
#[post("/experiments/<id>/containers", format = "json", data = "<req>")]
async fn add_experiment_container(
    id: &str,
    req: Json<AddContainerRequest>,
    state: &State<SharedState>,
) -> Json<serde_json::Value> {
    let mut state = state.lock().await;
    if state.add_container_to_experiment(id, &req.container_id) {
        // Register provided IPs in the ip_to_container map
        for ip_str in &req.ips {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                state.ip_to_container.insert(ip, req.container_id.clone());
            }
        }
        tracing::info!(
            experiment = %id,
            container = %req.container_id,
            ips = ?req.ips,
            "container added to experiment"
        );
        Json(serde_json::json!({ "ok": true }))
    } else {
        Json(serde_json::json!({ "ok": false, "error": "experiment not found" }))
    }
}

/// List all experiments.
#[get("/experiments")]
async fn list_experiments(state: &State<SharedState>) -> Json<serde_json::Value> {
    let state = state.lock().await;
    let experiments: Vec<serde_json::Value> = state.experiments.values()
        .map(|e| serde_json::json!({
            "id": e.id,
            "name": e.name,
            "containers": e.container_ids,
        }))
        .collect();
    Json(serde_json::json!({ "ok": true, "experiments": experiments }))
}

/// Aggregated receipt for an experiment (all containers, cross-container flows).
#[get("/experiments/<id>/receipt")]
async fn experiment_receipt(
    id: &str,
    state: &State<SharedState>,
) -> Json<serde_json::Value> {
    let state = state.lock().await;
    let experiment = match state.experiments.get(id) {
        Some(e) => e,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "experiment not found",
            }));
        }
    };
    let receipt_text = receipt::generate_experiment_receipt(&state, experiment);
    Json(serde_json::json!({
        "ok": true,
        "experiment_id": id,
        "receipt": receipt_text,
    }))
}

/// Receipt for a specific action across all containers in an experiment.
#[get("/experiments/<id>/actions/<action_id>/receipt")]
async fn experiment_action_receipt(
    id: &str,
    action_id: u64,
    state: &State<SharedState>,
) -> Json<serde_json::Value> {
    let state = state.lock().await;
    let experiment = match state.experiments.get(id) {
        Some(e) => e,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "experiment not found",
            }));
        }
    };
    let receipt_text = receipt::generate_experiment_action_receipt(&state, experiment, action_id);
    Json(serde_json::json!({
        "ok": true,
        "experiment_id": id,
        "action_id": action_id,
        "receipt": receipt_text,
    }))
}

/// DOT graph for an experiment (containers as cluster boxes, cross-container edges).
#[get("/experiments/<id>/graph")]
async fn experiment_graph(
    id: &str,
    state: &State<SharedState>,
) -> (rocket::http::ContentType, String) {
    let state = state.lock().await;
    let experiment = match state.experiments.get(id) {
        Some(e) => e,
        None => {
            return (rocket::http::ContentType::Plain, format!("experiment not found: {}", id));
        }
    };
    let dot = crate::graph::render_experiment_dot(&state, experiment);
    (rocket::http::ContentType::new("text", "vnd.graphviz"), dot)
}

/// Build the Rocket instance with shared state.
pub fn rocket(state: SharedState) -> Rocket<Build> {
    rocket::build()
        .manage(state)
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
                create_experiment,
                add_experiment_container,
                list_experiments,
                experiment_receipt,
                experiment_action_receipt,
                experiment_graph,
            ],
        )
}
