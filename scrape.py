#!/usr/bin/env python3
"""Scrape a running syscon instance into a static-hostable folder.

Usage:
    python3 scrape.py [--url http://localhost:8000] [--out ./dump]

Produces:
    out/
        index.html          (patched to use local JSON instead of API calls)
        viz.js              (fetched from the server)
        containers.json     (container list)
        containers/
            {id}/
                actions.json
                receipt.json        (snapshot receipt)
                graph.dot
                actions/
                    {action_id}/
                        receipt.json
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

MAX_PROCS = 1500


def fetch(base, path):
    url = base.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        print(f"  WARN: {path} -> HTTP {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  WARN: {path} -> {e}", file=sys.stderr)
        return None


def fetch_json(base, path):
    data = fetch(base, path)
    if data is None:
        return None
    return json.loads(data)


def write(out_dir, rel_path, data):
    full = os.path.join(out_dir, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    if isinstance(data, bytes):
        with open(full, "wb") as f:
            f.write(data)
    else:
        with open(full, "w") as f:
            f.write(data)


def make_static_index(original_html, containers_data):
    """Patch index.html to load from local JSON files instead of API calls."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>syscon - Container Auditor (static)</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Menlo', 'Monaco', 'Consolas', monospace; background: #1a1a2e; color: #e0e0e0; display: flex; height: 100vh; }
  #sidebar { width: 280px; background: #16213e; border-right: 1px solid #0f3460; overflow-y: auto; flex-shrink: 0; }
  #sidebar h2 { padding: 16px; font-size: 14px; color: #e94560; border-bottom: 1px solid #0f3460; }
  .container-item { padding: 10px 16px; border-bottom: 1px solid #0f3460; cursor: pointer; font-size: 12px; }
  .container-item:hover { background: #0f3460; }
  .container-item.active { background: #0f3460; border-left: 3px solid #e94560; }
  .container-item .cid { color: #e94560; font-weight: bold; }
  .container-item .stats { color: #888; font-size: 11px; margin-top: 2px; }
  #main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  #tabs { display: flex; background: #16213e; border-bottom: 1px solid #0f3460; }
  .tab { padding: 10px 16px; cursor: pointer; font-size: 12px; color: #888; border-bottom: 2px solid transparent; white-space: nowrap; }
  .tab:hover { color: #e0e0e0; }
  .tab.active { color: #e94560; border-bottom-color: #e94560; }
  #content-wrapper { flex: 1; display: flex; overflow: hidden; }
  #action-sidebar { width: 220px; background: #16213e; border-right: 1px solid #0f3460; overflow-y: auto; flex-shrink: 0; }
  #action-sidebar h3 { padding: 10px 12px; font-size: 11px; color: #888; border-bottom: 1px solid #0f3460; text-transform: uppercase; letter-spacing: 0.5px; }
  .action-item { padding: 8px 12px; border-bottom: 1px solid #0f3460; cursor: pointer; font-size: 11px; color: #aaa; }
  .action-item:hover { background: #0f3460; color: #e0e0e0; }
  .action-item.active { background: #0f3460; color: #e94560; border-left: 3px solid #e94560; }
  .action-item .action-id { color: #e94560; font-weight: bold; }
  .action-item .action-cmd { color: #aaa; margin-top: 2px; word-break: break-all; }
  #content { flex: 1; overflow: hidden; position: relative; }
  #receipt-view { white-space: pre-wrap; padding: 16px; font-size: 12px; line-height: 1.6; overflow: auto; height: 100%; }
  #graph-view { width: 100%; height: 100%; background: #f8f8f8; overflow: hidden; cursor: grab; position: relative; }
  #graph-view.dragging { cursor: grabbing; }
  #graph-inner { transform-origin: 0 0; position: absolute; }
  #graph-controls { position: absolute; top: 10px; right: 10px; display: flex; flex-direction: column; gap: 4px; z-index: 10; }
  #graph-controls button { width: 32px; height: 32px; background: #16213e; color: #e0e0e0; border: 1px solid #0f3460; border-radius: 4px; cursor: pointer; font-size: 16px; font-family: inherit; display: flex; align-items: center; justify-content: center; }
  #graph-controls button:hover { background: #0f3460; color: #e94560; }
  #zoom-level { color: #666; font-size: 10px; text-align: center; background: #16213e; padding: 2px; border-radius: 3px; border: 1px solid #0f3460; }
  .hidden { display: none !important; }
  #no-selection { display: flex; align-items: center; justify-content: center; height: 100%; color: #555; font-size: 14px; }
  #status-bar { background: #16213e; border-top: 1px solid #0f3460; padding: 6px 16px; font-size: 11px; color: #666; }
</style>
</head>
<body>

<div id="sidebar">
  <h2>CONTAINERS</h2>
  <div id="container-list"></div>
</div>

<div id="main">
  <div id="tabs">
    <div class="tab active" data-tab="receipt" onclick="switchTab('receipt')">Snapshot</div>
    <div class="tab" data-tab="graph" onclick="switchTab('graph')">Graph</div>
  </div>
  <div id="content-wrapper">
    <div id="action-sidebar" class="hidden">
      <h3>Actions</h3>
      <div id="action-list"></div>
    </div>
    <div id="content">
      <div id="no-selection">Select a container from the sidebar</div>
      <div id="receipt-view" class="hidden"></div>
      <div id="graph-view" class="hidden">
        <div id="graph-inner"></div>
        <div id="graph-controls">
          <button onclick="graphZoom(1.3)" title="Zoom in">+</button>
          <button onclick="graphZoom(0.7)" title="Zoom out">-</button>
          <button onclick="graphFit()" title="Fit to view">F</button>
          <button onclick="graphReset()" title="Reset zoom">1</button>
          <div id="zoom-level">100%</div>
        </div>
      </div>
    </div>
  </div>
  <div id="status-bar">
    <span id="status-text">Static dump</span>
  </div>
</div>

<script>
let selectedContainer = null;
let currentTab = 'receipt';
let selectedAction = null;

let gZoom = 1, gPanX = 0, gPanY = 0;
let gDragging = false, gDragStartX = 0, gDragStartY = 0, gPanStartX = 0, gPanStartY = 0;

function graphUpdateTransform() {
  const inner = document.getElementById('graph-inner');
  if (inner) inner.style.transform = `translate(${gPanX}px, ${gPanY}px) scale(${gZoom})`;
  const zl = document.getElementById('zoom-level');
  if (zl) zl.textContent = Math.round(gZoom * 100) + '%';
}
function graphZoom(factor) {
  const view = document.getElementById('graph-view');
  const cx = view.clientWidth / 2, cy = view.clientHeight / 2;
  gPanX = cx - factor * (cx - gPanX);
  gPanY = cy - factor * (cy - gPanY);
  gZoom = Math.max(0.05, Math.min(10, gZoom * factor));
  graphUpdateTransform();
}
function graphFit() {
  const view = document.getElementById('graph-view');
  const svg = document.getElementById('graph-inner')?.querySelector('svg');
  if (!svg) return;
  const svgW = parseFloat(svg.getAttribute('width') || svg.getBBox().width);
  const svgH = parseFloat(svg.getAttribute('height') || svg.getBBox().height);
  if (!svgW || !svgH) return;
  gZoom = Math.min(view.clientWidth / svgW, view.clientHeight / svgH) * 0.95;
  gPanX = (view.clientWidth - svgW * gZoom) / 2;
  gPanY = (view.clientHeight - svgH * gZoom) / 2;
  graphUpdateTransform();
}
function graphReset() { gZoom = 1; gPanX = 0; gPanY = 0; graphUpdateTransform(); }

document.addEventListener('DOMContentLoaded', () => {
  const view = document.getElementById('graph-view');
  view.addEventListener('wheel', (e) => {
    if (currentTab !== 'graph') return;
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.91;
    const rect = view.getBoundingClientRect();
    gPanX = (e.clientX - rect.left) - factor * ((e.clientX - rect.left) - gPanX);
    gPanY = (e.clientY - rect.top) - factor * ((e.clientY - rect.top) - gPanY);
    gZoom = Math.max(0.05, Math.min(10, gZoom * factor));
    graphUpdateTransform();
  }, { passive: false });
  view.addEventListener('mousedown', (e) => {
    if (e.button !== 0 || currentTab !== 'graph') return;
    gDragging = true; gDragStartX = e.clientX; gDragStartY = e.clientY;
    gPanStartX = gPanX; gPanStartY = gPanY; view.classList.add('dragging');
  });
  document.addEventListener('mousemove', (e) => {
    if (!gDragging) return;
    gPanX = gPanStartX + (e.clientX - gDragStartX);
    gPanY = gPanStartY + (e.clientY - gDragStartY);
    graphUpdateTransform();
  });
  document.addEventListener('mouseup', () => { gDragging = false; document.getElementById('graph-view').classList.remove('dragging'); });
});

// --- Static data loading ---
async function fetchLocalJSON(path) {
  const r = await fetch(path);
  return r.json();
}
async function fetchLocalText(path) {
  const r = await fetch(path);
  return r.text();
}

async function init() {
  const containers = await fetchLocalJSON('containers.json');
  const list = document.getElementById('container-list');
  containers.sort((a, b) => b.processes - a.processes);
  for (const c of containers) {
    const div = document.createElement('div');
    div.className = 'container-item';
    div.innerHTML = `
      <div class="cid">${c.container_id}</div>
      <div class="stats">${c.processes} procs, ${c.influence_edges} edges, ${c.completed_actions} actions</div>
    `;
    div.onclick = () => selectContainer(c.container_id);
    list.appendChild(div);
  }
  document.getElementById('status-text').textContent = `${containers.length} containers (static dump)`;
}

async function selectContainer(id) {
  selectedContainer = id;
  selectedAction = null;
  document.querySelectorAll('.container-item').forEach(el => {
    el.classList.toggle('active', el.querySelector('.cid').textContent === id);
  });
  document.getElementById('no-selection').classList.add('hidden');
  await loadActionList();
  await loadTab();
}

async function loadActionList() {
  if (!selectedContainer) return;
  const actionList = document.getElementById('action-list');
  try {
    const data = await fetchLocalJSON(`containers/${selectedContainer}/actions.json`);
    let html = `<div class="action-item${selectedAction === null ? ' active' : ''}" onclick="selectAction(null)">
      <div class="action-id">Snapshot</div>
      <div class="action-cmd">Full container receipt</div>
    </div>`;
    for (const a of (data.completed || [])) {
      const short = a.command.length > 40 ? a.command.slice(0,40)+'...' : a.command;
      html += `<div class="action-item${selectedAction === a.action_id ? ' active' : ''}" onclick="selectAction(${a.action_id})">
        <div class="action-id">Action ${a.action_id}</div>
        <div class="action-cmd">${short}</div>
      </div>`;
    }
    actionList.innerHTML = html;
  } catch (e) { actionList.innerHTML = ''; }
}

function selectAction(actionId) {
  selectedAction = actionId;
  document.querySelectorAll('.action-item').forEach((el, i) => {
    el.classList.toggle('active', actionId === null ? i === 0 : el.querySelector('.action-id').textContent === `Action ${actionId}`);
  });
  loadTab();
}

function updateActionSidebarVisibility() {
  const s = document.getElementById('action-sidebar');
  if (currentTab === 'graph' || !selectedContainer) s.classList.add('hidden');
  else s.classList.remove('hidden');
}

async function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('#tabs .tab').forEach(el => el.classList.toggle('active', el.dataset.tab === tab));
  updateActionSidebarVisibility();
  await loadTab();
}

async function loadTab() {
  if (!selectedContainer) return;
  const receiptView = document.getElementById('receipt-view');
  const graphView = document.getElementById('graph-view');
  updateActionSidebarVisibility();

  if (currentTab === 'graph') {
    graphView.classList.remove('hidden');
    receiptView.classList.add('hidden');
    try {
      const dot = await fetchLocalText(`containers/${selectedContainer}/graph.dot`);
      if (typeof Viz !== 'undefined') {
        const svg = await Viz.instance().then(viz => viz.renderSVGElement(dot));
        const inner = document.getElementById('graph-inner');
        inner.innerHTML = '';
        inner.appendChild(svg);
        svg.style.width = 'auto'; svg.style.height = 'auto';
      }
      setTimeout(graphFit, 50);
    } catch (e) {
      document.getElementById('graph-inner').innerHTML = '<div style="color:#c00;padding:20px">Error: ' + e.message + '</div>';
    }
  } else {
    receiptView.classList.remove('hidden');
    graphView.classList.add('hidden');
    try {
      let data;
      if (selectedAction === null) {
        data = await fetchLocalJSON(`containers/${selectedContainer}/receipt.json`);
      } else {
        data = await fetchLocalJSON(`containers/${selectedContainer}/actions/${selectedAction}/receipt.json`);
      }
      receiptView.textContent = data.receipt || data.error || 'No data';
    } catch (e) { receiptView.textContent = 'Error: ' + e.message; }
  }
}

init();
</script>
<script src="viz.js"></script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Scrape a syscon instance into a static folder")
    parser.add_argument("--url", default="http://localhost:8000", help="syscon base URL")
    parser.add_argument("--out", default="./syscon-dump", help="output directory")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    out = args.out

    print(f"Scraping {base} -> {out}/")

    # 1. Fetch container list
    containers = fetch_json(base, "/containers")
    if containers is None:
        print("ERROR: Could not reach syscon at " + base, file=sys.stderr)
        sys.exit(1)

    # Filter: skip 0 actions and >MAX_PROCS
    visible = [c for c in containers if c.get("completed_actions", 0) > 0 and c.get("processes", 0) <= MAX_PROCS]
    skipped = len(containers) - len(visible)
    print(f"  {len(containers)} total containers, {len(visible)} with actions (skipped {skipped})")

    write(out, "containers.json", json.dumps(visible, indent=2))

    # 2. Fetch viz.js
    viz = fetch(base, "/viz.js")
    if viz:
        write(out, "viz.js", viz)
        print("  viz.js saved")
    else:
        print("  WARN: could not fetch viz.js", file=sys.stderr)

    # 3. For each container, fetch everything
    # Count total fetches for progress: per container = 3 (actions, receipt, graph) + N action receipts
    total_actions = sum(c.get("completed_actions", 0) for c in visible)
    total_fetches = len(visible) * 3 + total_actions
    done_fetches = 0

    def progress():
        nonlocal done_fetches
        done_fetches += 1
        pct = done_fetches * 100 // total_fetches if total_fetches else 100
        bar = "#" * (pct // 2) + "-" * (50 - pct // 2)
        print(f"\r  [{bar}] {pct:3d}% ({done_fetches}/{total_fetches})", end="", flush=True)

    for i, c in enumerate(visible):
        cid = c["container_id"]
        prefix = f"containers/{cid}"

        # Actions list
        actions_data = fetch_json(base, f"/containers/{cid}/actions")
        if actions_data:
            write(out, f"{prefix}/actions.json", json.dumps(actions_data, indent=2))
        progress()

        # Snapshot receipt
        receipt_data = fetch_json(base, f"/containers/{cid}/receipt")
        if receipt_data:
            write(out, f"{prefix}/receipt.json", json.dumps(receipt_data, indent=2))
        progress()

        # Graph DOT
        graph_dot = fetch(base, f"/containers/{cid}/graph")
        if graph_dot:
            write(out, f"{prefix}/graph.dot", graph_dot)
        progress()

        # Per-action receipts
        if actions_data:
            for a in actions_data.get("completed", []):
                aid = a["action_id"]
                ar = fetch_json(base, f"/containers/{cid}/actions/{aid}/receipt")
                if ar:
                    write(out, f"{prefix}/actions/{aid}/receipt.json", json.dumps(ar, indent=2))
                progress()

    print()  # newline after progress bar

    # 4. Write static index.html
    write(out, "index.html", make_static_index(None, visible))

    print(f"Done! {len(visible)} containers, {total_actions} actions -> {out}/")
    print(f"Serve with: python3 -m http.server -d {out}")


if __name__ == "__main__":
    main()
