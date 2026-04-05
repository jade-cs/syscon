#!/usr/bin/env bash
# Run all Docker-based syscon test scenarios.
#
# Prerequisites:
#   - syscon daemon running: sudo ./target/debug/syscon daemon --port 9900
#   - Docker available
#
# Usage:
#   ./tests/run-tests.sh              # run all scenarios
#   ./tests/run-tests.sh scenario-01  # run one scenario
#   ./tests/run-tests.sh -q           # quiet mode (summary only)

set -euo pipefail

QUIET=false
if [ "${1:-}" = "-q" ]; then
    QUIET=true
    shift
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCENARIOS_DIR="$SCRIPT_DIR/scenarios"
PORT="${SYSCON_PORT:-9900}"
URL="http://localhost:$PORT"
RESULTS_DIR="$SCRIPT_DIR/results"

PASS=0
FAIL=0
SKIP=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

cleanup_container() {
    local name="$1"
    sudo docker rm -f "$name" 2>/dev/null || true
}

check_prereqs() {
    if ! curl -sf "$URL/status" > /dev/null 2>&1; then
        echo -e "${RED}ERROR: syscon daemon not reachable at $URL${NC}"
        echo "Start with: sudo $PROJECT_DIR/target/debug/syscon daemon --port $PORT"
        exit 1
    fi
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}ERROR: docker not found${NC}"
        exit 1
    fi
}

# Run a single scenario directory.
# Each scenario has:
#   - Dockerfile (optional, defaults to alpine)
#   - run.sh: commands to execute inside the container
#   - actions.sh: action boundary markers + docker exec calls
#   - verify.sh: checks on the receipt output (exit 0 = pass)
run_scenario() {
    local dir="$1"
    local name
    name="$(basename "$dir")"
    local container_name="syscon-test-$name"

    $QUIET || echo -e "${BOLD}=== Scenario: $name ===${NC}"

    # Read scenario metadata
    if [ -f "$dir/description.txt" ] && ! $QUIET; then
        echo "  $(cat "$dir/description.txt")"
    fi

    cleanup_container "$container_name"
    mkdir -p "$RESULTS_DIR/$name"

    # Build image if Dockerfile exists
    local image="alpine:latest"
    if [ -f "$dir/Dockerfile" ]; then
        $QUIET || echo "  Building image..."
        if ! sudo docker build -t "syscon-test-$name" "$dir" > "$RESULTS_DIR/$name/build.log" 2>&1; then
            echo -e "  ${RED}FAIL: $name — docker build failed${NC}"
            $QUIET || cat "$RESULTS_DIR/$name/build.log"
            FAIL=$((FAIL + 1))
            return
        fi
        image="syscon-test-$name"
    fi

    # Launch container
    $QUIET || echo "  Launching container..."
    local cid
    cid=$(sudo docker run -d --name "$container_name" \
        "$image" sh -c 'sleep 300')
    local short_cid="${cid:0:12}"
    $QUIET || echo "  Container: $short_cid"
    sleep 1

    # Run actions
    if [ -f "$dir/actions.sh" ]; then
        $QUIET || echo "  Running actions..."
        if ! CONTAINER="$container_name" CID="$short_cid" URL="$URL" \
            bash "$dir/actions.sh" > "$RESULTS_DIR/$name/actions.log" 2>&1; then
            $QUIET || echo -e "  ${YELLOW}WARN: actions.sh had errors (may be expected)${NC}"
        fi
    fi

    # Collect receipts
    $QUIET || echo "  Collecting receipts..."
    local receipt_file="$RESULTS_DIR/$name/receipt.txt"
    curl -sf "$URL/containers/$short_cid/receipt" | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('receipt',''))" \
        > "$receipt_file" 2>/dev/null || true

    # Collect per-action receipts
    for i in $(seq 1 10); do
        local action_receipt
        action_receipt=$(curl -sf "$URL/containers/$short_cid/actions/$i/receipt" 2>/dev/null || echo "")
        if [ -n "$action_receipt" ]; then
            echo "$action_receipt" | \
                python3 -c "import sys,json; print(json.load(sys.stdin).get('receipt',''))" \
                > "$RESULTS_DIR/$name/action_${i}_receipt.txt" 2>/dev/null || true
        else
            break
        fi
    done

    # Collect graph
    curl -sf "$URL/containers/$short_cid/graph" \
        > "$RESULTS_DIR/$name/graph.dot" 2>/dev/null || true

    # Verify
    if [ -f "$dir/verify.sh" ]; then
        $QUIET || echo "  Verifying..."
        if RECEIPT="$receipt_file" RESULTS="$RESULTS_DIR/$name" CID="$short_cid" URL="$URL" \
            bash "$dir/verify.sh" > "$RESULTS_DIR/$name/verify.log" 2>&1; then
            if $QUIET; then
                echo -e "${GREEN}PASS${NC}  $name"
            else
                echo -e "  ${GREEN}PASS${NC}"
            fi
            PASS=$((PASS + 1))
        else
            echo -e "${RED}FAIL${NC}  $name"
            cat "$RESULTS_DIR/$name/verify.log"
            FAIL=$((FAIL + 1))
        fi
    else
        echo -e "${YELLOW}SKIP${NC}  $name (no verify.sh)"
        SKIP=$((SKIP + 1))
    fi

    # Cleanup
    cleanup_container "$container_name"

    # Delete container from daemon
    curl -sf -X DELETE "$URL/containers/$short_cid" > /dev/null 2>&1 || true
}

# Main
check_prereqs
mkdir -p "$RESULTS_DIR"

# Filter scenarios
if [ $# -gt 0 ]; then
    for name in "$@"; do
        dir="$SCENARIOS_DIR/$name"
        if [ -d "$dir" ]; then
            run_scenario "$dir"
        else
            echo -e "${RED}Scenario not found: $name${NC}"
            FAIL=$((FAIL + 1))
        fi
    done
else
    for dir in "$SCENARIOS_DIR"/*/; do
        [ -d "$dir" ] && run_scenario "$dir"
    done
fi

# Summary
echo ""
echo -e "${BOLD}=== Results ===${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}SKIP: $SKIP${NC}"

echo ""
echo "Results saved to: $RESULTS_DIR/"
[ $FAIL -gt 0 ] && exit 1
exit 0
