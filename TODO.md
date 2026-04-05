# TODO

## High Priority

### Multi-attribution
- Current model: each process has a single `attributed_action` that gets overwritten on cross-action taint (last-tag-wins)
- Better model: track *all* actions that influenced a process (set of action IDs) so the receipt can show the full causal chain
- Example: daemon from action 1 receives commands in action 2 and action 3 — its events should reference all three, not just the latest
- Relevant for eval frameworks where a long-lived control daemon receives commands across many actions

## Medium Priority

### Per-action graph view
- Generate a graph scoped to a single action (only processes/files from that action)
- Highlight new relationships vs pre-existing ones

## Low Priority

### Signal tracking
- `kill`/`tgkill` target PID resolution
- Create signal edges in taint graph

## Maybe

### Baseline noise suppression
- Every `bash --login` action produces locale-check, mesg, profile reads, nscd socket connects
- These are shell startup artifacts that repeat in every action
- Could maintain a per-container "baseline noise" set and suppress after first occurrence
- Risk: must not suppress genuinely suspicious profile/bashrc modifications
