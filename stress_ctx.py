#!/usr/bin/env python3
"""Stress test context window of OpenAI-compatible servers with tool calls."""

import json
import time
import sys
import urllib.request
import urllib.error

SERVERS = {
    "10.0.0.2": "http://10.0.0.2:8080/v1/chat/completions",
    "10.0.0.3": "http://10.0.0.3:8080/v1/chat/completions",
}

MODEL = "Qwen3.5-122B-A10B-UD-Q4_K_XL-00001-of-00003.gguf"

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a location",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {"type": "string", "description": "City name"},
                },
                "required": ["location"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_database",
            "description": "Search a database with a query string",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "limit": {"type": "integer", "description": "Max results"},
                },
                "required": ["query"],
            },
        },
    },
]

# Context size targets (in approximate prompt tokens)
# We'll build up messages to hit these targets
TARGETS = [1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 196608, 262144]


def make_filler_message(target_tokens: int, current_tokens: int) -> str:
    """Generate filler text to reach target token count.
    Rough estimate: 1 token ~= 4 chars for English text.
    """
    needed_tokens = target_tokens - current_tokens
    if needed_tokens <= 0:
        return ""
    # Use repetitive but varied text to fill context
    # Each line is roughly 20 tokens
    lines = []
    words = [
        "The", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog",
        "while", "analyzing", "distributed", "systems", "performance", "metrics",
        "across", "multiple", "server", "nodes", "in", "the", "cluster",
        "configuration", "database", "network", "protocol", "authentication",
        "service", "endpoint", "monitoring", "deployment", "infrastructure",
    ]
    i = 0
    while len(" ".join(lines)) < needed_tokens * 3.5:  # 3.5 chars per token estimate
        line_words = []
        for j in range(20):
            line_words.append(words[(i + j) % len(words)])
            i += 1
        line_words.append(f"(item {i})")
        lines.append(" ".join(line_words))
    return "\n".join(lines)


def send_request(url: str, payload: dict, timeout: int = 300) -> dict:
    """Send request and return parsed JSON response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return {"error": f"HTTP {e.code}: {body}"}
    except urllib.error.URLError as e:
        return {"error": f"URL error: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


def test_at_context_size(url: str, target_tokens: int) -> dict:
    """Test tool calling at a given context size."""
    # Build messages: system + filler user messages + final tool-call prompt
    # Estimate base prompt tokens (tools + system + final user msg) ~150 tokens
    base_tokens = 200
    filler = make_filler_message(target_tokens, base_tokens)

    messages = []
    # Add filler as a series of user/assistant exchanges to be more realistic
    chunk_size = len(filler) // 6  # split into 3 exchanges
    if chunk_size > 0:
        for i in range(3):
            start = i * chunk_size * 2
            messages.append({
                "role": "user",
                "content": f"Here is document section {i+1} for context:\n{filler[start:start+chunk_size]}",
            })
            messages.append({
                "role": "assistant",
                "content": f"I've reviewed section {i+1}. {filler[start+chunk_size:start+chunk_size*2][:chunk_size]}",
            })

    # Final prompt asking for a tool call
    messages.append({
        "role": "user",
        "content": "Based on all the context above, please look up the weather in Berlin.",
    })

    payload = {
        "model": MODEL,
        "messages": messages,
        "tools": TOOLS,
        "tool_choice": "auto",
    }

    # Measure payload size
    payload_bytes = len(json.dumps(payload).encode("utf-8"))

    start_time = time.time()
    result = send_request(url, payload, timeout=600)
    elapsed = time.time() - start_time

    # Parse result
    if "error" in result:
        return {
            "target_tokens": target_tokens,
            "payload_bytes": payload_bytes,
            "elapsed_s": round(elapsed, 2),
            "status": "ERROR",
            "error": result["error"][:200],
            "prompt_tokens": None,
            "completion_tokens": None,
            "tool_call_correct": False,
            "prompt_tps": None,
            "gen_tps": None,
        }

    usage = result.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)

    timings = result.get("timings", {})
    prompt_tps = None
    gen_tps = None
    if timings.get("prompt_per_second"):
        prompt_tps = round(timings["prompt_per_second"], 1)
    if timings.get("predicted_per_second"):
        gen_tps = round(timings["predicted_per_second"], 1)

    choice = result.get("choices", [{}])[0]
    finish_reason = choice.get("finish_reason", "")
    msg = choice.get("message", {})
    tool_calls = msg.get("tool_calls", [])

    tool_call_correct = False
    tool_call_detail = ""
    if finish_reason == "tool_calls" and len(tool_calls) > 0:
        tc = tool_calls[0]
        fn = tc.get("function", {})
        name = fn.get("name", "")
        try:
            args = json.loads(fn.get("arguments", "{}"))
        except json.JSONDecodeError:
            args = {"_raw": fn.get("arguments", "")}
        if name == "get_weather" and "location" in args:
            tool_call_correct = True
        tool_call_detail = f"{name}({json.dumps(args)})"
    elif msg.get("content"):
        tool_call_detail = f"text response (no tool call): {msg['content'][:100]}"
    else:
        tool_call_detail = f"finish_reason={finish_reason}, tool_calls={len(tool_calls)}"

    return {
        "target_tokens": target_tokens,
        "payload_bytes": payload_bytes,
        "elapsed_s": round(elapsed, 2),
        "status": "OK",
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "tool_call_correct": tool_call_correct,
        "tool_call_detail": tool_call_detail,
        "prompt_tps": prompt_tps,
        "gen_tps": gen_tps,
    }


def main():
    print("=" * 100)
    print("CONTEXT WINDOW STRESS TEST - Tool Calling")
    print("=" * 100)

    for server_name, url in SERVERS.items():
        print(f"\n{'='*100}")
        print(f"SERVER: {server_name}")
        print(f"{'='*100}")
        print(
            f"{'Target':>10} | {'Actual':>10} | {'Payload':>10} | {'Time':>8} | "
            f"{'Prompt t/s':>10} | {'Gen t/s':>8} | {'Tool OK':>8} | Detail"
        )
        print("-" * 100)

        for target in TARGETS:
            result = test_at_context_size(url, target)

            if result["status"] == "ERROR":
                print(
                    f"{result['target_tokens']:>10} | {'ERR':>10} | "
                    f"{result['payload_bytes']:>10} | {result['elapsed_s']:>7}s | "
                    f"{'--':>10} | {'--':>8} | {'FAIL':>8} | {result['error'][:40]}"
                )
                # If we get an error, likely hit the limit - but keep trying
                continue

            actual = result["prompt_tokens"] or 0
            ptps = str(result["prompt_tps"]) if result["prompt_tps"] else "--"
            gtps = str(result["gen_tps"]) if result["gen_tps"] else "--"
            ok = "YES" if result["tool_call_correct"] else "NO"
            detail = result.get("tool_call_detail", "")[:40]

            print(
                f"{result['target_tokens']:>10} | {actual:>10} | "
                f"{result['payload_bytes']:>10} | {result['elapsed_s']:>7}s | "
                f"{ptps:>10} | {gtps:>8} | {ok:>8} | {detail}"
            )
            sys.stdout.flush()

        print()

    print("\nDone.")


if __name__ == "__main__":
    main()
