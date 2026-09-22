#!/usr/bin/env python3
"""Probe the MT Manager built-in APK MCP server (Streamable HTTP).

MT Manager (bin.mt.plus) ships an "APK MCP" service that exposes its APK
analysis/edit/repack/sign capabilities to MCP clients over Streamable HTTP,
by default on device port 8787 (reachable from the PC via
``adb forward tcp:8787 tcp:8787``).

This script does the MCP handshake by hand (JSON-RPC 2.0 over plain HTTP
POSTs, no mcp SDK dependency):

  1. ``initialize``        -> serverInfo + capabilities
  2. ``notifications/initialized``
  3. ``tools/list``        -> tool inventory

Output is a human-readable capability report grouping the ``mt_apk_*`` tools
by category. When the server is not up yet (it must be started by hand in
the MT UI; adb cannot start it), the script prints waiting instructions and
exits 2, so it can also be used as a "is it up yet" check in a loop.

Verification status of the protocol shape: measured against the MT 2.26.9
implementation on 2026-09 (see docs/tool-verification/EXTENSION-kernel-ondevice.md).
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8787/mcp"

# Tool categories for the report, keyed by name prefix within mt_apk_*.
CATEGORIES = [
    ("open", "APK open/selection"),
    ("list", "Entry listing"),
    ("search", "Text/string search"),
    ("read", "Content read"),
    ("dex", "Dex analysis"),
    ("resource", "Resources"),
    ("native", "Native (.so) static analysis"),
    ("edit", "Edit sessions"),
    ("patch", "Byte/instruction patching"),
    ("build", "Repack + sign"),
    ("close", "Cleanup"),
]


def http_post(url, payload, session_id=None, timeout=10.0):
    """POST one JSON-RPC message; return (status, headers, parsed-body-or-None).

    Handles both plain application/json responses and text/event-stream
    (SSE-framed) responses, which Streamable HTTP servers may use for
    request bodies. Returns the first JSON object found in either shape.
    """
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            sid = resp.headers.get("Mcp-Session-Id")
            return resp.status, sid, parse_body(raw, resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return e.code, None, parse_body(raw, e.headers.get("Content-Type", ""))


def parse_body(raw, ctype):
    """Extract the first JSON message from a JSON or SSE-framed body."""
    raw = raw.strip()
    if not raw:
        return None
    if "text/event-stream" in (ctype or ""):
        for line in raw.splitlines():
            if line.startswith("data:"):
                chunk = line[len("data:"):].strip()
                try:
                    return json.loads(chunk)
                except ValueError:
                    continue
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def print_waiting_help(url):
    print("[waiting] MCP server is not answering at %s" % url)
    print()
    print("The MT APK MCP must be started by hand in the MT UI (adb cannot start it):")
    print("  1. On the phone: MT Manager -> side drawer -> Tools -> APK MCP -> Start")
    print("  2. Note the address shown on that page (host:port, default 8787)")
    print("  3. On the PC, make the port reachable over USB:")
    print("       adb forward tcp:8787 tcp:8787")
    print("  4. Re-run this probe:  python mt_mcp_probe.py")
    print()
    print("(LAN alternative: connect the PC and phone to the same network and pass")
    print(" --url http://<phone-ip>:8787/mcp)")


def main():
    ap = argparse.ArgumentParser(
        description="Probe the MT Manager APK MCP (Streamable HTTP) and list its tools.")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help="MCP endpoint (default: %(default)s)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request timeout in seconds (default: %(default)s)")
    ap.add_argument("--json", action="store_true",
                    help="print raw JSON-RPC responses instead of the report")
    args = ap.parse_args()

    # 1) initialize
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mt-mcp-probe", "version": "0.1"},
        },
    }
    try:
        status, session_id, body = http_post(args.url, init, timeout=args.timeout)
    except (urllib.error.URLError, OSError) as e:
        print_waiting_help(args.url)
        if args.json:
            print("[error] %s" % e)
        return 2

    if body is None or "result" not in (body or {}):
        print("[unexpected] HTTP %d, no MCP initialize result in response" % status)
        if args.json:
            print(json.dumps(body, indent=2) if body is not None else "(empty body)")
        return 1

    result = body["result"]
    server = result.get("serverInfo", {})
    proto = result.get("protocolVersion", "?")
    print("[online] %s | server %s %s | protocol %s | HTTP %d%s" % (
        args.url, server.get("name", "?"), server.get("version", "?"),
        proto, status, " | session %s" % session_id if session_id else ""))
    if args.json:
        print(json.dumps(result, indent=2))

    # 2) initialized notification (no id -> notification; 202 expected, body ignored)
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    try:
        http_post(args.url, note, session_id=session_id, timeout=args.timeout)
    except (urllib.error.URLError, OSError):
        pass  # some servers accept it silently; tools/list will tell us

    # 3) tools/list
    listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    try:
        status, _, body = http_post(args.url, listing, session_id=session_id,
                                    timeout=args.timeout)
    except (urllib.error.URLError, OSError) as e:
        print("[error] tools/list failed after successful initialize: %s" % e)
        return 1

    if body is None or "result" not in (body or {}):
        print("[unexpected] HTTP %d, no tools/list result" % status)
        if args.json:
            print(json.dumps(body, indent=2) if body is not None else "(empty body)")
        return 1

    tools = body["result"].get("tools", [])
    if args.json:
        print(json.dumps(body, indent=2))

    # 4) capability report
    print()
    print("== MCP tool inventory: %d tool(s) ==" % len(tools))
    mt_tools = [t for t in tools if t.get("name", "").startswith("mt_apk_")]
    other = [t for t in tools if not t.get("name", "").startswith("mt_apk_")]

    grouped = {prefix: [] for prefix, _ in CATEGORIES}
    for t in sorted(mt_tools, key=lambda x: x.get("name", "")):
        name = t.get("name", "")
        suffix = name[len("mt_apk_"):]
        placed = False
        for prefix, label in CATEGORIES:
            if suffix == prefix or suffix.startswith(prefix + "_"):
                grouped[prefix].append(t)
                placed = True
                break
        if not placed:
            grouped.setdefault("misc", []).append(t)

    for prefix, label in CATEGORIES:
        items = grouped.get(prefix, [])
        if not items:
            continue
        print("\n[%s] %s" % (label, len(items)))
        for t in items:
            desc = (t.get("description") or "").strip().splitlines()
            first = desc[0].strip() if desc else ""
            print("  %-42s %s" % (t.get("name"), first[:90]))
    if grouped.get("misc"):
        print("\n[other mt_apk_*] %d" % len(grouped["misc"]))
        for t in grouped["misc"]:
            print("  %s" % t.get("name"))

    if other:
        print("\n[non-mt_apk tools] %d" % len(other))
        for t in other:
            print("  %s" % t.get("name"))

    print()
    print("Constraints (from the official MT MCP docs, see on-device-tooling.md):")
    print("  - no Java decompilation; read smali directly instead")
    print("  - .so support is static analysis only (no dynamic run, no pseudo-C)")
    print("  - resources.arsc: existing entries editable, no new locales/entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
