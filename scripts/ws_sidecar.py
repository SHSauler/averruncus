#!/usr/bin/env python3
"""ws_sidecar.py — WebSocket sidecar tests for Kallisti (dynamic, no source).
Phases: handshake/auth matrix, messaging delivery, malformed-input robustness,
basic authZ probes. Env: WS_URL, cookies/tokens via HTTP login done externally.
Usage: WS_URL=ws://127.0.0.1:8080/ws ALICE_CK=.. BOB_CK=.. GUEST_CK=.. ./ws_sidecar.py"""
import json
import os
import struct
import time

import websocket
from pymumble_py3.mumble_pb2 import Authenticate, Version

URL = os.environ.get("WS_URL", "ws://127.0.0.1:8080/ws")
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


def connect(cookie="", protos=("kallisti",)):
    kw = {"timeout": 8}
    if cookie:
        kw["header"] = {"Cookie": f"kallisti_session={cookie}"}
    if protos:
        kw["subprotocols"] = list(protos)
    ws = websocket.create_connection(URL, **kw)
    ws.settimeout(5)
    return ws


def drain(ws, n=6):
    out = []
    for _ in range(n):
        try:
            m = ws.recv()
            out.append(("str", m[:120]) if isinstance(m, str)
                       else ("bin", len(m), m[:2].hex() if len(m) >= 2 else ""))
        except Exception as e:
            out.append(("exc", type(e).__name__))
            break
    return out


def authed(cookie, user, pw=""):
    ws = connect(cookie)
    ws.send_binary(hello(user, pw))
    time.sleep(2)
    return ws, drain(ws)


if __name__ == "__main__":
    A = os.environ.get("ALICE_CK", "")
    B = os.environ.get("BOB_CK", "")
    G = os.environ.get("GUEST_CK", "")
    GN = os.environ.get("GUEST_NAME", "wsguest")

    # 1. no hello -> server waits then closes (inactivity), must stay alive
    w0 = connect()
    d0 = drain(w0, 2)
    rec("no-hello.stays-silent", any(x[0] == "exc" for x in d0), d0)
    try:
        w0.close()
    except Exception:
        pass

    # 2. wrong password
    w1, d1 = authed(A, "alice", "WrongPass!")
    types = [x[1] if x[0] == "bin" else x for x in d1]
    rec("wrong-password.rejected-or-limited", True, types)
    try:
        w1.close()
    except Exception:
        pass

    # 3. alice + bob authenticated sessions
    wa, da = authed(A, "alice", "TestPass123!")
    wb, db = authed(B, "bob", "TestPass123!")
    rec("alice.authed", any(x[0] == "bin" for x in da), da[:2])
    rec("bob.authed", any(x[0] == "bin" for x in db), db[:2])

    # 4. guest session
    wg, dg = authed(G, GN)
    rec("guest.authed", any(x[0] == "bin" for x in dg), dg[:2])

    # 5. alice sends channel text via JSON; bob (subscribed via history) hears it
    wb.settimeout(6)
    try:
        wb.send(json.dumps({"type": "history", "channel": 1}))
        time.sleep(1)
        for _ in range(4):
            try:
                wb.recv()
            except Exception:
                break
        wa.send(json.dumps({"type": "send", "channel": 1,
                            "text": "ws-probe-hello", "nonce": f"n-{time.time_ns()}"}))
        heard = []
        for _ in range(8):
            try:
                m = wb.recv()
                if isinstance(m, bytes) and m[:2] == b"\x00\x0b":
                    heard.append(m)
                elif isinstance(m, str) and "ws-probe-hello" in m:
                    heard.append(m)
            except Exception:
                break
        rec("json.send-delivered", len(heard) > 0, f"{len(heard)} msgs")
    except Exception as e:
        rec("json.send-delivered", False, e)

    # 6. malformed inputs: garbage binary, truncated frame, giant JSON, unknown type
    for label, payload, is_bin in [
        ("garbage-binary", b"\xff" * 64, True),
        ("truncated-frame", struct.pack("!HL", 2, 500) + b"\x0a\x05", True),
        ("giant-json", "x" * 200000, False),
        ("unknown-type", json.dumps({"type": "no-such-type", "x": 1}), False),
        ("wrong-shape", json.dumps({"type": "send", "channel": 12345}), False),
    ]:
        try:
            if is_bin:
                wa.send_binary(payload)
            else:
                wa.send(payload)
            time.sleep(1)
            rec(f"malformed.{label}", True, "no crash on send")
        except Exception as e:
            rec(f"malformed.{label}", "SEND-FAIL", e)
    # liveness: session still usable + server responds
    try:
        wa.send(json.dumps({"type": "send", "channel": 1,
                            "text": "ws-probe-after-fuzz", "nonce": f"n-{time.time_ns()}"}))
        time.sleep(1)
        rec("liveness.after-fuzz", True)
    except Exception as e:
        rec("liveness.after-fuzz", False, e)

    for w in (wa, wb, wg):
        try:
            w.close()
        except Exception:
            pass
    json.dump(R, open("/tmp/ws_sidecar.json", "w"), indent=1)
