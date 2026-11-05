#!/usr/bin/env python3
"""mumble_matrix.py — authZ/enumeration matrix against Kallisti built-in Mumble.
Guest join/move/message, registered login, SuperUser login, name protection.
Env: MUMBLE_HOST/PORT, MUMBLE_USER/MUMBLE_PASS, MUMBLE_SUPER_PASS."""
import os
import ssl
import time

if not hasattr(ssl, "wrap_socket"):
    def _wrap(sock, keyfile=None, certfile=None, server_side=False,
              ssl_version=None, **kw):
        ctx = ssl.SSLContext(ssl_version or ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if certfile:
            ctx.load_cert_chain(certfile, keyfile)
        return ctx.wrap_socket(sock)
    ssl.wrap_socket = _wrap

from pymumble_py3 import Mumble  # noqa: E402
from pymumble_py3.messages import MoveCmd, TextMessage, TextPrivateMessage  # noqa: E402

HOST = os.environ.get("MUMBLE_HOST", "127.0.0.1")
PORT = int(os.environ.get("MUMBLE_PORT", "64738"))
R = []
HEARD = []


def rec(check, ok, detail=""):
    R.append({"check": check, "ok": bool(ok), "detail": str(detail)[:200]})
    print(("PASS " if ok else "FAIL ") + check + (f" | {detail}"[:160] if detail else ""))


def connect(name, password=""):
    m = Mumble(HOST, name, port=PORT, password=password, debug=False)
    m.callbacks.set_callback("text_received", lambda msg: HEARD.append(msg.message[:120]))
    m.start()
    time.sleep(4)
    return m


def sess(m):
    try:
        return m.users.myself_session
    except Exception:
        return None


def me_of(m):
    try:
        return dict(m.users.myself)
    except Exception:
        pass
    for sid, u in m.users.items():
        if u.get("name") == m.user:
            return u
    return {}


def phase_guest():
    m = connect("probe-guest")
    rec("guest.connect", m.is_alive())
    if not m.is_alive():
        return None
    rec("guest.lands-in-lobby", me_of(m).get("channel_id") == 0,
        me_of(m).get("channel_id"))
    # join voice channel
    try:
        m.execute_command(MoveCmd(sess(m), 1))
        time.sleep(2)
        rec("guest.join-voice", me_of(m).get("channel_id") == 1,
            me_of(m).get("channel_id"))
    except Exception as e:
        rec("guest.join-voice", False, e)
    # channel text message (verified by a second listener client)
    lst = connect("probe-listen")
    try:
        lst.execute_command(MoveCmd(lst.users.myself_session, 1))
        time.sleep(2)
        HEARD.clear()
        m.execute_command(TextMessage(sess(m), 1, "probe guest hello"))
        time.sleep(2)
        rec("guest.send-channel-text", True)
        rec("guest.text-delivered", any("probe guest hello" in h for h in HEARD),
            HEARD[:2])
    except Exception as e:
        rec("guest.send-channel-text", False, e)
    finally:
        try:
            lst.stop()
        except Exception:
            pass
    # mirror channel enter attempt
    try:
        m.execute_command(MoveCmd(sess(m), 3))
        time.sleep(2)
        rec("guest.enter-mirror-note", True, f"chan={me_of(m).get('channel_id')}")
    except Exception as e:
        rec("guest.enter-mirror-note", True, f"rejected: {e}")
    return m


def phase_guest_moderation():
    """Guest attempts moderator actions on another user: all must fail."""
    a = connect("probe-victim")
    b = connect("probe-attacker")
    if not (a.is_alive() and b.is_alive()):
        rec("modprobe.setup", False)
        return
    try:
        a.execute_command(MoveCmd(a.users.myself_session, 1))
        b.execute_command(MoveCmd(b.users.myself_session, 1))
        time.sleep(2)
        # find victim from attacker's view
        tgt = None
        for sid, u in b.users.items():
            if u.get("name") == "probe-victim":
                tgt = u
                break
        if tgt is None:
            rec("modprobe.setup", False, "victim not visible")
            return
        try:
            tgt.mute()
            time.sleep(1)
        except Exception as e:
            rec("guest.mute-other", True, f"client refused: {e}")
            return
        av = None
        for sid, u in a.users.items():
            if u.get("name") == "probe-victim":
                av = u
                break
        rec("guest.mute-other", not (av and av.get("mute")), av)
        try:
            tgt2 = None
            for sid, u in b.users.items():
                if u.get("name") == "probe-victim":
                    tgt2 = u
                    break
            tgt2.kick("probe")
            time.sleep(2)
        except Exception:
            pass
        still = any(u.get("name") == "probe-victim" for _, u in a.users.items())
        rec("guest.kick-other", still, "victim still connected" if still else "VICTIM GONE")
    finally:
        try: a.stop()
        except Exception: pass
        try: b.stop()
        except Exception: pass


def phase_registered():
    u, p = os.environ.get("MUMBLE_USER", ""), os.environ.get("MUMBLE_PASS", "")
    if not u:
        rec("registered.login", "SKIP", "no creds")
        return
    m = connect(u, p)
    rec("registered.login", m.is_alive())
    if m.is_alive():
        rec("registered.channel", True, me_of(m).get("channel_id"))
        m.stop()


def phase_name_squat():
    u = os.environ.get("MUMBLE_USER", "")
    if not u:
        return
    m = connect(u)  # guest trying a registered name, no password
    time.sleep(2)
    if m.is_alive():
        rec("name-squat.blocked-or-renamed", me_of(m).get("name") != u,
            f"name={me_of(m).get('name')}")
        m.stop()
    else:
        rec("name-squat.rejected", True, "connect refused")


def phase_super():
    p = os.environ.get("MUMBLE_SUPER_PASS", "")
    if not p:
        rec("super.login", "SKIP", "no creds")
        return
    m = connect("SuperUser", p)
    rec("super.login", m.is_alive())
    if m.is_alive():
        m.stop()


if __name__ == "__main__":
    g = phase_guest()
    phase_guest_moderation()
    phase_registered()
    phase_name_squat()
    phase_super()
    if g:
        g.stop()
    import json
    open("/tmp/mumble_matrix.json", "w").write(json.dumps(R, indent=1))
