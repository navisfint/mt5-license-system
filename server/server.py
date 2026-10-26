# -*- coding: utf-8 -*-
"""
授权服务端（跑在你的 VPS / 服务器上）

接口：
    GET  /health                 健康检查
    POST /license                换当月密钥。body: {"license_key","fingerprint","host","osuser"}
                                 响应 v2：一次下发该授权可用的全部 EA（每个 EA 一个密文包）
    POST /redeem                 卡密续期。body: {"license_key","fingerprint","code"}
    GET  /admin                  管理后台（Basic Auth）：看授权、绑定机器、最后联网时间、EA 库
    GET  /admin/lic?lk=xxx       单个授权的 EA 控制页（逐个 EA 启停）
    POST /admin/toggle           切换某授权下某 EA 的启停（表单：lk / ea / to=on|off）

启动：
    python server.py --host 0.0.0.0 --port 8787
    首次启动会自动生成后台账号密码，写在 server/admin.json 并打印到控制台。

★ 红线（同 crypto_core）：
  1. MASTER 与私钥只在本机内存里读，绝不通过任何接口返回。
  2. 客户端拿到的是「当月密钥」，泄露一把只影响那个月 —— 这正是"月更"的语义。
  3. 生产环境必须套 HTTPS（Nginx / Caddy 反代即可），否则中间人能看到 key。
"""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import secrets
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from crypto_core import (  # noqa: E402
    current_month,
    derive_month_key,
    load_private_pem,
    month_end_ts,
    seal,
    sha256_hex,
    sign_obj,
)

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
SERVER_DIR = ROOT / "server"
DB = SERVER_DIR / "licenses.db"
PAYLOADS = SERVER_DIR / "payloads"
ADMIN_JSON = SERVER_DIR / "admin.json"

_lock = threading.Lock()
MASTER: bytes = b""
PRIV = None
PAYLOAD_INFO: dict = {}
ADMIN: dict = {}


# ── 数据库 ───────────────────────────────────────────────────────────
def db_connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def ensure_schema() -> None:
    con = db_connect()
    con.execute(
        """CREATE TABLE IF NOT EXISTS licenses(
               license_key  TEXT PRIMARY KEY,
               fingerprint  TEXT,
               status       TEXT NOT NULL DEFAULT 'active',
               expires_at   INTEGER NOT NULL,
               last_issued  INTEGER NOT NULL DEFAULT 0,
               note         TEXT,
               created_at   INTEGER NOT NULL)"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS redeem_codes(
               code       TEXT PRIMARY KEY,
               days       INTEGER NOT NULL,
               created_at INTEGER NOT NULL,
               used_by    TEXT,
               used_at    INTEGER)"""
    )
    # 向后兼容：老库补列
    have = {r["name"] for r in con.execute("PRAGMA table_info(licenses)")}
    for col, decl in [
        ("last_seen", "INTEGER DEFAULT 0"),
        ("host", "TEXT"),
        ("osuser", "TEXT"),
        ("last_ip", "TEXT"),
        ("disabled_eas", "TEXT DEFAULT ''"),
    ]:
        if col not in have:
            con.execute(f"ALTER TABLE licenses ADD COLUMN {col} {decl}")
            print(f"[迁移] licenses 增加列 {col}")
    con.commit()
    con.close()


# ── 启动 ─────────────────────────────────────────────────────────────
def load_lib() -> dict:
    """热读 payloads.json —— publish / 停用 EA 后立即生效，无需重启服务。"""
    path = SERVER_DIR / "payloads.json"
    if not path.exists():
        # 向后兼容：老部署只有单 EA 的 payload.json
        old = json.loads((SERVER_DIR / "payload.json").read_text(encoding="utf-8"))
        return {"eas": {old["filename"]: {
            "display": old["filename"].rsplit(".", 1)[0],
            "size": old["size"], "sha256": old["sha256"], "enabled": True,
        }}}
    return json.loads(path.read_text(encoding="utf-8"))


def boot() -> None:
    global MASTER, PRIV, ADMIN
    ensure_schema()
    MASTER = bytes.fromhex((KEYS / "master.key").read_text(encoding="ascii").strip())
    PRIV = load_private_pem((KEYS / "ed25519_priv.pem").read_bytes())

    if ADMIN_JSON.exists():
        ADMIN = json.loads(ADMIN_JSON.read_text(encoding="utf-8"))
    else:
        ADMIN = {"user": "admin", "password": secrets.token_urlsafe(12)}
        ADMIN_JSON.write_text(json.dumps(ADMIN, ensure_ascii=False, indent=2), encoding="utf-8")

    lib = load_lib()
    n_on = sum(1 for m in lib["eas"].values() if m.get("enabled", True))
    print(f"[启动] EA 库 {len(lib['eas'])} 个（其中启用 {n_on} 个）：{'、'.join(lib['eas']) or '空'}")
    print(f"[启动] 当前月份 = {current_month()}，本月底 exp = {month_end_ts(current_month())}")
    print(f"[后台] /admin  账号 {ADMIN['user']}  密码 {ADMIN['password']}")


# ── 授权核心 ─────────────────────────────────────────────────────────
def _touch(con, lk: str, host: str, osuser: str, ip: str, now: int) -> None:
    con.execute(
        "UPDATE licenses SET last_seen=?, host=?, osuser=?, last_ip=? WHERE license_key=?",
        (now, host[:64], osuser[:64], ip, lk),
    )


def issue(license_key: str, fingerprint: str, host: str, osuser: str, ip: str) -> tuple[int, dict]:
    """换当月密钥。返回 (HTTP 状态码, 响应体)。"""
    now = int(time.time())
    con = db_connect()
    try:
        row = con.execute(
            "SELECT fingerprint,status,expires_at,disabled_eas FROM licenses WHERE license_key=?",
            (license_key,),
        ).fetchone()
        if not row:
            return 403, {"error": "license_not_found", "message": "授权码不存在"}
        if row["status"] != "active":
            return 403, {"error": "license_revoked", "message": "该授权已被吊销"}
        if row["expires_at"] <= now:
            return 403, {"error": "license_expired", "message": "授权已到期，请续费后重试"}
        if row["fingerprint"] and row["fingerprint"] != fingerprint:
            return 403, {"error": "fingerprint_mismatch", "message": "该授权已绑定其他设备"}

        if not row["fingerprint"]:
            con.execute("UPDATE licenses SET fingerprint=? WHERE license_key=?", (fingerprint, license_key))
            print(f"[绑定] {license_key} -> {fingerprint[:16]}...  {host}")

        _touch(con, license_key, host, osuser, ip, now)
        con.commit()

        month = current_month()
        key = derive_month_key(MASTER, month)

        # 每次请求重读 EA 库：publish / 停用 EA 立即生效，不用重启服务
        lib = load_lib()
        disabled = {s for s in (row["disabled_eas"] or "").split(",") if s}
        eas: list[dict] = []
        blocked: list[dict] = []
        for fn, meta in lib["eas"].items():
            if not meta.get("enabled", True):
                blocked.append({"name": fn, "why": "global"})
                continue
            if fn in disabled:
                blocked.append({"name": fn, "why": "license"})
                continue
            path = PAYLOADS / fn
            if not path.is_file():
                print(f"[警告] EA 文件缺失，跳过：{fn}")
                blocked.append({"name": fn, "why": "missing"})
                continue
            raw = path.read_bytes()
            if sha256_hex(raw) != meta["sha256"]:
                print(f"[警告] EA 哈希不符，跳过：{fn}")
                blocked.append({"name": fn, "why": "corrupt"})
                continue
            eas.append({
                "name": fn,
                "display": meta.get("display") or fn,
                "sha256": meta["sha256"],
                "size": len(raw),
                "payload": base64.b64encode(seal(raw, key, month)).decode("ascii"),
            })

        if not eas:
            return 503, {"error": "no_ea_available",
                         "message": "当前没有可下发的 EA，请联系提供方"}

        body = {
            "v": 2,
            "license_key": license_key,
            "month": month,
            "exp": month_end_ts(month),
            "license_expires_at": int(row["expires_at"]),
            "issued": now,
            "key": key.hex(),
            "eas": eas,
            # 被停用的 EA 名单：客户端要把它们从 MT5 目录里清掉
            "revoked_eas": [b["name"] for b in blocked],
        }
        body["sig"] = sign_obj(PRIV, body)
        total = sum(e["size"] for e in eas)
        print(f"[下发] {license_key}  month={month}  {host}/{osuser}  "
              f"{len(eas)} 个 EA ({total:,} 字节)"
              + (f"  停用 {len(blocked)} 个" if blocked else ""))
        return 200, body
    finally:
        con.close()


def redeem(license_key: str, fingerprint: str, code: str, ip: str) -> tuple[int, dict]:
    """卡密续期：校验卡密 → 未使用则给该授权延长 days 天 → 标记卡密已用。"""
    now = int(time.time())
    code = code.strip().upper()
    con = db_connect()
    try:
        lic = con.execute(
            "SELECT fingerprint,status,expires_at FROM licenses WHERE license_key=?", (license_key,)
        ).fetchone()
        if not lic:
            return 403, {"error": "license_not_found", "message": "授权码不存在"}
        if lic["fingerprint"] and lic["fingerprint"] != fingerprint:
            return 403, {"error": "fingerprint_mismatch", "message": "该授权已绑定其他设备"}
        card = con.execute("SELECT days,used_by FROM redeem_codes WHERE code=?", (code,)).fetchone()
        if not card:
            return 403, {"error": "code_invalid", "message": "卡密无效"}
        if card["used_by"]:
            return 403, {"error": "code_used", "message": "该卡密已被使用"}

        base = max(int(lic["expires_at"]), now)
        new_exp = base + int(card["days"]) * 86400
        con.execute("UPDATE redeem_codes SET used_by=?, used_at=? WHERE code=?", (license_key, now, code))
        con.execute(
            "UPDATE licenses SET expires_at=?, status='active', last_seen=?, last_ip=? WHERE license_key=?",
            (new_exp, now, ip, license_key),
        )
        con.commit()
        print(f"[续期] {license_key} +{card['days']}天 -> {time.strftime('%Y-%m-%d', time.localtime(new_exp))}")
        return 200, {
            "ok": True,
            "license_key": license_key,
            "days": int(card["days"]),
            "expires_at": new_exp,
            "message": f"续期成功，有效期至 {time.strftime('%Y-%m-%d %H:%M', time.localtime(new_exp))}",
        }
    finally:
        con.close()


# ── 管理后台页面 ─────────────────────────────────────────────────────
PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>EA 授权管理</title><style>
body{font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif;margin:32px;color:#1f2328;background:#fff}
h1{font-size:18px;font-weight:500;margin:0 0 16px}
h2{font-size:15px;font-weight:500;margin:28px 0 10px;color:#444}
table{border-collapse:collapse;width:100%%}
th,td{border:1px solid #e3e6eb;padding:7px 10px;text-align:left;font-size:13px}
th{background:#f7f8fa;font-weight:500}
.ok{color:#27500a}.warn{color:#854f0b}.bad{color:#a32d2d}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.muted{color:#888780;font-size:12px}
a{color:#185fa5;text-decoration:none}
form{display:inline}
button{font:12px system-ui;padding:2px 8px;border:1px solid #d0d4da;background:#fff;
       border-radius:5px;cursor:pointer;color:#1f2328}
button:hover{background:#f2f4f7}
button.off{color:#a32d2d;border-color:#e9c4c4}
</style></head><body>
<h1>EA 授权管理 · %(server_time)s</h1>
<p class="muted">当前月份密钥：%(month)s　|　授权 %(n_lic)s 条　|　EA 库 %(n_ea)s 个　|　卡密 %(n_code)s 张（未用 %(n_code_free)s）</p>
<h2>授权列表</h2>
<table><tr><th>授权码</th><th>状态</th><th>到期</th><th>剩余</th><th>EA 可用</th><th>绑定机器</th><th>使用人</th><th>最后联网</th><th>来源 IP</th></tr>
%(lic_rows)s</table>
<h2>EA 库</h2>
<table><tr><th>文件名</th><th>显示名</th><th>大小</th><th>全局状态</th><th>更新时间</th></tr>
%(ea_rows)s</table>
<h2>卡密</h2>
<table><tr><th>卡密</th><th>天数</th><th>状态</th><th>使用者</th><th>使用时间</th></tr>
%(code_rows)s</table>
</body></html>"""

LIC_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>%(lk)s · EA 控制</title><style>
body{font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif;margin:32px;color:#1f2328;background:#fff}
h1{font-size:17px;font-weight:500;margin:0 0 4px}
h2{font-size:15px;font-weight:500;margin:26px 0 10px;color:#444}
table{border-collapse:collapse;width:100%%}
th,td{border:1px solid #e3e6eb;padding:7px 10px;text-align:left;font-size:13px}
th{background:#f7f8fa;font-weight:500}
.ok{color:#27500a}.warn{color:#854f0b}.bad{color:#a32d2d}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.muted{color:#888780;font-size:12px}
a{color:#185fa5;text-decoration:none}
form{display:inline}
button{font:12px system-ui;padding:2px 8px;border:1px solid #d0d4da;background:#fff;
       border-radius:5px;cursor:pointer;color:#1f2328}
button:hover{background:#f2f4f7}
button.off{color:#a32d2d;border-color:#e9c4c4}
</style></head><body>
<p class="muted"><a href="/admin">&larr; 返回授权列表</a></p>
<h1>%(lk)s</h1>
<p class="muted">%(summary)s</p>
<h2>EA 控制</h2>
<p class="muted">停用后，该客户下次启动程序时这个 EA 不再下发，客户端会把它从 MT5 目录中移除。不影响其他 EA。</p>
<table><tr><th>EA</th><th>显示名</th><th>状态</th><th>操作</th></tr>
%(ea_rows)s</table>
</body></html>"""


def _lib_meta() -> dict:
    return load_lib()["eas"]


def render_admin() -> str:
    now = int(time.time())
    con = db_connect()
    try:
        lics = con.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
        codes = con.execute("SELECT * FROM redeem_codes ORDER BY created_at DESC LIMIT 500").fetchall()
    finally:
        con.close()
    eas = _lib_meta()
    n_on = sum(1 for m in eas.values() if m.get("enabled", True))

    def lic_row(r) -> str:
        left = (r["expires_at"] - now) // 86400
        if r["status"] != "active":
            cls, st = "bad", "已吊销"
        elif r["expires_at"] <= now:
            cls, st = "bad", "已到期"
        elif left <= 7:
            cls, st = "warn", "即将到期"
        else:
            cls, st = "ok", "正常"
        seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_seen"])) if r["last_seen"] else "—"
        off = {s for s in (r["disabled_eas"] or "").split(",") if s}
        avail = max(0, n_on - len([s for s in off if eas.get(s, {}).get("enabled", True)]))
        ea_cell = (f"<a href='/admin/lic?lk={r['license_key']}'>{avail}/{n_on} 个"
                   f"{'　已停 ' + str(len(off)) if off else ''}</a>")
        return (
            f"<tr><td class='mono'>{r['license_key']}</td>"
            f"<td class='{cls}'>{st}</td>"
            f"<td>{time.strftime('%Y-%m-%d', time.localtime(r['expires_at']))}</td>"
            f"<td class='{cls}'>{left} 天</td>"
            f"<td>{ea_cell}</td>"
            f"<td>{r['host'] or '—'}</td>"
            f"<td>{r['osuser'] or '—'}</td>"
            f"<td>{seen}</td>"
            f"<td class='mono'>{r['last_ip'] or '—'}</td></tr>"
        )

    def ea_row(fn: str, m: dict) -> str:
        on = m.get("enabled", True)
        return (
            f"<tr><td class='mono'>{fn}</td><td>{m.get('display') or '—'}</td>"
            f"<td>{m['size']:,} 字节</td>"
            f"<td class='{'ok' if on else 'bad'}'>{'启用' if on else '全局停用'}</td>"
            f"<td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(m.get('updated_at', 0)))}</td></tr>"
        )

    def code_row(r) -> str:
        return (
            f"<tr><td class='mono'>{r['code']}</td><td>{r['days']}</td>"
            f"<td class='{'ok' if not r['used_by'] else 'muted'}'>{'未使用' if not r['used_by'] else '已使用'}</td>"
            f"<td class='mono'>{r['used_by'] or '—'}</td>"
            f"<td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(r['used_at'])) if r['used_at'] else '—'}</td></tr>"
        )

    return PAGE % {
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "month": current_month(),
        "n_lic": len(lics),
        "n_ea": len(eas),
        "n_code": len(codes),
        "n_code_free": sum(1 for c in codes if not c["used_by"]),
        "lic_rows": "".join(lic_row(r) for r in lics) or "<tr><td colspan='9'>暂无授权</td></tr>",
        "ea_rows": "".join(ea_row(fn, m) for fn, m in eas.items()) or "<tr><td colspan='5'>EA 库为空</td></tr>",
        "code_rows": "".join(code_row(r) for r in codes) or "<tr><td colspan='5'>暂无卡密</td></tr>",
    }


def render_license(lk: str) -> str | None:
    now = int(time.time())
    con = db_connect()
    try:
        r = con.execute("SELECT * FROM licenses WHERE license_key=?", (lk,)).fetchone()
    finally:
        con.close()
    if not r:
        return None
    eas = _lib_meta()
    off = {s for s in (r["disabled_eas"] or "").split(",") if s}

    left = (r["expires_at"] - now) // 86400
    summary = (f"到期 {time.strftime('%Y-%m-%d', time.localtime(r['expires_at']))}（剩 {left} 天）"
               f"　|　绑定机器 {r['host'] or '未绑定'}　|　使用人 {r['osuser'] or '—'}")

    def row(fn: str, m: dict) -> str:
        g_on = m.get("enabled", True)
        l_off = fn in off
        if not g_on:
            cls, st = "bad", "全局停用"
            btn = "<span class='muted'>需先全局启用</span>"
        elif l_off:
            cls, st = "bad", "已停用"
            btn = (f"<form method='post' action='/admin/toggle'>"
                   f"<input type='hidden' name='lk' value='{lk}'>"
                   f"<input type='hidden' name='ea' value='{fn}'>"
                   f"<input type='hidden' name='to' value='on'>"
                   f"<button>启用</button></form>")
        else:
            cls, st = "ok", "可用"
            btn = (f"<form method='post' action='/admin/toggle'>"
                   f"<input type='hidden' name='lk' value='{lk}'>"
                   f"<input type='hidden' name='ea' value='{fn}'>"
                   f"<input type='hidden' name='to' value='off'>"
                   f"<button class='off'>停用</button></form>")
        return (f"<tr><td class='mono'>{fn}</td><td>{m.get('display') or '—'}</td>"
                f"<td class='{cls}'>{st}</td><td>{btn}</td></tr>")

    return LIC_PAGE % {
        "lk": lk,
        "summary": summary,
        "ea_rows": "".join(row(fn, m) for fn, m in eas.items()) or "<tr><td colspan='4'>EA 库为空</td></tr>",
    }


def toggle_ea(lk: str, fn: str, to: str) -> None:
    con = db_connect()
    try:
        r = con.execute("SELECT disabled_eas FROM licenses WHERE license_key=?", (lk,)).fetchone()
        if not r:
            return
        off = {s for s in (r["disabled_eas"] or "").split(",") if s}
        if to == "off":
            off.add(fn)
        else:
            off.discard(fn)
        con.execute("UPDATE licenses SET disabled_eas=? WHERE license_key=?", (",".join(sorted(off)), lk))
        con.commit()
        print(f"[EA控制] {lk} / {fn} -> {'停用' if to == 'off' else '启用'}")
    finally:
        con.close()


# ── HTTP ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "MT5Lic/2.0"

    def _json(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, code: int, html: str) -> None:
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self) -> bool:
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            u, _, p = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
        except Exception:
            return False
        return hmac.compare_digest(u, ADMIN["user"]) and hmac.compare_digest(p, ADMIN["password"])

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        if path == "/health":
            return self._json(200, {"ok": True, "month": current_month()})
        if path == "/admin":
            if not self._authed():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="EA License"')
                self.end_headers()
                return
            return self._html(200, render_admin())
        if path == "/admin/lic":
            if not self._authed():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="EA License"')
                self.end_headers()
                return
            lk = (parse_qs(query).get("lk") or [""])[0]
            html = render_license(lk)
            if html is None:
                return self._html(404, "<p>授权码不存在</p>")
            return self._html(200, html)
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        if path == "/admin/toggle":
            if not self._authed():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="EA License"')
                self.end_headers()
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
                form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
            except Exception:
                return self._json(400, {"error": "bad_request"})
            lk = (form.get("lk") or [""])[0]
            ea = (form.get("ea") or [""])[0]
            to = (form.get("to") or [""])[0]
            if not lk or not ea or to not in ("on", "off"):
                return self._json(400, {"error": "bad_request"})
            with _lock:
                toggle_ea(lk, ea, to)
            self.send_response(303)
            self.send_header("Location", f"/admin/lic?lk={quote(lk)}")
            self.end_headers()
            return

        if path not in ("/license", "/redeem"):
            return self._json(404, {"error": "not_found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json(400, {"error": "bad_request"})

        lk = (req.get("license_key") or "").strip()
        fp = (req.get("fingerprint") or "").strip()
        ip = self.client_address[0]
        if not lk or not fp:
            return self._json(400, {"error": "bad_request", "message": "缺少 license_key 或 fingerprint"})

        if path == "/license":
            with _lock:
                code, body = issue(
                    lk, fp,
                    (req.get("host") or "").strip(),
                    (req.get("osuser") or "").strip(),
                    ip,
                )
        else:
            card = (req.get("code") or "").strip()
            if not card:
                return self._json(400, {"error": "bad_request", "message": "缺少卡密"})
            with _lock:
                code, body = redeem(lk, fp, card, ip)
        self._json(code, body)

    def log_message(self, fmt, *args) -> None:
        sys.stderr.write("%s - %s\n" % (time.strftime("%H:%M:%S"), fmt % args))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    boot()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"[监听] http://{a.host}:{a.port}   后台 /admin   Ctrl+C 退出")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[退出]")


if __name__ == "__main__":
    main()
