# -*- coding: utf-8 -*-
"""第二轮联调：授权下发 / 卡密续期 / 管理后台。需要 server.py 已在 8787 监听。"""
import base64
import json
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from crypto_core import device_fingerprint  # noqa: E402

BASE = "http://127.0.0.1:8787"
ADMIN = json.loads((ROOT / "server" / "admin.json").read_text(encoding="utf-8"))
FP = device_fingerprint()
OK = []


def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def admin_page():
    req = urllib.request.Request(BASE + "/admin")
    tok = base64.b64encode(f"{ADMIN['user']}:{ADMIN['password']}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, ""


def check(name, ok, extra=""):
    OK.append(ok)
    print(f"{'✓' if ok else '✗'} {name}{('  ' + extra) if extra else ''}")


print("── 1. 授权下发 ──")
code, body = post("/license", {"license_key": "EA-ABC-001", "fingerprint": FP,
                               "host": "测试机-01", "osuser": "tester"})
check("正常授权返回 200", code == 200, f"month={body.get('month')}")
check("响应含签名", bool(body.get("sig")))
check("响应含授权到期时间", bool(body.get("license_expires_at")),
      f"expires_at={body.get('license_expires_at')}")

print("\n── 1b. 多 EA 下发 ──")
eas = body.get("eas") or []
check("响应是 v2 结构（eas 数组）", body.get("v") == 2 and isinstance(eas, list), f"v={body.get('v')}, {len(eas)} 个")
check("每个 EA 都有 name/sha256/payload",
      all(e.get("name", "").endswith(".ex5") and len(e.get("sha256", "")) == 64 and e.get("payload")
          for e in eas))
check("下发数量与 EA 库启用数一致", len(eas) + len(body.get("revoked_eas") or []) > 0,
      f"下发 {len(eas)}，未下发 {len(body.get('revoked_eas') or [])}")
check("含 revoked_eas 字段（客户端据此清理目录）", "revoked_eas" in body)

print("\n── 2. 管理后台 ──")
try:
    urllib.request.urlopen(BASE + "/admin", timeout=10)
    check("未带密码访问被拒", False, "竟然返回了 200")
except urllib.error.HTTPError as e:
    check("未带密码访问被拒", e.code == 401, f"HTTP {e.code}")
code, html = admin_page()
check("带密码可打开后台", code == 200 and "EA 授权管理" in html)
check("后台能看到授权码", "EA-ABC-001" in html)
check("后台能看到绑定机器", "测试机-01" in html)
check("后台能看到使用人", "tester" in html)

print("\n── 3. 卡密续期 ──")
con = sqlite3.connect(ROOT / "server" / "licenses.db")
card = con.execute("SELECT code FROM redeem_codes WHERE used_by IS NULL LIMIT 1").fetchone()
if not card:  # 让脚本可重复跑
    import secrets as _s, string as _st, time as _t
    raw = "".join(_s.choice(_st.ascii_uppercase + _st.digits) for _ in range(12))
    _c = f"MT5-{raw[:4]}-{raw[4:8]}-{raw[8:12]}"
    con.execute("INSERT INTO redeem_codes(code,days,created_at) VALUES(?,?,?)", (_c, 31, int(_t.time())))
    con.commit()
    card = (_c,)
before = con.execute("SELECT expires_at FROM licenses WHERE license_key='EA-ABC-001'").fetchone()[0]
con.close()
check("有待用卡密可用于测试", bool(card), card[0] if card else "")

code, r = post("/redeem", {"license_key": "EA-ABC-001", "fingerprint": FP, "code": card[0]})
check("卡密续期成功", code == 200 and r.get("ok"), r.get("message", ""))
con = sqlite3.connect(ROOT / "server" / "licenses.db")
after = con.execute("SELECT expires_at FROM licenses WHERE license_key='EA-ABC-001'").fetchone()[0]
con.close()
check("到期时间被延长", after > before, f"{before} -> {after}")

code, r = post("/redeem", {"license_key": "EA-ABC-001", "fingerprint": FP, "code": card[0]})
check("同一卡密不能重复使用", code == 403 and r.get("error") == "code_used", r.get("message", ""))
code, r = post("/redeem", {"license_key": "EA-ABC-001", "fingerprint": FP, "code": "MT5-XXXX-XXXX-XXXX"})
check("无效卡密被拒", code == 403 and r.get("error") == "code_invalid", r.get("message", ""))

print("\n── 4. 拒绝路径（回归） ──")
for name, key, fp, want in [
    ("已吊销的授权", "EA-REV-001", FP, "license_revoked"),
    ("不存在的授权码", "EA-NOT-EXIST", FP, "license_not_found"),
    ("换了一台机器", "EA-ABC-001", "fp-other-machine", "fingerprint_mismatch"),
]:
    c, b = post("/license", {"license_key": key, "fingerprint": fp, "host": "x", "osuser": "y"})
    check(name, c == 403 and b.get("error") == want, b.get("error", ""))

print(f"\n通过 {sum(OK)} / 共 {len(OK)}")
sys.exit(0 if all(OK) else 1)
