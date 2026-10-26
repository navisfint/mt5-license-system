# -*- coding: utf-8 -*-
"""
打包 / 管理工具（只在你自己的机器上跑，绝不发给客户）

用法：
    python pack_tool.py init
    python pack_tool.py publish 900421850.ex5          # 登记要保护的 EA（可换版本重发）
    python pack_tool.py issue  EA-ABC-001 --days 31    # 发一个 31 天有效期的授权
    python pack_tool.py revoke EA-ABC-001              # 立即吊销
    python pack_tool.py list
    python pack_tool.py client-const                   # 生成给 launcher 内置的常量

★ 红线：本脚本会读写 keys/ 下的 MASTER 与私钥。keys/ 目录永远不要进客户机、不要进 git。
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sqlite3
import string
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from crypto_core import (  # noqa: E402
    KEY_LEN,
    gen_signing_key,
    month_end_ts,
    current_month,
    sha256_hex,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402

ROOT = Path(__file__).resolve().parent
KEYS = ROOT / "keys"
SERVER_DIR = ROOT / "server"
PAYLOADS = SERVER_DIR / "payloads"
DB = SERVER_DIR / "licenses.db"
CLIENT = ROOT / "client"

MASTER_FILE = KEYS / "master.key"
PRIV_PEM = KEYS / "ed25519_priv.pem"
PUB_PEM = KEYS / "ed25519_pub.pem"
LIB_JSON = SERVER_DIR / "payloads.json"
LEGACY_JSON = SERVER_DIR / "payload.json"


def _ensure_dirs() -> None:
    for d in (KEYS, SERVER_DIR, PAYLOADS, CLIENT):
        d.mkdir(parents=True, exist_ok=True)


# ── EA 库（支持多个 EA 并存）────────────────────────────────────────
def load_lib() -> dict:
    """EA 库结构：{"eas": {文件名: {display,size,sha256,enabled,updated_at}}}"""
    if LIB_JSON.exists():
        return json.loads(LIB_JSON.read_text(encoding="utf-8"))
    if LEGACY_JSON.exists():
        old = json.loads(LEGACY_JSON.read_text(encoding="utf-8"))
        lib = {"eas": {old["filename"]: {
            "display": old["filename"].rsplit(".", 1)[0],
            "size": old["size"], "sha256": old["sha256"],
            "enabled": True, "updated_at": old.get("updated_at", int(time.time())),
        }}}
        LIB_JSON.write_text(json.dumps(lib, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[迁移] 旧版单 EA 配置 -> {LIB_JSON.name}")
        return lib
    return {"eas": {}}


def save_lib(lib: dict) -> None:
    LIB_JSON.write_text(json.dumps(lib, ensure_ascii=False, indent=2), encoding="utf-8")


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(DB)
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
    have = {r[1] for r in con.execute("PRAGMA table_info(licenses)")}
    for col, decl in [
        ("last_seen", "INTEGER DEFAULT 0"),
        ("host", "TEXT"),
        ("osuser", "TEXT"),
        ("last_ip", "TEXT"),
        ("disabled_eas", "TEXT DEFAULT ''"),
    ]:
        if col not in have:
            con.execute(f"ALTER TABLE licenses ADD COLUMN {col} {decl}")
    con.commit()
    return con


# ── init ─────────────────────────────────────────────────────────────
def cmd_init(_a) -> None:
    _ensure_dirs()
    if MASTER_FILE.exists():
        print(f"[跳过] MASTER 已存在：{MASTER_FILE}")
    else:
        MASTER_FILE.write_text(os.urandom(KEY_LEN).hex(), encoding="ascii")
        print(f"[生成] MASTER          -> {MASTER_FILE}")
    if PRIV_PEM.exists():
        print(f"[跳过] 签名私钥已存在：{PRIV_PEM}")
    else:
        priv = gen_signing_key()
        PRIV_PEM.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        PUB_PEM.write_bytes(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        print(f"[生成] Ed25519 私钥    -> {PRIV_PEM}")
        print(f"[生成] Ed25519 公钥    -> {PUB_PEM}")
    _db().close()
    print(f"[就绪] 授权库          -> {DB}")


# ── publish ──────────────────────────────────────────────────────────
def cmd_publish(a) -> None:
    _ensure_dirs()
    src = Path(a.ex5).resolve()
    if not src.is_file():
        sys.exit(f"[错误] 找不到文件：{src}")
    if src.suffix.lower() != ".ex5":
        print(f"[提醒] {src.name} 不是 .ex5 后缀，仍按二进制处理。")
    raw = src.read_bytes()
    dst = PAYLOADS / src.name
    shutil.copyfile(src, dst)

    lib = load_lib()
    old = lib["eas"].get(src.name)
    lib["eas"][src.name] = {
        "display": a.display or (old or {}).get("display") or src.name.rsplit(".", 1)[0],
        "size": len(raw),
        "sha256": sha256_hex(raw),
        "enabled": (old or {}).get("enabled", True),
        "updated_at": int(time.time()),
    }
    save_lib(lib)

    print(f"[发布] {src.name}  ({len(raw):,} 字节)  {'更新' if old else '新增'}")
    print(f"       显示名     = {lib['eas'][src.name]['display']}")
    print(f"       明文 SHA-256 = {lib['eas'][src.name]['sha256']}")
    print(f"       EA 库共 {len(lib['eas'])} 个：{'、'.join(lib['eas'])}")
    print("       客户端默认跟随服务端版本，换 EA 后无需重发 exe。")


def cmd_eas(a) -> None:
    lib = load_lib()
    if not lib["eas"]:
        print("（EA 库为空，用 publish 添加）")
        return
    print(f"{'文件名':<24}{'显示名':<20}{'大小':>10}  状态")
    print("-" * 74)
    for fn, m in lib["eas"].items():
        st = "启用" if m.get("enabled", True) else "全局停用"
        print(f"{fn:<24}{(m.get('display') or '')[:18]:<20}{m['size']:>10,}  {st}")
    print(f"\n共 {len(lib['eas'])} 个 EA。客户级启停用 issue --disable 或后台页面控制。")


def cmd_ea_toggle(a) -> None:
    lib = load_lib()
    if a.filename not in lib["eas"]:
        sys.exit(f"[错误] EA 库里没有 {a.filename}")
    lib["eas"][a.filename]["enabled"] = (a.cmd == "ea-enable")
    save_lib(lib)
    word = "启用" if lib["eas"][a.filename]["enabled"] else "全局停用"
    print(f"[{word}] {a.filename}")
    if a.cmd == "ea-disable":
        print("        影响所有客户：下一次启动时该 EA 不再下发，客户端会把它从 MT5 目录移除。")


def cmd_ea_remove(a) -> None:
    lib = load_lib()
    if a.filename not in lib["eas"]:
        sys.exit(f"[错误] EA 库里没有 {a.filename}")
    if input(f"确认从库中彻底删除 {a.filename}？(yes/no) ") != "yes":
        sys.exit("已取消")
    lib["eas"].pop(a.filename)
    save_lib(lib)
    (PAYLOADS / a.filename).unlink(missing_ok=True)
    print(f"[删除] {a.filename}")


# ── 授权签发 ─────────────────────────────────────────────────────────
def _parse_eas(spec: str) -> str:
    """--eas a.ex5,b.ex5 → 校验存在后返回规范化逗号串。空串表示「全部可用」。"""
    spec = (spec or "").strip()
    if not spec:
        return ""
    lib = load_lib()
    names = [s.strip() for s in spec.split(",") if s.strip()]
    missing = [n for n in names if n not in lib["eas"]]
    if missing:
        sys.exit(f"[错误] EA 库里没有：{', '.join(missing)}\n先 publish 它们，或用 --eas '' 表示全部可用。")
    return ",".join(names)


def cmd_issue(a) -> None:
    _ensure_dirs()
    exp = int(time.time()) + a.days * 86400
    allowed = _parse_eas(getattr(a, "eas", "") or "")
    disabled = _parse_eas(getattr(a, "disable", "") or "")
    if allowed and disabled:
        sys.exit("[错误] --eas 与 --disable 不能同时用：前者是白名单，后者是黑名单。")

    con = _db()
    con.execute(
        "INSERT INTO licenses(license_key,status,expires_at,created_at,note,disabled_eas) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(license_key) DO UPDATE SET status='active', expires_at=excluded.expires_at, "
        "note=excluded.note, disabled_eas=excluded.disabled_eas",
        (a.license_key, "active", exp, int(time.time()), a.note or "", disabled),
    )
    con.commit()
    con.close()

    lib = load_lib()
    total = len(lib["eas"])
    print(f"[签发] {a.license_key}  有效期至 {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}")
    if allowed:
        print(f"       EA 白名单：{allowed}  （其余不下发）")
    elif disabled:
        print(f"       EA 黑名单：{disabled}  （这些不下发，其余 {total - len(disabled.split(','))} 个正常）")
    else:
        print(f"       EA 范围：全部 {total} 个")
    print("       （指纹留空 = 首次联网时自动绑定客户机；换机需 revoke 后重发）")


def cmd_issue_ea(a) -> None:
    """给某个授权单独启停某个 EA。"""
    con = _db()
    row = con.execute("SELECT disabled_eas FROM licenses WHERE license_key=?", (a.license_key,)).fetchone()
    if not row:
        con.close()
        sys.exit(f"[错误] 授权码不存在：{a.license_key}")
    cur = {s for s in (row[0] or "").split(",") if s}
    if a.cmd == "license-ea-off":
        cur.add(a.filename)
    else:
        cur.discard(a.filename)
    new = ",".join(sorted(cur))
    con.execute("UPDATE licenses SET disabled_eas=? WHERE license_key=?", (new, a.license_key))
    con.commit()
    con.close()
    word = "停用" if a.cmd == "license-ea-off" else "启用"
    print(f"[{word}] {a.license_key} / {a.filename}")
    print(f"        该授权当前不可用的 EA：{new or '（无，全部可用）'}")


def cmd_revoke(a) -> None:
    con = _db()
    n = con.execute(
        "UPDATE licenses SET status='revoked' WHERE license_key=?", (a.license_key,)
    ).rowcount
    con.commit()
    con.close()
    print(f"[吊销] {a.license_key}  影响 {n} 行" if n else f"[未找到] {a.license_key}")


def cmd_list(_a) -> None:
    con = _db()
    rows = con.execute(
        "SELECT license_key,fingerprint,status,expires_at,last_seen,host,osuser,note,disabled_eas "
        "FROM licenses ORDER BY created_at"
    ).fetchall()
    con.close()
    lib = load_lib()
    total = len([1 for m in lib["eas"].values() if m.get("enabled", True)])
    if not rows:
        print("（授权库为空）")
        return
    now = int(time.time())
    print(f"{'授权码':<16}{'状态':<8}{'到期':<12}{'剩余':<7}{'EA 可用':<9}{'绑定机器':<18}{'使用人':<12}备注")
    print("-" * 108)
    for k, fp, st, exp, seen, host, user, note, dis in rows:
        left = (exp - now) // 86400
        flag = "已吊销" if st != "active" else ("已到期" if exp <= now else "正常")
        n_off = len([s for s in (dis or "").split(",") if s])
        ea_txt = f"{total - n_off}/{total}"
        print(
            f"{k:<16}{flag:<8}{time.strftime('%Y-%m-%d', time.localtime(exp)):<12}"
            f"{str(left) + '天':<7}{ea_txt:<9}{(host or '(未绑定)')[:16]:<18}{(user or '-')[:10]:<12}{note or ''}"
        )
        if dis:
            print(f"{'':<16}已停用 EA：{dis}")
        if fp:
            print(f"{'':<16}指纹 {fp[:20]}…   最后联网 {time.strftime('%Y-%m-%d %H:%M', time.localtime(seen)) if seen else '—'}")


def cmd_gencodes(a) -> None:
    """批量生成卡密。客户付钱后你发一张，他在启动器里输入即自动续期。"""
    _ensure_dirs()
    alphabet = string.ascii_uppercase + string.digits
    con = _db()
    made = []
    for _ in range(a.count):
        while True:
            raw = "".join(secrets.choice(alphabet) for _ in range(12))
            code = f"MT5-{raw[:4]}-{raw[4:8]}-{raw[8:12]}"
            if not con.execute("SELECT 1 FROM redeem_codes WHERE code=?", (code,)).fetchone():
                break
        con.execute(
            "INSERT INTO redeem_codes(code,days,created_at) VALUES(?,?,?)",
            (code, a.days, int(time.time())),
        )
        made.append(code)
    con.commit()
    con.close()
    print(f"[生成] {len(made)} 张卡密，每张 +{a.days} 天：\n")
    for c in made:
        print(f"    {c}")
    print("\n发给客户的方式：他付款后你把其中一张发给他，他在启动器里输入就自动续期。")


def cmd_codes(_a) -> None:
    con = _db()
    rows = con.execute(
        "SELECT code,days,used_by,used_at FROM redeem_codes ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    con.close()
    if not rows:
        print("（还没有卡密，用 gencodes 生成）")
        return
    free = sum(1 for r in rows if not r[2])
    print(f"共 {len(rows)} 张（未使用 {free} 张）\n")
    print(f"{'卡密':<22}{'天数':<7}{'状态':<9}使用者")
    print("-" * 70)
    for code, days, by, at in rows:
        st = "已使用" if by else "未使用"
        print(f"{code:<22}{days:<7}{st:<9}{by or '-'}")


# ── 生成客户端常量 ───────────────────────────────────────────────────
def cmd_client_const(a) -> None:
    if not PUB_PEM.exists():
        sys.exit("[错误] 请先执行 init。")
    lib = load_lib()
    if getattr(a, "pin", False):
        if len(lib["eas"]) != 1:
            sys.exit(f"[错误] --pin 只适用于库里只有 1 个 EA 的情况（当前 {len(lib['eas'])} 个）。\n"
                     "       多 EA 场景请用默认的「跟随服务端」模式。")
        fn, m = next(iter(lib["eas"].items()))
        policy = (f"PIN_PAYLOAD = True\n"
                  f'PAYLOAD_NAME = "{fn}"\n'
                  f'EXPECTED_SHA256 = "{m["sha256"]}"')
        note = "已钉死版本 → 以后换 EA 必须重发 exe"
    else:
        policy = ('PIN_PAYLOAD = False\n'
                  'PAYLOAD_NAME = ""\n'
                  'EXPECTED_SHA256 = ""')
        note = "跟随服务端签名响应 → 换 EA 只需 publish，无需重发 exe"
    body = f'''# -*- coding: utf-8 -*-
"""由 pack_tool.py client-const 自动生成 —— 请勿手改。
   本文件是唯一允许出现在客户机上的密钥相关材料：公钥只能验签，哈希不是秘密。"""
SERVER_PUBKEY_PEM = b"""{PUB_PEM.read_text(encoding='ascii').strip()}"""

# 版本策略：{note}
{policy}
'''
    out = CLIENT / "_const.py"
    out.write_text(body, encoding="utf-8")
    print(f"[生成] {out}")
    print(f"       策略：{note}")
    print(f"       EA 库：{len(lib['eas'])} 个")
    print(f"       当前月份密钥对应月份 = {current_month()}, 本月底 exp = {month_end_ts(current_month())}")


def main() -> None:
    p = argparse.ArgumentParser(description="MT5 EA 月度授权 - 打包/管理工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="生成 MASTER 与 Ed25519 密钥对、初始化授权库").set_defaults(fn=cmd_init)

    sp = sub.add_parser("publish", help="登记/更新一个 ex5（可重复调用，累积成 EA 库）")
    sp.add_argument("ex5")
    sp.add_argument("--display", default="", help="后台显示的友好名称")
    sp.set_defaults(fn=cmd_publish)

    sub.add_parser("eas", help="列出 EA 库").set_defaults(fn=cmd_eas)

    sp = sub.add_parser("ea-disable", help="全局停用某 EA（所有客户下次启动即失去它）")
    sp.add_argument("filename")
    sp.set_defaults(fn=cmd_ea_toggle)

    sp = sub.add_parser("ea-enable", help="全局恢复某 EA")
    sp.add_argument("filename")
    sp.set_defaults(fn=cmd_ea_toggle)

    sp = sub.add_parser("ea-remove", help="从 EA 库彻底删除")
    sp.add_argument("filename")
    sp.set_defaults(fn=cmd_ea_remove)

    sp = sub.add_parser("issue", help="签发授权")
    sp.add_argument("license_key")
    sp.add_argument("--days", type=int, default=31)
    sp.add_argument("--note", default="")
    sp.add_argument("--eas", default="", help="EA 白名单，逗号分隔；留空=全部可用")
    sp.add_argument("--disable", default="", help="EA 黑名单，逗号分隔")
    sp.set_defaults(fn=cmd_issue)

    sp = sub.add_parser("license-ea-off", help="给某个授权单独停用某个 EA")
    sp.add_argument("license_key")
    sp.add_argument("filename")
    sp.set_defaults(fn=cmd_issue_ea)

    sp = sub.add_parser("license-ea-on", help="给某个授权恢复某个 EA")
    sp.add_argument("license_key")
    sp.add_argument("filename")
    sp.set_defaults(fn=cmd_issue_ea)

    sp = sub.add_parser("revoke", help="吊销授权（下一次联网立即失效）")
    sp.add_argument("license_key")
    sp.set_defaults(fn=cmd_revoke)

    sub.add_parser("list", help="列出全部授权（含绑定机器、最后联网）").set_defaults(fn=cmd_list)

    sp = sub.add_parser("gencodes", help="批量生成续期卡密")
    sp.add_argument("--count", type=int, default=10)
    sp.add_argument("--days", type=int, default=31)
    sp.set_defaults(fn=cmd_gencodes)

    sub.add_parser("codes", help="查看卡密使用情况").set_defaults(fn=cmd_codes)
    sp = sub.add_parser("client-const", help="生成 launcher 需要的内置常量")
    sp.add_argument("--pin", action="store_true",
                    help="钉死当前 EA 版本（换 EA 时必须重发 exe）")
    sp.set_defaults(fn=cmd_client_const)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
