# -*- coding: utf-8 -*-
"""
加密过程逐帧演示 —— 只为演示用，不参与生产链路。
运行：python demo_crypto.py
"""
import base64
import hashlib
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives import serialization

import crypto_core as cc

BAR = "─" * 68


def h(title: str) -> None:
    print(f"\n{BAR}\n{title}\n{BAR}")


def hexdump(b: bytes, n: int = 48) -> str:
    """十六进制 + ASCII 对照"""
    s = b[:n]
    hx = " ".join(f"{x:02x}" for x in s)
    asc = "".join(chr(x) if 32 <= x < 127 else "." for x in s)
    return f"{hx}\n      {asc}"


def main() -> None:
    mk = HERE / "keys" / "master.key"
    if mk.exists():
        master = bytes.fromhex(mk.read_text(encoding="ascii").strip())
        src = "keys/master.key  (权限 600，离线备份，永不进 git)"
    else:
        # 公开示例版：仓库里不含真实密钥，用本次运行随机生成的一把
        master = os.urandom(32)
        src = "本次运行随机生成（示例版无 keys/，真实使用时先跑 pack_tool.py init）"
    plain = (HERE / "server" / "payloads" / "demo.ea.ex5").read_bytes()

    # ── 1. 明文 ──────────────────────────────────────────────
    h("① 明文 EA 本体")
    print(f"文件      : demo.ea.ex5")
    print(f"大小      : {len(plain):,} 字节")
    print(f"SHA-256   : {hashlib.sha256(plain).hexdigest()}")
    print(f"前 48 字节 (MQL5 程序头，注意 magic = EX5):")
    print("      " + hexdump(plain))

    # ── 2. MASTER ────────────────────────────────────────────
    h("② 你手里唯一的那把主密钥 MASTER（32 字节，永不外发）")
    print(f"长度   : {len(master)} 字节")
    print(f"内容   : {master.hex()}")
    print(f"来源   : {src}")

    # ── 3. 按月派生 ──────────────────────────────────────────
    h("③ 按月派生会话密钥（HKDF-SHA256，纯函数 —— 这就是「月更」的全部机制）")
    print("  公式: K_月份 = HKDF-SHA256(MASTER, info=\"mt5-ea-payload|<月份>\", 32字节)\n")
    months = ["2026-10", "2026-11", "2026-12"]
    keys = {}
    for m in months:
        k = cc.derive_month_key(master, m)
        keys[m] = k
        mark = "  ← 当前月" if m == "2026-10" else ""
        print(f"  {m}  →  {k.hex()}{mark}")
    print(f"\n  三个密钥互不相同，且无法从任一推出另一个（HKDF 单向）")

    # ── 4. 加密 ──────────────────────────────────────────────
    h("④ AES-256-GCM 加密（AAD 绑定月份，密文包自证身份）")
    k = keys["2026-10"]
    blob = cc.seal(plain, k, "2026-10")
    print(f"  明文      : {len(plain):,} 字节")
    print(f"  密文包    : {len(blob):,} 字节   (+{len(blob)-len(plain)} 字节开销)")
    print(f"  开销构成  : 魔数 4 + 月长 1 + 月份 7 + nonce 12 + tag 16 = {4+1+7+12+16} 字节")
    print(f"\n  密文包布局（前 32 字节原件）:")
    print("      " + hexdump(blob, 32))
    print(f"\n  分层解剖:")
    print(f"    [0:4]    魔数      {blob[:4]!r}")
    print(f"    [4]      月长      {blob[4]}")
    print(f"    [5:12]   月份      {blob[5:12].decode('ascii')!r}   ← 解错月直接拒绝")
    print(f"    [12:24]  nonce     {blob[12:24].hex()}")
    print(f"    [24:-16] 密文体    {len(blob)-24-16:,} 字节 (与明文等长)")
    print(f"    [-16:]   GCM tag   {blob[-16:].hex()}")
    print(f"\n  密文体前 32 字节（与明文完全无关联）:")
    print("      " + hexdump(blob[24:56], 32))
    print(f"\n  整包 SHA-256: {hashlib.sha256(blob).hexdigest()}")

    # ── 5. 抗攻击演示 ────────────────────────────────────────
    h("⑤ 三层防护实测（全部是真跑，不是描述）")
    ok = 0
    total = 0

    # 5.1 改 1 bit
    total += 1
    bad = bytearray(blob)
    bad[len(bad) // 2] ^= 0x01
    try:
        cc.unseal(bytes(bad), k, expect_month="2026-10")
        print("  ✗ 密文改 1 bit → 竟然解开了（严重问题）")
    except Exception as e:
        ok += 1
        print(f"  ✓ 密文改 1 bit      → 拒绝 ({type(e).__name__})")

    # 5.2 跨月密钥
    total += 1
    try:
        cc.unseal(blob, keys["2026-11"], expect_month="2026-10")
        print("  ✗ 用 11 月密钥解 10 月包 → 竟然解开了（月更失效）")
    except Exception as e:
        ok += 1
        print(f"  ✓ 用 11 月密钥解 10 月包 → 拒绝 ({type(e).__name__})   ← 月更生效")

    # 5.3 换月份 AAD
    total += 1
    try:
        cc.unseal(blob, k, expect_month="2026-11")
        print("  ✗ 篡改月份参数 → 竟然解开了")
    except Exception as e:
        ok += 1
        print(f"  ✓ 篡改 AAD 月份     → 拒绝 ({type(e).__name__})")

    # 5.4 截断
    total += 1
    try:
        cc.unseal(blob[:len(blob) // 2], k, expect_month="2026-10")
        print("  ✗ 密文被截断 → 竟然解开了")
    except Exception as e:
        ok += 1
        print(f"  ✓ 密文被截断        → 拒绝 ({type(e).__name__})")

    # 5.5 正常解
    total += 1
    try:
        out, m = cc.unseal(blob, k, expect_month="2026-10")
        assert out == plain
        ok += 1
        print(f"  ✓ 正常密钥+正常月份 → 解开成功，{len(out):,} 字节，与原文逐字节一致")
    except Exception as e:
        print(f"  ✗ 正常路径失败: {e}")

    print(f"\n  {ok}/{total} 通过")

    # ── 6. 签名 ──────────────────────────────────────────────
    h("⑥ Ed25519 签名（防伪造服务器）")
    priv_path = HERE / "keys" / "ed25519_priv.pem"
    if priv_path.exists():
        priv = cc.load_private_pem(priv_path.read_bytes())
        pub_pem = (HERE / "keys" / "ed25519_pub.pem").read_bytes()
    else:
        # 公开示例版：无 keys/，现场生成一对演示用密钥
        priv = cc.gen_signing_key()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    pub = cc.load_public_pem(pub_pem)
    payload = {
        "license_key": "EA-ABC-001",
        "month": "2026-10",
        "key": k.hex(),
        "payload_sha256": hashlib.sha256(plain).hexdigest(),
        "exp": 1791993599,
    }
    sig = cc.sign_obj(priv, payload)
    print(f"  待签字段 : {list(payload.keys())}")
    print(f"  签名     : {sig[:64]}…")
    print(f"  签名长度 : {len(sig)//2} 字节")
    print(f"  验签(公钥)     : {'通过' if cc.verify_obj(pub, payload, sig) else '失败'}")
    tampered = dict(payload, exp=4102444799)
    print(f"  验签(改 exp 为2099) : {'通过（危险！）' if cc.verify_obj(pub, tampered, sig) else '拒绝  ← 改一个字签名就废'}")
    print(f"\n  客户端内置的只有这把公钥：")
    print(f"    {pub_pem.decode().strip().splitlines()[1][:56]}…")
    print(f"  客户即使逆向 exe 拿到公钥，也签不出新令牌（没有私钥）")

    # ── 7. 体积对比 ──────────────────────────────────────────
    h("⑦ 关键结论：月更的成本")
    print(f"  EA 加密一次           : {len(plain):,} 字节 → 之后密文永不变")
    print(f"  每月轮换的实际动作     : 重新派生 32 字节密钥（几微秒）")
    print(f"  而非每月重加密全文     : 那要每次处理 {len(plain):,} 字节，且所有客户要重下整包")
    print(f"\n  → 密文永久静止，只有那把 32 字节的钥匙跟着月份走")


if __name__ == "__main__":
    main()
