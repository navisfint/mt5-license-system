# -*- coding: utf-8 -*-
"""
加密层自测：验证「该拒绝的必须拒绝」。
跑法：python selftest.py     （纯本地，不需要服务端）
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from crypto_core import (  # noqa: E402
    current_month,
    derive_month_key,
    gen_signing_key,
    load_public_pem,
    seal,
    sign_obj,
    unseal,
    verify_obj,
)

PASS, FAIL = [], []


def check(name: str, ok: bool, extra: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"{'✓' if ok else '✗'} {name}{('  ' + extra) if extra else ''}")


def must_fail(name: str, fn) -> None:
    try:
        fn()
        check(name, False, "→ 竟然成功了，这是漏洞")
    except Exception as e:
        check(name, True, f"→ 已拒绝（{type(e).__name__}）")


def current_payload() -> bytes:
    """始终读 EA 库里第一个 EA，换版本/加 EA 后自测无需改代码。"""
    lib = json.loads((HERE / "server" / "payloads.json").read_text(encoding="utf-8"))
    fn = next(iter(lib["eas"]))
    return (HERE / "server" / "payloads" / fn).read_bytes()


def main() -> None:
    master = os.urandom(32)
    plain = current_payload()
    this_month = current_month()

    print("\n── 1. 密钥派生 ──")
    k_oct = derive_month_key(master, "2026-10")
    k_oct2 = derive_month_key(master, "2026-10")
    k_nov = derive_month_key(master, "2026-11")
    check("同月派生结果稳定（服务端无需存密钥）", k_oct == k_oct2)
    check("跨月派生结果不同（这就是月更）", k_oct != k_nov,
          f"10月={k_oct.hex()[:16]}…  11月={k_nov.hex()[:16]}…")
    check("换 MASTER 等于所有密文作废", derive_month_key(os.urandom(32), "2026-10") != k_oct)

    print("\n── 2. 正常封 / 解 ──")
    blob = seal(plain, k_oct, "2026-10")
    back, m = unseal(blob, k_oct)
    check("解密结果与原文逐字节一致", back == plain and m == "2026-10",
          f"密文 {len(blob):,} 字节（原文 {len(plain):,}，开销 {len(blob) - len(plain)} 字节）")

    print("\n── 3. 该拒绝的一律拒绝 ──")
    bad = bytearray(blob)
    bad[len(bad) // 2] ^= 0x01
    must_fail("密文被改 1 bit → 解密失败（GCM 认证）", lambda: unseal(bytes(bad), k_oct))

    must_fail("拿 11 月密钥解 10 月包 → 失败（月更生效）", lambda: unseal(blob, k_nov))

    def month_swap():
        b2 = seal(plain, k_nov, "2026-11")
        unseal(b2, k_oct, expect_month="2026-10")
    must_fail("包内月份与服务器宣称月份不一致 → 失败（AAD 绑定）", month_swap)

    def truncate():
        unseal(blob[:20], k_oct)
    must_fail("密文被截断 → 失败", truncate)

    def wrong_magic():
        unseal(b"XXXX" + blob[4:], k_oct)
    must_fail("包头被换 → 失败", wrong_magic)

    print("\n── 4. 授权响应签名 ──")
    priv = gen_signing_key()
    pub = load_public_pem(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    resp = {"month": this_month, "key": k_oct.hex(), "exp": 1, "issued": 2}
    sig = sign_obj(priv, resp)
    check("合法签名 → 通过", verify_obj(pub, resp, sig))
    check("篡改响应体（把 key 换掉）→ 拒绝",
          not verify_obj(pub, dict(resp, key=os.urandom(32).hex()), sig))
    check("伪造服务器自称有效（无签名）→ 拒绝", not verify_obj(pub, resp, ""))
    check("换一对密钥自签 → 拒绝（客户端只认内置公钥）",
          not verify_obj(pub, resp, sign_obj(gen_signing_key(), resp)))

    print("\n── 汇总 ──")
    print(f"通过 {len(PASS)} / 共 {len(PASS) + len(FAIL)}")
    if FAIL:
        print("失败项：" + "；".join(FAIL))
        sys.exit(1)
    print("加密层行为符合预期。")


if __name__ == "__main__":
    main()
