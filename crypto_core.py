# -*- coding: utf-8 -*-
"""
MT5 EA 月度授权 —— 加密核心（打包侧 / 服务端 / 客户端 三端共用）

★ 红线（改代码前必读，别绕）
1. MASTER 主密钥 与 Ed25519 私钥，只允许出现在「打包侧」和「服务端」。
   launcher（跑在客户机上）里只允许内置两样东西：Ed25519 **公钥** + 明文 ex5 的 SHA-256。
   这两样泄露无害（公钥只能验签，哈希不是秘密）。一旦把 MASTER 或私钥塞进客户端，全盘皆输。
2. 月度密钥由 MASTER + 月份「纯派生」（HKDF），服务端不落盘任何月度密钥。
   所以你不需要"每月改一次配置"——月份到了，密钥自然就变了。
   ⚠ 换 MASTER = 所有历史月份的密文全部作废，动手前确认。
3. AES-GCM 的 nonce 必须每次随机、同密钥下永不重复（重复即灾难性泄密）。
   AAD 绑死月份，防止把 10 月的密文配 11 月的密钥用。
4. 不要为了"更安全"让客户端自己能派生密钥 —— 那等价于把 MASTER 发给客户。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── 常量 ─────────────────────────────────────────────────────────────
MAGIC = b"EAX1"                 # 密文包头：EA X = EA eXchange，1 = 格式版本
HKDF_SALT = b"mt5-ea-license-v1"  # HKDF salt。改它 = 所有历史密文作废
NONCE_LEN = 12
KEY_LEN = 32
MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


# ── 时间工具 ─────────────────────────────────────────────────────────
def current_month(ts: float | None = None) -> str:
    """当前月份，形如 '2026-10'。以 UTC 为准，避免客户端改时区。"""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
    return f"{dt.year:04d}-{dt.month:02d}"


def month_end_ts(month: str) -> int:
    """某月最后一刻的 unix 时间戳。这个值就是授权令牌的 exp。"""
    y, m = int(month[:4]), int(month[5:7])
    nxt = datetime(y + (1 if m == 12 else 0), 1 if m == 12 else m + 1, 1, tzinfo=timezone.utc)
    return int(nxt.timestamp()) - 1


# ── 月度密钥派生 ─────────────────────────────────────────────────────
def derive_month_key(master: bytes, month: str) -> bytes:
    """
    由 MASTER 派生出某个月的对称密钥（32 字节）。
    这是整套方案的心脏：密钥是 (MASTER, 月份) 的纯函数，服务端无需存储。
    """
    if not MONTH_RE.match(month):
        raise ValueError(f"月份格式必须是 YYYY-MM，收到：{month!r}")
    if len(master) != KEY_LEN:
        raise ValueError(f"MASTER 必须是 {KEY_LEN} 字节，收到 {len(master)}")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=HKDF_SALT,
        info=b"mt5-ea-payload|" + month.encode("ascii"),
    ).derive(master)


# ── 密文包 封 / 解 ───────────────────────────────────────────────────
# 包结构：[MAGIC 4][month_len 1][month n][nonce 12][ciphertext + tag 16+]
def seal(plaintext: bytes, key: bytes, month: str) -> bytes:
    """用当月密钥加密明文，产出可过网络的密文包。"""
    mb = month.encode("ascii")
    if len(mb) > 255:
        raise ValueError("month 过长")
    nonce = os.urandom(NONCE_LEN)
    aad = MAGIC + mb
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return MAGIC + bytes([len(mb)]) + mb + nonce + ct


def unseal(blob: bytes, key: bytes, expect_month: str | None = None) -> tuple[bytes, str]:
    """
    解封密文包，返回 (明文, 包内月份)。
    任何篡改（改一个字节）都会在这里抛 InvalidTag —— 这是 GCM 给的认证保护。
    """
    if len(blob) < len(MAGIC) + 1 + 1 + NONCE_LEN + 16:
        raise ValueError("密文包太短，不是合法包")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("包头标识不对，不是我们的密文包")
    ml = blob[4]
    month = blob[5 : 5 + ml].decode("ascii")
    if expect_month is not None and month != expect_month:
        raise ValueError(f"包内月份 {month} 与服务器宣称的 {expect_month} 不一致")
    off = 5 + ml
    nonce, ct = blob[off : off + NONCE_LEN], blob[off + NONCE_LEN :]
    plain = AESGCM(key).decrypt(nonce, ct, MAGIC + month.encode("ascii"))
    return plain, month


# ── Ed25519 授权响应签名 ─────────────────────────────────────────────
def gen_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def load_private_pem(pem: bytes) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_public_pem(pem: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem)


def canonical(obj: dict) -> bytes:
    """规范化 JSON，保证签名与验签两侧字节完全一致。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_obj(priv: Ed25519PrivateKey, obj: dict) -> str:
    return priv.sign(canonical(obj)).hex()


def verify_obj(pub: Ed25519PublicKey, obj: dict, sig_hex: str) -> bool:
    """验签失败一律返回 False，不抛异常，调用方按 False 处理即可。"""
    try:
        pub.verify(bytes.fromhex(sig_hex), canonical(obj))
        return True
    except Exception:
        return False


# ── 设备指纹 ─────────────────────────────────────────────────────────
def _ps(cmd: str) -> str:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return out.stdout.decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def device_fingerprint() -> str:
    """
    客户机唯一标识：主板 UUID + CPU ID + 主机名，取 SHA-256。
    Windows 上 CIM 取值；非 Windows（本机自测）退化为 主机名 + MAC。
    """
    if sys.platform == "win32":
        parts = [
            _ps("(Get-CimInstance Win32_ComputerSystemProduct).UUID"),
            _ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).ProcessorId"),
            _ps("$env:COMPUTERNAME"),
        ]
    else:
        parts = ["non-win", uuid.getnode().__str__(), os.uname().nodename]
    raw = "|".join(p.strip() for p in parts if p and p.strip())
    if not raw or raw.count("|") >= len(parts):
        raw = f"fallback|{uuid.getnode()}|{os.environ.get('COMPUTERNAME', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
