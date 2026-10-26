# -*- coding: utf-8 -*-
"""
授权启动器（这个才是随产品分发的，打包成单个 launcher.exe）

每次启动的动作：
    联网换当月密钥 → 验签 → 解密 → 校验哈希 → 释放到 MT5 数据目录 → 启动 MT5 → 看守 → 退出即擦除

命令行：
    launcher.exe               正常启动
    launcher.exe --redeem      输入卡密续期（到期后终端用户用这个）
    launcher.exe --check-only  只做联网+验签+解密+哈希校验，不落盘、不起 MT5
    launcher.exe --dry-run     落盘但不启动 MT5（现场排查用）
    launcher.exe --keep        退出后不擦除明文（只给自己调试，不要随产品分发）

★ 红线：本文件内置的只有 公钥 + 明文哈希，都可公开。
  绝对不要在这里写 MASTER、私钥、或任何能派生月度密钥的东西。
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) \
    else Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import _const  # noqa: E402
from crypto_core import (  # noqa: E402
    device_fingerprint,
    load_public_pem,
    sha256_hex,
    unseal,
    verify_obj,
)

STATE_DIR = Path.home() / ".mt5lic"
STATE_FILE = STATE_DIR / "state.json"
CACHE_FILE = STATE_DIR / "cache.bin"
LOG_FILE = STATE_DIR / "launcher.log"
CONFIG_FILE = HERE / "config.json"

MT5_EXE = "terminal64.exe"
APP_NAME = "EA 授权"

DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8787",
    "license_key": "",
    "terminal_path": "",
    "data_dir": "",
    "timeout": 20,
    "grace_hours": 72,
    "wipe_passes": 3,
    "watchdog_seconds": 3,
    "readonly_lock": True,
    "warn_days_before": 3,
}

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ── 日志 / 交互 ──────────────────────────────────────────────────────
def log(msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if sys.stdout is not None:
        try:
            print(line, flush=True)
        except Exception:
            pass


def popup(title: str, msg: str, kind: str = "info") -> None:
    """原生 Windows 弹窗。没有控制台时这是终端用户唯一能看到的信息。"""
    code = {"error": 0x10, "warn": 0x30, "info": 0x40}.get(kind, 0x40)
    log(f"[弹窗/{kind}] {msg}")
    if os.environ.get("MT5LIC_NOPOPUP"):      # 自动化测试 / 远程支持时静音
        return
    if sys.platform == "win32":
        try:
            ctypes.windll.user32.MessageBoxW(None, msg, f"{APP_NAME} - {title}", code)
            return
        except Exception:
            pass
    print(f"{title}: {msg}", file=sys.stderr)


def ask_string(title: str, prompt: str) -> str:
    """输入框。优先 tkinter（窗口版 exe 可用），退化到控制台。"""
    try:
        import tkinter as tk
        from tkinter import simpledialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        val = simpledialog.askstring(title, prompt, parent=root)
        root.destroy()
        return (val or "").strip()
    except Exception:
        try:
            return input(f"{prompt} ").strip()
        except Exception:
            return ""


def fail(title: str, msg: str) -> None:
    log(f"✗ {title}：{msg}")
    popup(title, msg, "error")
    sys.exit(1)


# ── DPAPI：让离线缓存只能被「本机本用户」解开 ────────────────────────
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi(data: bytes, unprotect: bool = False) -> bytes | None:
    """Windows DPAPI 加/解密。失败返回 None（宁可不缓存，也不明文落盘）。"""
    if sys.platform != "win32":
        return None
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_string_buffer(data, len(data))
        src = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        out = _BLOB()
        fn = crypt32.CryptUnprotectData if unprotect else crypt32.CryptProtectData
        if not fn(ctypes.byref(src), None, None, None, None, 0x1, ctypes.byref(out)):
            return None
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)
    except Exception:
        return None


# ── 配置 / 状态 ──────────────────────────────────────────────────────
def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except Exception as e:
            fail("配置读取失败", f"{CONFIG_FILE}\n{e}")
    else:
        CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        fail("首次运行", f"已生成配置模板，请填写 license_key 后重试：\n{CONFIG_FILE}")
    if not cfg.get("license_key"):
        key = os.environ.get("MT5LIC_LICENSE_KEY") or ask_string("首次使用", "请输入您的授权码：")
        if not key:
            fail("未填写授权码",
                 f"请把授权码填入 config.json 的 license_key 字段：\n{CONFIG_FILE}")
        cfg["license_key"] = key.strip()
        try:
            CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        log(f"已保存授权码：{cfg['license_key']}")
    return cfg


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(st: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(st), encoding="utf-8")


def save_cache(body: dict) -> None:
    raw = dpapi(json.dumps(body).encode("utf-8"))
    if raw is None:
        log("（DPAPI 不可用，跳过离线缓存）")
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_bytes(raw)


def load_cache() -> dict | None:
    try:
        raw = dpapi(CACHE_FILE.read_bytes(), unprotect=True)
        return json.loads(raw.decode("utf-8")) if raw else None
    except Exception:
        return None


# ── 联网 ─────────────────────────────────────────────────────────────
def post(cfg: dict, path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        cfg["server_url"].rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=cfg["timeout"]) as r:
        return json.loads(r.read().decode("utf-8"))


def acquire(cfg: dict) -> dict:
    """联网换当月授权；连不上则尝试用 DPAPI 加密的缓存撑过宽限期。"""
    payload = {
        "license_key": cfg["license_key"],
        "fingerprint": device_fingerprint(),
        "host": os.environ.get("COMPUTERNAME", ""),
        "osuser": os.environ.get("USERNAME", ""),
    }
    try:
        body = post(cfg, "/license", payload)
        save_cache(body)
        log("✓ 已从服务器换取当月授权")
        return body
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8"))
        except Exception:
            detail = {}
        code = detail.get("error", "")
        msg = detail.get("message") or f"服务器返回 {e.code}"
        if code == "license_expired":
            fail("授权已到期", f"{msg}\n\n请在「续期」程序里输入新的卡密。")
        fail("授权被拒绝", msg)
    except Exception as e:
        log(f"⚠ 连不上授权服务器：{e}")

    cached = load_cache()
    if not cached:
        fail("无法连接授权服务器", f"地址：{cfg['server_url']}\n请检查网络后重试。")
    grace = int(cfg["grace_hours"])
    deadline = min(int(cached.get("exp", 0)), int(cached.get("issued", 0)) + grace * 3600)
    now = int(time.time())
    if now > deadline:
        fail("需要重新联网", f"已超过 {grace} 小时离线宽限，请连接网络后重试。")
    left = int((deadline - now) // 3600)
    log(f"⚠ 服务器不可达，启用离线宽限（剩余 {left} 小时）")
    popup("离线模式", f"暂时连不上授权服务器，已启用离线宽限，还可运行约 {left} 小时。", "warn")
    return cached


# ── 验签 / 解密 ──────────────────────────────────────────────────────
def _safe_ea_name(name: str) -> bool:
    """只接受纯文件名，杜绝 ..\\ 与绝对路径穿越。"""
    if not name or len(name) > 128 or not name.lower().endswith(".ex5"):
        return False
    return all(c.isalnum() or c in "._-" for c in name)


def verify(body: dict) -> tuple[list[dict], str, int, list[str]]:
    """验签 + 逐个解密。

    返回 (eas, month, lic_exp, blocked)
      eas     : [{"name","display","sha256","plain"}]  本次允许释放的 EA
      blocked : 服务端明确告知「不下发」的 EA 文件名（含被停用/缺失/损坏）
    """
    body = dict(body)
    sig = body.pop("sig", "")
    pub = load_public_pem(_const.SERVER_PUBKEY_PEM)
    if not verify_obj(pub, body, sig):
        fail("安全校验失败", "服务器响应签名不合法，可能连到了伪造的服务器。")

    month = body.get("month", "")
    issued, exp = int(body.get("issued", 0)), int(body.get("exp", 0))
    if exp <= issued:
        fail("安全校验失败", "响应过期（exp 早于签发时间）。")
    st = load_state()
    if issued < int(st.get("last_issued", 0)) - 120:
        fail("安全校验失败", "检测到旧响应重放。")

    key_hex = str(body.get("key") or "")
    items = body.get("eas")
    if not key_hex or not isinstance(items, list) or not items:
        fail("安全校验失败", "服务端未下发可用的 EA，拒绝执行。")

    pin = getattr(_const, "PIN_PAYLOAD", False)
    if pin and len(items) != 1:
        fail("版本不匹配", "本程序钉死了单个 EA，但服务端下发了多个，请向提供方索取新版启动程序。")

    key = bytes.fromhex(key_hex)
    out: list[dict] = []
    seen: set[str] = set()
    for it in items:
        name = str(it.get("name") or "")
        srv_sha = str(it.get("sha256") or "").lower()
        if not _safe_ea_name(name):
            fail("安全校验失败", f"服务端下发的 EA 文件名不合法：{name!r}")
        if name in seen:
            fail("安全校验失败", f"服务端下发了重复的 EA：{name}")
        seen.add(name)
        if len(srv_sha) != 64:
            fail("安全校验失败", f"{name} 的哈希值不合法，拒绝执行。")

        if pin and (name != _const.PAYLOAD_NAME
                    or srv_sha != (_const.EXPECTED_SHA256 or "").lower()):
            fail("版本不匹配", "服务端上的 EA 与本程序内置版本不一致，请向提供方索取新版启动程序。")

        try:
            plain, packed_month = unseal(base64.b64decode(it["payload"]), key,
                                         expect_month=month)
        except Exception as e:
            fail("解密失败", f"{name} 解密失败，密钥或密文不匹配：{e}")
        if packed_month != month:
            fail("安全校验失败", f"{name} 的密文包内月份与令牌不一致。")

        actual = sha256_hex(plain)
        if actual != srv_sha:
            fail("完整性校验失败",
                 f"{name} 解密结果与预期不符，已拒绝释放。\n"
                 f"期望 {srv_sha[:16]}…\n实际 {actual[:16]}…")
        out.append({"name": name,
                    "display": str(it.get("display") or name),
                    "sha256": srv_sha,
                    "plain": plain})

    blocked = [str(x) for x in (body.get("revoked_eas") or []) if _safe_ea_name(str(x))]

    st["last_issued"] = max(int(st.get("last_issued", 0)), issued)
    st["last_month"] = month
    save_state(st)

    total = sum(len(e["plain"]) for e in out)
    log(f"✓ 验签通过 month={month}，{len(out)} 个 EA 共 {total:,} 字节，哈希全部一致")
    for e in out:
        log(f"    · {e['name']}  {len(e['plain']):,} 字节")
    if blocked:
        log(f"⚠ 服务端未下发 {len(blocked)} 个 EA：{'、'.join(blocked)}")
    return out, month, int(body.get("license_expires_at", 0)), blocked


def warn_if_expiring(cfg: dict, expires_at: int) -> None:
    if not expires_at:
        return
    days = (expires_at - int(time.time())) / 86400
    threshold = cfg.get("warn_days_before", 3)
    st = load_state()
    if days <= threshold and time.time() - int(st.get("last_warn", 0)) > 43200:
        st["last_warn"] = int(time.time())
        save_state(st)
        popup("授权即将到期",
              f"您的授权将在 {int(days)} 天后到期。\n到期后 EA 将无法启动，"
              f"请在「续期」程序里输入新的卡密。", "warn")


# ── 定位 MT5 ─────────────────────────────────────────────────────────
def find_terminal(cfg: dict) -> Path:
    """三路兜底：配置 → 常见安装路径 → 数据目录里的 origin.txt 反查。"""
    if cfg.get("terminal_path"):
        p = Path(cfg["terminal_path"])
        if p.is_file():
            return p
        log(f"⚠ 配置里的 terminal_path 不存在：{p}")

    drives = [f"{c}:\\" for c in "CDEFGH" if Path(f"{c}:\\").exists()]
    guesses = [
        "MetaTrader 5", "MT5", "Program Files\\MetaTrader 5", "Program Files (x86)\\MetaTrader 5",
        "Program Files\\MetaQuotes\\MetaTrader 5", "Program Files\\MetaQuotes\\Terminal",
        "Program Files\\FxPro - MetaTrader 5", "Program Files\\ICMarkets - MetaTrader 5",
        "Program Files\\XM Global MT5", "Program Files\\Alpari MT5",
        "Program Files\\Pepperstone MetaTrader 5", "Program Files\\Exness MetaTrader 5",
    ]
    for d in drives:
        for g in guesses:
            cand = Path(d) / g / MT5_EXE
            if cand.is_file():
                log(f"✓ 自动找到 MT5：{cand}")
                return cand

    for origin in (Path(os.environ.get("APPDATA", "")) / "MetaQuotes" / "Terminal").glob("*/origin.txt"):
        try:
            raw = origin.read_text(encoding="utf-16", errors="ignore").strip("\x00").strip()
            raw = raw or origin.read_text(encoding="utf-8", errors="ignore").strip()
            cand = Path(raw.strip('"')) / MT5_EXE
            if cand.is_file():
                log(f"✓ 由数据目录反查到 MT5：{cand}")
                return cand
        except Exception:
            continue

    fail("找不到 MetaTrader 5",
         f"请把 MT5 的安装路径填进 config.json 的 terminal_path。\n配置文件：{CONFIG_FILE}")


def _origin_of(inst: Path) -> str:
    origin = inst / "origin.txt"
    if not origin.is_file():
        return ""
    try:
        raw = origin.read_text(encoding="utf-16", errors="ignore").strip("\x00").strip()
        raw = raw or origin.read_text(encoding="utf-8", errors="ignore").strip()
        return raw.strip('"').rstrip("\\/").lower()
    except Exception:
        return ""


def find_experts_dir(cfg: dict, terminal: Path) -> Path:
    """定位 EA 真正的落点：MT5 的数据目录，而不是安装目录。"""
    if cfg.get("data_dir"):
        return Path(cfg["data_dir"]) / "MQL5" / "Experts"

    term_dir = terminal.parent
    if (term_dir / "MQL5" / "Experts").is_dir():
        log(f"✓ 数据目录（随安装目录）：{term_dir}")
        return term_dir / "MQL5" / "Experts"

    root = Path(os.environ.get("APPDATA", "")) / "MetaQuotes" / "Terminal"
    want = str(term_dir).rstrip("\\/").lower()
    fallback = None
    if root.is_dir():
        for inst in root.iterdir():
            if not (inst / "MQL5").is_dir():
                continue
            fallback = fallback or inst
            if _origin_of(inst) == want:
                log(f"✓ 匹配到数据目录：{inst}")
                return inst / "MQL5" / "Experts"
    if fallback:
        log(f"⚠ 未能精确匹配，使用数据目录：{fallback}")
        return fallback / "MQL5" / "Experts"

    fail("找不到 MT5 数据目录",
         "请在 config.json 里指定 data_dir。\n（在 MT5 里点「文件 → 打开数据文件夹」可查到）")


def mt5_running() -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {MT5_EXE}", "/FO", "CSV", "/NH"],
            capture_output=True, timeout=15, creationflags=NO_WINDOW,
        ).stdout.decode("gbk", "ignore")
        return MT5_EXE.lower() in out.lower()
    except Exception:
        return False


# ── 释放 / 看守 / 擦除 ───────────────────────────────────────────────
def release(plain: bytes, experts: Path, cfg: dict, name: str) -> Path:
    experts.mkdir(parents=True, exist_ok=True)
    target = experts / name
    if target.exists():
        try:
            os.chmod(target, 0o666)
        except Exception:
            pass
    target.write_bytes(plain)
    if cfg.get("readonly_lock"):
        try:
            os.chmod(target, 0o444)
        except Exception:
            pass
    log(f"✓ 已释放到 {target}")
    return target


def _kill(holder: dict) -> None:
    p = holder.get("proc")
    if p and p.poll() is None:
        subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                       capture_output=True, creationflags=NO_WINDOW)


def start_watchdog(targets: list[Path], cfg: dict, holder: dict) -> threading.Event:
    """监视这一批 EA 是否被替换/篡改。只比对大小与修改时间，避免频繁读盘。"""
    stop = threading.Event()
    sig0: dict[Path, tuple[int, int] | None] = {}
    for t in targets:
        try:
            s = t.stat()
            sig0[t] = (s.st_size, s.st_mtime_ns)
        except Exception:
            sig0[t] = None

    def run() -> None:
        while not stop.wait(int(cfg["watchdog_seconds"])):
            for t, base in sig0.items():
                try:
                    if not t.exists():
                        log(f"⚠ {t.name} 已消失 → 终止 MT5")
                        _kill(holder)
                        return
                    s = t.stat()
                    if base and (s.st_size, s.st_mtime_ns) != base:
                        log(f"⚠ {t.name} 被改动 → 立即终止 MT5")
                        _kill(holder)
                        return
                except Exception:
                    pass

    threading.Thread(target=run, daemon=True).start()
    return stop


def wipe(target: Path, passes: int) -> None:
    try:
        if not target.exists():
            return
        os.chmod(target, 0o666)
        size = target.stat().st_size
        with open(target, "r+b") as f:
            for _ in range(max(1, passes)):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        target.unlink()
        log("✓ 已擦除本地明文副本")
    except Exception as e:
        log(f"⚠ 擦除失败（请手动确认）：{e}")


# ── 续期 ─────────────────────────────────────────────────────────────
def do_redeem(cfg: dict) -> None:
    code = os.environ.get("MT5LIC_REDEEM_CODE") or ask_string("EA 授权续期", "请输入续期卡密：")
    if not code:
        log("用户取消续期")
        return
    try:
        r = post(cfg, "/redeem", {
            "license_key": cfg["license_key"],
            "fingerprint": device_fingerprint(),
            "code": code,
        })
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8"))
        except Exception:
            detail = {}
        popup("续期失败", detail.get("message") or f"服务器返回 {e.code}", "error")
        return
    except Exception as e:
        popup("续期失败", f"连不上授权服务器：\n{e}", "error")
        return
    popup("续期成功", r.get("message", "已续期"), "info")


def purge_unavailable(experts: Path, names: set[str], cfg: dict) -> None:
    """把本次不被授权、但可能还留在 MT5 目录里的 EA 抹掉。

    这是「单独停用某个 EA」真正生效的地方 —— 光不下发不够，
    已经释放到客户机上的文件必须一并清掉，否则它还能继续跑。
    """
    if not names:
        return
    for fn in sorted(names):
        p = experts / fn
        if not p.exists():
            continue
        try:
            wipe(p, cfg["wipe_passes"])
            log(f"✓ 已移除不可用的 EA：{fn}")
        except Exception as e:
            log(f"⚠ 无法移除 {fn}：{e}（请关闭 MT5 后重新启动本程序）")


# ── 主流程 ───────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-only", action="store_true", help="只验证不落盘")
    ap.add_argument("--dry-run", action="store_true", help="落盘但不启动 MT5")
    ap.add_argument("--keep", action="store_true", help="退出后不擦除（调试用）")
    ap.add_argument("--redeem", action="store_true", help="输入卡密续期")
    a = ap.parse_args()

    cfg = load_config()
    log(f"=== 启动 === 服务器 {cfg['server_url']}")

    if a.redeem:
        do_redeem(cfg)
        return

    body = acquire(cfg)
    eas, month, lic_exp, blocked = verify(body)
    warn_if_expiring(cfg, lic_exp)

    if a.check_only:
        log("✓ --check-only 结束：未落盘、未启动")
        return

    terminal = find_terminal(cfg)
    experts = find_experts_dir(cfg, terminal)
    log(f"→ MT5: {terminal}\n→ EA 目录: {experts}")

    if mt5_running() and not a.dry_run:
        popup("请先关闭 MT5",
              "检测到 MetaTrader 5 正在运行。\n\n请先关闭 MT5，再双击本程序，"
              "授权校验完成后 MT5 会自动启动。", "warn")
        log("MT5 正在运行，已退出（避免影响正在进行的交易）")
        return

    valid = {e["name"] for e in eas}
    st = load_state()
    stale = (set(blocked) | set(st.get("released") or [])) - valid
    purge_unavailable(experts, stale, cfg)

    targets = [release(e["plain"], experts, cfg, e["name"]) for e in eas]
    st["released"] = sorted(valid)
    st["last_run"] = int(time.time())
    save_state(st)
    log(f"✓ 本次共释放 {len(targets)} 个 EA")

    if a.dry_run:
        log("✓ --dry-run 结束：未启动 MT5")
        if not a.keep:
            for t in targets:
                wipe(t, cfg["wipe_passes"])
        return

    cmd = [str(terminal)]
    ini = HERE / "mt5.ini"
    if ini.is_file():
        cmd.append(f"/config:{ini}")
    holder: dict = {"proc": subprocess.Popen(cmd, cwd=str(terminal.parent))}
    log(f"✓ MT5 已启动 pid={holder['proc'].pid}，开始看守 {len(targets)} 个 EA")

    stop = start_watchdog(targets, cfg, holder)
    holder["proc"].wait()
    stop.set()
    log("MT5 已退出")
    if not a.keep:
        for t in targets:
            wipe(t, cfg["wipe_passes"])
    log("=== 结束 ===")


if __name__ == "__main__":
    main()
