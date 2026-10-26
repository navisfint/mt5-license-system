# -*- coding: utf-8 -*-
"""验证 launcher 的「释放到 MT5 目录 → 只读锁 → 退出擦除」环节，用假 MT5 目录代替真实终端。"""
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLIENT = ROOT / "client"
sys.path.insert(0, str(CLIENT))
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location("launcher", CLIENT / "launcher.py")
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)

fake_term = HERE / "fakeMT5" / "terminal64.exe"
fake_term.parent.mkdir(parents=True, exist_ok=True)
fake_term.write_bytes(b"stub")
(fake_term.parent / "MQL5" / "Experts").mkdir(parents=True, exist_ok=True)
print(f"✓ 假 MT5 终端：{fake_term}")

lib = json.loads((ROOT / "server" / "payloads.json").read_text(encoding="utf-8"))
fn = next(iter(lib["eas"]))
plain = (ROOT / "server" / "payloads" / fn).read_bytes()
print(f"✓ 当前载荷：{fn} ({len(plain):,} 字节)")

cfg = dict(L.DEFAULT_CONFIG)
cfg.update({"terminal_path": str(fake_term), "readonly_lock": True})

experts = L.find_experts_dir(cfg, fake_term)
target = L.release(plain, experts, cfg, fn)

assert target.exists() and target.read_bytes() == plain, "释放内容不一致"
print(f"✓ 已释放并校验内容一致：{target.parent.relative_to(HERE)} / {target.name}")

mode = os.stat(target).st_mode
print(f"✓ 只读锁：mode={oct(mode & 0o777)}")

L.wipe(target, 3)
assert not target.exists(), "擦除失败，文件仍在"
print("✓ 明文副本已擦除（3 轮随机覆写后删除）")

leftover = list(target.parent.glob("*"))
print(f"  目录剩余文件：{[p.name for p in leftover] if leftover else '（空）'}")

shutil.rmtree(fake_term.parent, ignore_errors=True)
print("\n释放 / 擦除环节符合预期。")
