# -*- coding: utf-8 -*-
"""服务端拒绝逻辑自测：吊销 / 不存在 / 换机 / 正常。需要 server.py 已在 8787 监听。"""
import json
import sys
import urllib.error
import urllib.request

URL = "http://127.0.0.1:8787/license"


def call(key: str, fp: str):
    req = urllib.request.Request(
        URL, data=json.dumps({"license_key": key, "fingerprint": fp}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


cases = [
    ("已吊销的授权", "EA-REV-001", "fp-aaa", 403, "license_revoked"),
    ("不存在的授权码", "EA-NOT-EXIST", "fp-aaa", 403, "license_not_found"),
    ("换了一台机器", "EA-ABC-001", "fp-other-machine", 403, "fingerprint_mismatch"),
]

ok = True
for name, key, fp, want_code, want_err in cases:
    code, body = call(key, fp)
    good = code == want_code and body.get("error") == want_err
    ok &= good
    print(f"{'✓' if good else '✗'} {name:<16} HTTP {code}  {body.get('error')}  {body.get('message')}")

code, body = call("EA-ABC-001", "fp-other-machine")
print()
print("说明：以上均为「应当拒绝」的路径；正常放行路径见 launcher.py --check-only。")
sys.exit(0 if ok else 1)
