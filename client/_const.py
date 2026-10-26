# -*- coding: utf-8 -*-
"""由 pack_tool.py client-const 自动生成 —— 请勿手改。

   本文件是唯一允许出现在终端机器上的密钥相关材料：
   公钥只能验签，ex5 的 SHA-256 不是秘密。两者泄露均无害。

   ★ 本仓库为公开示例版，下面的公钥是占位值，不含任何真实密钥。
     实际使用时用 pack_tool.py 从你自己的 Ed25519 公钥重新生成此文件。
"""
SERVER_PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----"""

# 版本策略：跟随服务端签名响应 → 换 payload 只需 publish，无需重发 exe
PIN_PAYLOAD = False
PAYLOAD_NAME = ""
EXPECTED_SHA256 = ""
