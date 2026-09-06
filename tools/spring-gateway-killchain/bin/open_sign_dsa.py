#!/usr/bin/env python3
"""
DSA / RSA open-platform signing helper (authorized targets only).

Typical report patterns:
  - sign payload = merchant_id
  - or merchant_id + merchant_order_no
  - algorithm DSA / SHA1withDSA (legacy) or SHA256withRSA

Requires: pip install cryptography
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path


def load_key(pem: str):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(pem.encode() if isinstance(pem, str) else pem, password=None)


def sign_dsa(priv, payload: bytes) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils
    from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey

    if not isinstance(priv, DSAPrivateKey):
        raise TypeError("key is not DSA")
    sig = priv.sign(payload, hashes.SHA1())
    return base64.b64encode(sig).decode()


def sign_rsa(priv, payload: bytes, sha: str = "sha256") -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    if not isinstance(priv, RSAPrivateKey):
        raise TypeError("key is not RSA")
    h = hashes.SHA256() if sha == "sha256" else hashes.SHA1()
    sig = priv.sign(payload, padding.PKCS1v15(), h)
    return base64.b64encode(sig).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="PEM private key file or inline PEM string")
    ap.add_argument("--payload", required=True, help="string to sign (e.g. merchant_id)")
    ap.add_argument("--algo", choices=["dsa", "rsa-sha256", "rsa-sha1"], default="dsa")
    ap.add_argument("--hex", action="store_true", help="also print sha1 of payload")
    args = ap.parse_args()

    raw = args.key
    if Path(raw).is_file():
        pem = Path(raw).read_text(encoding="utf-8")
    else:
        pem = raw.replace("\\n", "\n")
    try:
        priv = load_key(pem)
    except Exception as e:
        print(f"load key failed: {e}", file=sys.stderr)
        raise SystemExit(1)

    data = args.payload.encode("utf-8")
    if args.hex:
        print("sha1=", hashlib.sha1(data).hexdigest())
    if args.algo == "dsa":
        print(sign_dsa(priv, data))
    elif args.algo == "rsa-sha256":
        print(sign_rsa(priv, data, "sha256"))
    else:
        print(sign_rsa(priv, data, "sha1"))


if __name__ == "__main__":
    main()
