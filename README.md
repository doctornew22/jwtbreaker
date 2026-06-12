# JWTBreaker CLI 🔐 – Real JWT Attack Generator

**JWTBreaker CLI** is a powerful penetration testing tool that exploits real-world JWT (JSON Web Token) vulnerabilities to generate **100% valid, correctly signed attack tokens**. It doesn't just decode tokens; it creates **executable payloads** ready to be pasted directly into Burp Suite, Repeater, or any HTTP tool.

This tool covers a wide range of attacks including **offline secret cracking, JWK embedding, JKU injection, Kid header path traversal, algorithm confusion (RS256→HS256)**, and more.

---

## ✨ Features

| # | Attack | Description |
| :--- | :--- | :--- |
| 1 | `alg: none` | Bypass signature verification by modifying the `alg` header |
| 2 | `RS256 → HS256` (Key Confusion) | Sign with the server's public key using HS256 |
| 3 | `Kid Header Injection` | Force an empty secret by pointing `kid` to `../../../../dev/null` |
| 4 | `JWK Embed` (Most Powerful) | Generate your own RSA keypair, embed the public key in the `jwk` header, and sign |
| 5 | `JKU Injection` | Use the `jku` header to force the server to fetch a malicious JWKS (Open Redirect/SSRF) |
| 6 | `Payload Manipulation` | Modify claims like `sub`, `role`, `email`, `admin`, `exp` and re-sign |
| 7 | `Expiry Bypass` | Increase or remove the `exp` (expiration) claim |
| 8 | `Offline Secret Cracking` | Brute-force HS256 secrets using a wordlist (no network traffic) |
| 9 | `JSON Output` | Output in JSON format for automation |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/jwtbreaker.git
cd jwtbreaker

# Install required library
pip install -r requirements.txt
```

---

🚀 Quick Usage

1. Powerful JWK Embed Attack (jwk_embed)

```bash
python jwtbreaker.py --token "eyJhbGc..." --attack jwk_embed --victim "administrator"
```

2. Change sub without knowing the secret (for labs)

python jwtbreaker.py --token "eyJ..." --attack payload --victim "administrator"

3. Crack a weak secret

python jwtbreaker.py --token "eyJ..." --crack /usr/share/wordlists/rockyou.txt

✅ If successful, the tool will automatically use the found secret as --secret.

4. Kid Path Traversal (Null Secret)

python jwtbreaker.py --token "eyJ..." --attack kid --victim "administrator"

5. JKU Injection (requires your exploit server)

python jwtbreaker.py --token "eyJ..." --attack jku --jku-url "http://your-exploit-server.net/jwks.json" --victim "administrator"


---

🧠 Attack Reference

Attack Name Command Requirements
alg:none --attack alg_none None
RS256→HS256 --attack rs_to_hs --pubkey public.pem Public key PEM file
Kid Injection --attack kid None (automatically uses /dev/null)
JWK Embed --attack jwk_embed None (auto-generates RSA keypair)
JKU Injection --attack jku --jku-url "URL" Exploit server URL
Payload Modify --attack payload --victim "admin" --secret to re-sign
Expiry --attack expiry --secret to re-sign
All in one --attack all --victim "admin" Modifies both payload and headers

---

🧪 Real Lab Examples

Example 1: PortSwigger Lab – JWT authentication bypass via jwk header injection

python jwtbreaker.py --token "eyJ..." --attack all --victim "administrator"


✅ Copy the token from the JWK HEADER EMBED (self-signed) section and paste it into /admin.

Example 2: Lab – JWT authentication bypass via weak signing key

python jwtbreaker.py --token "eyJ..." --crack /usr/share/wordlists/rockyou.txt
python jwtbreaker.py --token "eyJ..." --attack payload --victim "administrator" --secret "found_secret"

Example 3: Lab – JWT authentication bypass via kid header path traversal

python jwtbreaker.py --token "eyJ..." --attack kid --victim "administrator"


✅ Use the first token from the KID HEADER INJECTION section (with kid="../../../../dev/null").

---

📝 How to Identify the Correct Token

Output Section Label Use Case
ALG:NONE ATTACK Legacy labs where alg:none works
RS256 → HS256 KEY CONFUSION Server uses RS256 and you have the public key
KID HEADER INJECTION kid path traversal (e.g., /dev/null)
JWK HEADER EMBED (self-signed) Most common for jwk embed labs
JKU INJECTION For JKU labs (also provides the JWKS document)
PAYLOAD MANIPULATION Just payload modification (requires secret to re-sign)

💡 Best Practice: Run --attack all --victim "administrator" once to see all possible outputs and easily identify which one works.

---

🔧 Full Argument Reference

Argument Type Description
--token  Required The JWT token to attack (eyJ...)
--attack  alg_none, rs_to_hs, kid, jwk_embed, jku, payload, expiry, all Attack type
--secret  String Known secret (to re-sign modified payloads)
--crack  File Path Wordlist file for brute-forcing the secret
--pubkey  File Path Public key PEM file (for RS256→HS256)
--jku-url  URL URL where your JWKS is hosted (for JKU attack)
--victim  String Value for the sub claim (default: victim@target.com)
--admin  String Value for the role claim (default: admin)
--json  Flag Output in JSON format (for automation)

---

⚠️ Disclaimer

This tool is for educational purposes, authorized penetration testing, and CTF challenges only. Attacking any server without explicit permission is illegal. The author is not responsible for any misuse of this tool.