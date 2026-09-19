"""JWT 访问令牌校验：JWKS 来自固定可信配置，按固定顺序报告首个失败层。

校验顺序: 签名/alg/typ -> iss -> aud -> exp（含时钟误差）。
任何失败抛 TokenError(code, message)，由调用方映射为认证错误。
"""
import time

import jwt
from jwt import PyJWKClient

from . import config

_jwks_client: PyJWKClient | None = None


class TokenError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _jwks() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(config.JWKS_URL, cache_keys=True)
    return _jwks_client


def verify_agent_token(token: str, audience: str | None = None) -> dict:
    audience = audience or config.TOOLS_AUDIENCE
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise TokenError("invalid_token", "令牌格式无效")
    if header.get("alg") != "RS256":
        raise TokenError("alg_not_allowed", f"签名算法不被允许: {header.get('alg')}")
    typ = header.get("typ")
    if typ is not None and typ not in ("JWT", "at+jwt"):
        raise TokenError("typ_not_allowed", f"令牌类型不允许: {typ}")
    try:
        key = _jwks().get_signing_key_from_jwt(token)
    except jwt.exceptions.PyJWKClientError:
        raise TokenError("unknown_signing_key", "签名密钥不属于可信签发方（可信 JWKS 中无此密钥）")
    except Exception:
        raise TokenError("jwks_unavailable", "可信公钥获取失败，拒绝执行")
    try:
        claims = jwt.decode(
            token, key.key, algorithms=["RS256"],
            options={
                "verify_exp": False, "verify_iss": False, "verify_aud": False,
                "require": ["exp", "iat", "iss", "sub", "aud"],
            },
        )
    except jwt.exceptions.InvalidSignatureError:
        raise TokenError("invalid_signature", "签名验证失败（令牌可能被篡改）")
    except jwt.exceptions.DecodeError:
        raise TokenError("invalid_token", "令牌解析失败")
    except Exception as e:
        raise TokenError("invalid_signature", f"签名验证失败: {type(e).__name__}")
    if claims.get("iss") != config.ISSUER:
        raise TokenError("issuer_mismatch", f"签发方不匹配: {claims.get('iss')}")
    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if audience not in aud_list:
        raise TokenError("audience_mismatch", f"目标服务不匹配: {aud}")
    if int(claims.get("exp", 0)) <= time.time() + config.CLOCK_SKEW_SECONDS:
        raise TokenError("token_expired", "令牌已过期")
    return claims


def token_scopes(claims: dict) -> set:
    return set((claims.get("scope") or "").split())
