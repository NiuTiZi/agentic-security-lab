"""Agent 服务的 OAuth 令牌客户端：client_credentials 取令牌并缓存续期。"""
import time

import httpx

from . import config


class TokenFetchError(RuntimeError):
    pass


class AgentTokenClient:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self._cache: dict[str, tuple[str, float]] = {}

    def get_token(self, scopes: list[str]) -> tuple[str, str]:
        """返回 (access_token, 来源)，来源为 fetched/cache。"""
        scope = " ".join(sorted(set(scopes)))
        now = time.time()
        hit = self._cache.get(scope)
        if hit and hit[1] - 30 > now:
            return hit[0], "cache"
        with httpx.Client(timeout=15, trust_env=False) as c:
            r = c.post(
                config.TOKEN_ENDPOINT,
                auth=(self.client_id, self.client_secret),
                data={"grant_type": "client_credentials", "scope": scope},
            )
        if r.status_code != 200:
            raise TokenFetchError(f"客户端认证失败 HTTP {r.status_code}: {r.text[:120]}")
        j = r.json()
        token = j["access_token"]
        self._cache[scope] = (token, now + int(j.get("expires_in", 300)))
        return token, "fetched"
