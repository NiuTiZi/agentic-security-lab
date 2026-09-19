"""初始化 Keycloak realm 与两个 Agent 客户端（幂等）。

用法:
    .venv\\Scripts\\python.exe scripts\\setup_keycloak.py

前置:
    1. Keycloak 已由 scripts\\start-keycloak.ps1 启动
    2. .env 中 KC_ADMIN_USERNAME / KC_ADMIN_PASSWORD 可登录 master realm

行为:
    - 创建 realm agent-range（访问令牌有效期 300 秒）
    - 创建业务 client scope: order.read / docs.read / refund.delegate / refund.execute
    - 注册两个机密客户端（仅 client_credentials 流程）:
        customer-service-agent -> 可选 scope: order.read docs.read refund.delegate
        refund-agent           -> 可选 scope: refund.execute
      业务 scope 设为可选而非默认，Agent 取令牌时按需申请，未申请的不进令牌。
    - 为两个客户端添加 audience 协议映射（aud -> tools-service）
    - .env 中客户端密钥为占位符(changeme)时生成随机密钥并写回
"""
import os
import re
import secrets
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

KC_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "agent-range")
ADMIN_USER = os.environ.get("KC_ADMIN_USERNAME", "range-admin")
ADMIN_PASS = os.environ.get("KC_ADMIN_PASSWORD", "")
TOOLS_AUDIENCE = os.environ.get("TOOLS_AUDIENCE", "tools-service")

AGENT_CLIENTS = {
    "customer-service-agent": {
        "secret_env": "CUSTOMER_AGENT_CLIENT_SECRET",
        # message.send 为实验性出站权限（需求稿6.5：按实验配置单独授予）；
        # 应用侧由任务授权约束：用户需 message.send 任务才能实际发送
        "scopes": ["order.read", "docs.read", "refund.delegate", "message.send"],
    },
    "refund-agent": {
        "secret_env": "REFUND_AGENT_CLIENT_SECRET",
        "scopes": ["refund.execute"],
    },
}
ALL_SCOPES = ["order.read", "docs.read", "refund.delegate", "refund.execute", "message.send"]


def admin_login(c: httpx.Client) -> str:
    r = c.post(
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
        },
        timeout=30,
    )
    if r.status_code != 200:
        sys.exit(f"[setup] 管理员登录失败 HTTP {r.status_code}: {r.text[:200]}")
    return r.json()["access_token"]


def update_env_value(env_path: Path, key: str, value: str) -> None:
    lines = env_path.read_text(encoding="utf-8").splitlines()
    out, replaced = [], False
    for line in lines:
        if re.match(rf"^\s*{re.escape(key)}\s*=", line):
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key}={value}")
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> None:
    if not ADMIN_PASS:
        sys.exit("[setup] .env 缺少 KC_ADMIN_PASSWORD")

    with httpx.Client(timeout=30, trust_env=False) as c:
        tok = admin_login(c)
        h = {"Authorization": f"Bearer {tok}"}
        base = f"{KC_URL}/admin/realms"

        # --- realm ---
        r = c.get(f"{base}/{REALM}", headers=h)
        if r.status_code == 404:
            r = c.post(base, headers=h, json={"realm": REALM, "enabled": True, "accessTokenLifespan": 300})
            r.raise_for_status()
            print(f"[setup] realm 已创建: {REALM} (accessTokenLifespan=300s)")
        elif r.status_code == 200:
            rep = r.json()
            rep["accessTokenLifespan"] = 300
            c.put(f"{base}/{REALM}", headers=h, json=rep).raise_for_status()
            print(f"[setup] realm 已存在，令牌有效期固定为 300s: {REALM}")
        else:
            r.raise_for_status()

        # --- client scopes ---
        scope_ids = {}
        for name in ALL_SCOPES:
            r = c.get(f"{base}/{REALM}/client-scopes", headers=h)
            r.raise_for_status()
            existing = {s["name"]: s["id"] for s in r.json()}
            if name not in existing:
                r = c.post(
                    f"{base}/{REALM}/client-scopes",
                    headers=h,
                    json={
                        "name": name,
                        "protocol": "openid-connect",
                        "attributes": {
                            "include.in.token.scope": "true",
                            "display.on.consent.screen": "false",
                        },
                    },
                )
                r.raise_for_status()
                print(f"[setup] client scope 已创建: {name}")
            r = c.get(f"{base}/{REALM}/client-scopes", headers=h)
            scope_ids = {s["name"]: s["id"] for s in r.json()}

        # --- clients ---
        for client_id, spec in AGENT_CLIENTS.items():
            secret = os.environ.get(spec["secret_env"], "")
            generated = False
            if not secret or secret == "changeme":
                secret = secrets.token_hex(20)
                generated = True

            r = c.get(f"{base}/{REALM}/clients", headers=h, params={"clientId": client_id})
            r.raise_for_status()
            matches = r.json()
            if matches:
                cid = matches[0]["id"]
                rep = matches[0]
                rep.update({
                    "secret": secret,
                    "enabled": True,
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": False,
                    "directAccessGrantsEnabled": False,
                    "publicClient": False,
                })
                c.put(f"{base}/{REALM}/clients/{cid}", headers=h, json=rep).raise_for_status()
                print(f"[setup] 客户端已存在并更新: {client_id}")
            else:
                r = c.post(
                    f"{base}/{REALM}/clients",
                    headers=h,
                    json={
                        "clientId": client_id,
                        "name": client_id,
                        "description": f"靶场服务端 Agent: {client_id}",
                        "enabled": True,
                        "protocol": "openid-connect",
                        "publicClient": False,
                        "serviceAccountsEnabled": True,
                        "standardFlowEnabled": False,
                        "directAccessGrantsEnabled": False,
                        "secret": secret,
                    },
                )
                r.raise_for_status()
                loc = r.headers.get("Location", "")
                cid = loc.rstrip("/").split("/")[-1]
                print(f"[setup] 客户端已创建: {client_id}")

            # 业务 scope 挂为可选（按需申请）
            r = c.get(f"{base}/{REALM}/clients/{cid}/optional-client-scopes", headers=h)
            r.raise_for_status()
            current_opt = {s["name"] for s in r.json()}
            for sc in spec["scopes"]:
                if sc not in current_opt:
                    c.put(f"{base}/{REALM}/clients/{cid}/optional-client-scopes/{scope_ids[sc]}", headers=h).raise_for_status()
            # 确保业务 scope 不在默认列表（默认=必授，与按需申请模型冲突）
            r = c.get(f"{base}/{REALM}/clients/{cid}/default-client-scopes", headers=h)
            r.raise_for_status()
            for s in r.json():
                if s["name"] in ALL_SCOPES:
                    c.delete(f"{base}/{REALM}/clients/{cid}/default-client-scopes/{s['id']}", headers=h).raise_for_status()
                    print(f"[setup] 已从默认 scope 移除: {client_id} / {s['name']}")

            # audience 映射
            r = c.get(f"{base}/{REALM}/clients/{cid}/protocol-mappers/models", headers=h)
            r.raise_for_status()
            mapper_names = {m["name"] for m in r.json()}
            if f"aud-{TOOLS_AUDIENCE}" not in mapper_names:
                c.post(
                    f"{base}/{REALM}/clients/{cid}/protocol-mappers/models",
                    headers=h,
                    json={
                        "name": f"aud-{TOOLS_AUDIENCE}",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.client.audience": TOOLS_AUDIENCE,
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                            "lightweight.claim": "false",
                        },
                    },
                ).raise_for_status()
                print(f"[setup] audience 映射已添加: {client_id} -> {TOOLS_AUDIENCE}")

            if generated:
                update_env_value(ROOT / ".env", spec["secret_env"], secret)
                print(f"[setup] 已生成随机密钥并写回 .env: {spec['secret_env']}")

    print("[setup] 完成")


if __name__ == "__main__":
    main()
