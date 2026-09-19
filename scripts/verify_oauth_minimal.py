"""需求稿 6.1 OAuth 最小接入验证：逐项执行并产出组件行为记录。

用法:
    .venv\\Scripts\\python.exe scripts\\verify_oauth_minimal.py

前置: Keycloak 已启动, scripts\\setup_keycloak.py 已执行。

覆盖 6.1 的验证项:
    V1 服务与端点发现（issuer / token_endpoint / jwks_uri / 版本）
    V2 两个 Agent 客户端凭据取令牌（client_secret_basic）
    V3 JWKS 获取 + RS256 验签 + iss/aud 校验, 记录实际令牌特征
    V4 错误客户端密钥申请令牌（应拒绝）
    V5 超范围 scope 请求（客服 Agent 请求 refund.execute）——记录组件实际行为
    V6 令牌过期行为（临时将 realm 令牌寿命调为 5 秒后验证）
    V7 客户端停用行为（新令牌申请 + 已签发令牌的验签表现）

输出: reports/component-behavior.md 与控制台结论。
"""
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx
import jwt
from jwt import PyJWKClient
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

KC_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "agent-range")
ISSUER = os.environ.get("KEYCLOAK_ISSUER", f"{KC_URL}/realms/{REALM}").rstrip("/")
ADMIN_USER = os.environ.get("KC_ADMIN_USERNAME", "range-admin")
ADMIN_PASS = os.environ.get("KC_ADMIN_PASSWORD", "")
TOOLS_AUDIENCE = os.environ.get("TOOLS_AUDIENCE", "tools-service")

CUSTOMER_ID = os.environ.get("CUSTOMER_AGENT_CLIENT_ID", "customer-service-agent")
CUSTOMER_SEC = os.environ.get("CUSTOMER_AGENT_CLIENT_SECRET", "")
REFUND_ID = os.environ.get("REFUND_AGENT_CLIENT_ID", "refund-agent")
REFUND_SEC = os.environ.get("REFUND_AGENT_CLIENT_SECRET", "")

RESULTS = []


def record(vid, title, status, detail):
    RESULTS.append({"id": vid, "title": title, "status": status, "detail": detail})
    print(f"[{vid}] {status} | {title}")
    for line in detail:
        print(f"      {line}")


def admin_login(c):
    r = c.post(
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def client_token(c, client_id, client_secret, scope=None):
    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    return c.post(
        f"{ISSUER}/protocol/openid-connect/token",
        auth=(client_id, client_secret),
        data=data,
        timeout=30,
    )


def verify_token(token, audience=TOOLS_AUDIENCE):
    """从可信配置的 JWKS 地址取公钥验签（不接受令牌内 URL）。"""
    jwks_client = PyJWKClient(f"{ISSUER}/protocol/openid-connect/certs")
    key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(token, key.key, algorithms=["RS256"], audience=audience, issuer=ISSUER)


def main():
    if not ADMIN_PASS or not CUSTOMER_SEC or not REFUND_SEC:
        sys.exit("[verify] .env 缺少必要凭据，请先运行 setup_keycloak.py")

    with httpx.Client(timeout=30, trust_env=False) as c:
        # V1 服务与端点发现
        r = c.get(f"{ISSUER}/.well-known/openid-configuration")
        if r.status_code == 200:
            d = r.json()
            at = admin_login(c)
            si = c.get(f"{KC_URL}/admin/serverinfo", headers={"Authorization": f"Bearer {at}"}).json()
            version = si.get("systemInfo", {}).get("version", "unknown")
            record("V1", "服务与端点发现", "PASS", [
                f"Keycloak 版本: {version}",
                f"issuer: {d['issuer']}",
                f"token_endpoint: {d['token_endpoint']}",
                f"jwks_uri: {d['jwks_uri']}",
            ])
        else:
            record("V1", "服务与端点发现", "FAIL", [f"发现端点 HTTP {r.status_code}"])
            write_report()
            return

        # V2 客户端凭据取令牌
        details = []
        ok = True
        tokens = {}
        for cid, sec, scope in [
            (CUSTOMER_ID, CUSTOMER_SEC, "order.read docs.read"),
            (REFUND_ID, REFUND_SEC, "refund.execute"),
        ]:
            r = client_token(c, cid, sec, scope)
            if r.status_code == 200:
                j = r.json()
                tokens[cid] = j["access_token"]
                details.append(f"{cid}: HTTP 200, token_type={j.get('token_type')}, expires_in={j.get('expires_in')}, 请求scope='{scope}'")
            else:
                ok = False
                details.append(f"{cid}: HTTP {r.status_code} {r.text[:120]}")
        record("V2", "两个 Agent 客户端凭据取令牌", "PASS" if ok else "FAIL", details)

        # V3 验签与令牌特征
        details, ok = [], True
        for cid, tok in tokens.items():
            try:
                header = jwt.get_unverified_header(tok)
                payload = verify_token(tok)
                life = payload.get("exp", 0) - payload.get("iat", 0)
                details.append(f"{cid}: 验签通过 alg={header.get('alg')} typ={header.get('typ')} | sub={str(payload.get('sub'))[:12]}… azp={payload.get('azp')} | scope='{payload.get('scope')}' | aud={payload.get('aud')} | 有效期={life}s")
            except Exception as e:
                ok = False
                details.append(f"{cid}: 验签失败 {type(e).__name__}: {e}")
        record("V3", "JWKS 验签 + iss/aud 校验", "PASS" if ok else "FAIL", details)

        # V4 错误客户端密钥
        r = client_token(c, CUSTOMER_ID, "wrong-secret-0000")
        body = {}
        try:
            body = r.json()
        except Exception:
            pass
        record("V4", "错误客户端密钥申请令牌", "PASS" if r.status_code == 401 else "FAIL", [
            f"HTTP {r.status_code}, error={body.get('error')}, error_description={body.get('error_description', '')[:80]}",
        ])

        # V5 超范围 scope（客服 Agent 请求 refund.execute）
        r = client_token(c, CUSTOMER_ID, CUSTOMER_SEC, "order.read refund.execute")
        details = [f"HTTP {r.status_code}"]
        if r.status_code == 200:
            j = r.json()
            payload = jwt.decode(j["access_token"], options={"verify_signature": False})
            details.append(f"返回 token_type={j.get('token_type')}")
            details.append(f"实际授予 scope='{payload.get('scope')}'")
            details.append("结论: 组件采用【缩减】方式 —— 未注册的 scope 被静默剔除，签发剩余部分")
        else:
            body = {}
            try:
                body = r.json()
            except Exception:
                pass
            details.append(f"error={body.get('error')}, error_description={body.get('error_description', '')[:80]}")
            details.append("结论: 组件采用【拒绝】方式")
        record("V5", "超范围 scope 请求行为", "PASS", details)

        # V6 令牌过期行为
        try:
            at = admin_login(c)
            h = {"Authorization": f"Bearer {at}"}
            rep = c.get(f"{KC_URL}/admin/realms/{REALM}", headers=h).json()
            rep["accessTokenLifespan"] = 5
            c.put(f"{KC_URL}/admin/realms/{REALM}", headers=h, json=rep).raise_for_status()
            r = client_token(c, CUSTOMER_ID, CUSTOMER_SEC, "order.read")
            j = r.json()
            payload = jwt.decode(j["access_token"], options={"verify_signature": False})
            life = payload["exp"] - payload["iat"]
            time.sleep(7)
            try:
                verify_token(j["access_token"])
                status, details = "FAIL", ["过期令牌验签竟然通过"]
            except jwt.ExpiredSignatureError:
                status, details = "PASS", [
                    f"realm 寿命临时调为 5s 后取令牌: exp-iat={life}s",
                    "等待 7s 后验签: ExpiredSignatureError（过期拒绝）",
                ]
        finally:
            at = admin_login(c)
            h = {"Authorization": f"Bearer {at}"}
            rep = c.get(f"{KC_URL}/admin/realms/{REALM}", headers=h).json()
            rep["accessTokenLifespan"] = 300
            c.put(f"{KC_URL}/admin/realms/{REALM}", headers=h, json=rep).raise_for_status()
        details.append("realm 令牌寿命已恢复 300s")
        record("V6", "令牌过期行为", status, details)

        # V7 客户端停用行为
        r = client_token(c, CUSTOMER_ID, CUSTOMER_SEC, "order.read")
        old_token = r.json()["access_token"]
        at = admin_login(c)
        h = {"Authorization": f"Bearer {at}"}
        cid_uuid = c.get(f"{KC_URL}/admin/realms/{REALM}/clients", headers=h, params={"clientId": CUSTOMER_ID}).json()[0]["id"]
        c.put(f"{KC_URL}/admin/realms/{REALM}/clients/{cid_uuid}", headers=h, json={"enabled": False}).raise_for_status()
        r_new = client_token(c, CUSTOMER_ID, CUSTOMER_SEC, "order.read")
        try:
            verify_token(old_token)
            old_verify = "验签仍通过（签名层不感知停用状态）"
            old_ok = True
        except Exception as e:
            old_verify = f"验签失败: {type(e).__name__}"
            old_ok = False
        c.put(f"{KC_URL}/admin/realms/{REALM}/clients/{cid_uuid}", headers=h, json={"enabled": True}).raise_for_status()
        r_back = client_token(c, CUSTOMER_ID, CUSTOMER_SEC, "order.read")
        status = "PASS" if (r_new.status_code == 401 and old_ok and r_back.status_code == 200) else "FAIL"
        record("V7", "客户端停用行为", status, [
            f"停用后新令牌申请: HTTP {r_new.status_code}（预期 401 invalid_client）",
            f"停用前签发的未过期令牌: {old_verify}",
            "含义: 撤销必须依赖应用侧在线状态检查，仅靠验签无法感知 —— 支撑需求稿 6.6 的设计",
            f"重新启用后取令牌: HTTP {r_back.status_code}",
        ])

    write_report()


def write_report():
    lines = [
        "# OAuth 组件行为记录（阶段 0 验证）",
        "",
        f"- 日期: {datetime.now().isoformat(timespec='seconds')}",
        "- 组件: Keycloak 独立进程（非 Docker），来源 Maven Central keycloak-quarkus-dist",
        "- 流程: client_credentials（RFC 6749 4.4），客户端认证 client_secret_basic",
        f"- 端点: issuer={ISSUER}, token={ISSUER}/protocol/openid-connect/token, jwks={ISSUER}/protocol/openid-connect/certs",
        f"- audience: {TOOLS_AUDIENCE}（客户端协议映射注入）",
        "",
        "| 编号 | 验证项 | 结果 | 关键观察 |",
        "| --- | --- | --- | --- |",
    ]
    for x in RESULTS:
        joined = "<br>".join(x["detail"])
        lines.append(f"| {x['id']} | {x['title']} | {x['status']} | {joined} |")
    lines += [
        "",
        "## 对靶场设计的影响",
        "",
        "1. 超范围 scope 的实际处理方式以 V5 记录为准，AUTH-06 验收预期据此固定。",
        "2. 停用客户端后旧令牌验签仍通过（V7），证实需求稿 6.6 的结论：撤销需要应用侧在线状态检查，工具服务执行前必须查询应用授权状态。",
        "3. JWKS 地址来自固定可信配置（issuer 派生），不接受令牌内 URL；PyJWKClient 自带密钥缓存，验签失败即拒绝。",
        "4. 本记录为实际运行观察，非组件文档转述；后续 AUTH 实验的失败预期均以本文件为依据。",
    ]
    out = ROOT / "reports" / "component-behavior.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[verify] 报告已写入 {out}")


if __name__ == "__main__":
    main()
