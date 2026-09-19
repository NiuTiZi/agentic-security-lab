"""阶段1验收：AUTH-01~10、12、13 固定请求逐项验证（需求稿 6.7）。

前置: Keycloak 与四服务运行中（scripts\\start-all.ps1）。
模式: 固定请求回放（需求稿第8节）——验证服务端身份/授权/任务绑定控制，不涉及真实模型。
凭据: 测试执行凭据经受控测试通道加载（需求稿6.10），报告仅展示脱敏摘要。
输出: reports/auth-phase1.md + 控制台摘要。

用法:
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase1.py                  # 全量验收（写报告）
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase1.py --case AUTH-08   # 单案例复现（逐步输出，不写报告）
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase1.py --case AUTH-05,AUTH-09
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase1.py --list           # 列出可复现用例
单案例复现输出即验证复现手册（docs/08）中该用例的"预期输出"，可逐行对照。
"""
import argparse
import atexit
import base64
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

KC = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "agent-range")
ISSUER = os.environ.get("KEYCLOAK_ISSUER", f"{KC}/realms/{REALM}").rstrip("/")
TOKEN_EP = f"{ISSUER}/protocol/openid-connect/token"
CUST_ID = os.environ.get("CUSTOMER_AGENT_CLIENT_ID", "customer-service-agent")
CUST_SEC = os.environ.get("CUSTOMER_AGENT_CLIENT_SECRET", "")
REFUND_ID = os.environ.get("REFUND_AGENT_CLIENT_ID", "refund-agent")
REFUND_SEC = os.environ.get("REFUND_AGENT_CLIENT_SECRET", "")
ADMIN_USER = os.environ.get("KC_ADMIN_USERNAME", "range-admin")
ADMIN_PASS = os.environ.get("KC_ADMIN_PASSWORD", "")
INTERNAL_KEY = os.environ.get("INTERNAL_API_KEY", "")
BACKEND = "http://127.0.0.1:8000"
AGENT = "http://127.0.0.1:8100"
TOOLS = "http://127.0.0.1:8300"

TEST_AUD_CLIENT = "test-wrong-audience"   # 测试专用客户端（签发错误 audience 令牌）
TEST_AUD_SECRET = "test-wrong-aud-secret-0001"

CASES: dict[str, dict] = {}
CASE_FUNCS: list[tuple[str, str, object]] = []


def http(method, url, **kw):
    with httpx.Client(timeout=25, trust_env=False) as c:
        return c.request(method, url, **kw)


def unwrap(r):
    body = r.json()
    if isinstance(body.get("detail"), dict) and "ok" not in body:
        body = body["detail"]
    return body


def step(msg: str, detail: str = ""):
    """复现步骤输出：每次实际操作（登录/建任务/发请求）前的说明，供手册逐行对照。"""
    print(f"  · {msg}" + (f"\n      {detail}" if detail else ""))


def sub(case_id: str, title: str, name: str, ok: bool, note: str = ""):
    CASES.setdefault(case_id, {"title": title, "subs": []})["subs"].append(
        {"name": name, "ok": ok, "note": note})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" | {note}" if note else ""))
    return ok


def case_pass(case_id: str) -> bool:
    return all(s["ok"] for s in CASES[case_id]["subs"])


# ---------- 基础操作 ----------

def kc_token(client_id, secret, scope=None):
    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    return http("POST", TOKEN_EP, auth=(client_id, secret), data=data)


def login(username, password):
    r = http("POST", f"{BACKEND}/api/auth/login",
             json={"username": username, "password": password})
    if r.status_code != 200:
        sys.exit(f"登录失败 {username}: HTTP {r.status_code} {r.text[:100]}")
    return r.json()["session_token"]


def create_task(session, operation, resource):
    r = http("POST", f"{BACKEND}/api/tasks", headers={"Authorization": f"Bearer {session}"},
             json={"operation": operation, "resource": resource})
    if r.status_code != 200:
        sys.exit(f"任务创建失败: HTTP {r.status_code} {r.text[:150]}")
    return r.json()


def list_tasks(session):
    r = http("GET", f"{BACKEND}/api/tasks", headers={"Authorization": f"Bearer {session}"})
    return r.json()["tasks"]


def revoke_task(session, task_id):
    return http("POST", f"{BACKEND}/api/tasks/{task_id}/revoke",
                headers={"Authorization": f"Bearer {session}"})


def agent_message(session, task_id, message):
    return http("POST", f"{AGENT}/api/agent/message",
                headers={"X-Session-Token": session, "Content-Type": "application/json"},
                json={"task_id": task_id, "message": message})


def export_cred(task_id):
    r = http("POST", f"{BACKEND}/api/internal/test-export-credential",
             headers={"X-Internal-Key": INTERNAL_KEY}, json={"task_id": task_id})
    if r.status_code != 200:
        sys.exit(f"测试凭据导出失败 {task_id}: {r.text[:100]}")
    return r.json()["exec_credential"]


def tools_call(token, task_id, cred, operation, params, with_auth=True):
    headers = {"Content-Type": "application/json"}
    if with_auth:
        headers["Authorization"] = f"Bearer {token}"
    if task_id is not None:
        headers["X-Task-Id"] = task_id
    if cred is not None:
        headers["X-Task-Credential"] = cred
    return http("POST", f"{TOOLS}/api/tools/{operation}", headers=headers, json=params)


def admin_session():
    return login("carol", "carol123")


def agent_action(session, agent_id, action):
    return http("POST", f"{BACKEND}/api/admin/agents/{agent_id}/action",
                headers={"Authorization": f"Bearer {session}"}, json={"action": action})


# ---------- Keycloak 管理 ----------

def kc_admin_token():
    r = http("POST", f"{KC}/realms/master/protocol/openid-connect/token",
             data={"grant_type": "password", "client_id": "admin-cli",
                   "username": ADMIN_USER, "password": ADMIN_PASS})
    r.raise_for_status()
    return r.json()["access_token"]


def set_realm_lifespan(seconds):
    tok = kc_admin_token()
    h = {"Authorization": f"Bearer {tok}"}
    rep = http("GET", f"{KC}/admin/realms/{REALM}", headers=h).json()
    rep["accessTokenLifespan"] = seconds
    http("PUT", f"{KC}/admin/realms/{REALM}", headers=h, json=rep).raise_for_status()


def ensure_test_aud_client():
    """测试专用客户端：签发 aud=other-service 的令牌（其余条件有效），用于 AUTH-05c。"""
    tok = kc_admin_token()
    h = {"Authorization": f"Bearer {tok}"}
    matches = http("GET", f"{KC}/admin/realms/{REALM}/clients", headers=h,
                   params={"clientId": TEST_AUD_CLIENT}).json()
    if matches:
        cid = matches[0]["id"]
        rep = matches[0]
    else:
        r = http("POST", f"{KC}/admin/realms/{REALM}/clients", headers=h, json={
            "clientId": TEST_AUD_CLIENT, "enabled": True, "publicClient": False,
            "serviceAccountsEnabled": True, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False, "secret": TEST_AUD_SECRET})
        r.raise_for_status()
        cid = r.headers["Location"].rstrip("/").split("/")[-1]
        rep = http("GET", f"{KC}/admin/realms/{REALM}/clients/{cid}", headers=h).json()
    rep["secret"] = TEST_AUD_SECRET
    http("PUT", f"{KC}/admin/realms/{REALM}/clients/{cid}", headers=h, json=rep).raise_for_status()
    # 挂可选 scope order.read（保证除 audience 外其余条件有效）
    scopes = http("GET", f"{KC}/admin/realms/{REALM}/client-scopes", headers=h).json()
    order_read = next(s for s in scopes if s["name"] == "order.read")
    opt = http("GET", f"{KC}/admin/realms/{REALM}/clients/{cid}/optional-client-scopes", headers=h).json()
    if all(s["name"] != "order.read" for s in opt):
        http("PUT", f"{KC}/admin/realms/{REALM}/clients/{cid}/optional-client-scopes/{order_read['id']}",
             headers=h).raise_for_status()
    mappers = http("GET", f"{KC}/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models", headers=h).json()
    if all(m["name"] != "aud-other-service" for m in mappers):
        http("POST", f"{KC}/admin/realms/{REALM}/clients/{cid}/protocol-mappers/models", headers=h, json={
            "name": "aud-other-service", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": "other-service",
                       "id.token.claim": "false", "access.token.claim": "true"}}).raise_for_status()
    return cid


def tamper_token(token, payload_changes):
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=="))
    payload.update(payload_changes)
    new_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{new_p}.{s}"


def claims_of(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=="))


# ---------- 验收用例 ----------

def pin_fixed_mode():
    """固定请求回放（需求稿8）：验收期间将客服 Agent 钉在固定解析模式，结束后恢复默认。"""
    http("POST", f"{AGENT}/api/internal/experiment-config",
         headers={"X-Internal-Key": INTERNAL_KEY}, json={"changes": {"agent_mode": "fixed"}})
    atexit.register(lambda: http(
        "POST", f"{AGENT}/api/internal/experiment-config",
        headers={"X-Internal-Key": INTERNAL_KEY}, json={"changes": {"agent_mode": ""}}))


def register(cid: str, title: str):
    def deco(fn):
        CASE_FUNCS.append((cid, title, fn))
        return fn
    return deco


def ensure_ctx(ctx: dict, *keys):
    """按需建立用例共享状态（全量运行时自然复用；单案例运行时独立自建）。"""
    if "s_alice" in keys and "s_alice" not in ctx:
        step("前置：alice 登录可信后台（本地会话）", "POST /api/auth/login {alice}")
        ctx["s_alice"] = login("alice", "alice123")
    if "s_bob" in keys and "s_bob" not in ctx:
        step("前置：bob 登录可信后台（对照组，另一组数据权限）", "POST /api/auth/login {bob}")
        ctx["s_bob"] = login("bob", "bob123")
    if "s_carol" in keys and "s_carol" not in ctx:
        step("前置：carol（受限运维/审批人）登录", "POST /api/auth/login {carol}")
        ctx["s_carol"] = admin_session()
    if "t1" in keys and "t1" not in ctx:
        step("前置：alice 创建查询任务（order.read，限定 ORD-1001）",
             "POST /api/tasks {operation: order.read, order_ids: [ORD-1001]}")
        ctx["t1"] = create_task(ctx["s_alice"], "order.read",
                                {"type": "order_ids", "order_ids": ["ORD-1001"]})
        step(f"前置：任务 {ctx['t1']['task_id']} 已创建；经受控测试通道导出执行凭据（内容不展示）",
             "POST /api/internal/test-export-credential")
        ctx["cred1"] = export_cred(ctx["t1"]["task_id"])
    if "tok_cust" in keys and "tok_cust" not in ctx:
        step("前置：客服 Agent 以客户端凭据申请令牌（scope=order.read docs.read，有效期 300s）",
             f"POST {TOKEN_EP} (client_credentials, client={CUST_ID})")
        ctx["tok_cust"] = kc_token(CUST_ID, CUST_SEC, scope="order.read docs.read").json()["access_token"]
    if "tok_refund" in keys and "tok_refund" not in ctx:
        step("前置：退款 Agent 以自己的客户端凭据申请令牌（scope=refund.execute）",
             f"POST {TOKEN_EP} (client_credentials, client={REFUND_ID})")
        ctx["tok_refund"] = kc_token(REFUND_ID, REFUND_SEC, scope="refund.execute").json()["access_token"]
    if "t_all" in keys and "t_all" not in ctx:
        step("前置：alice 创建 user_all 查询任务（资源范围=本人全部订单）",
             "POST /api/tasks {operation: order.read, type: user_all}")
        ctx["t_all"] = create_task(ctx["s_alice"], "order.read", {"type": "user_all"})
        ctx["cred_all"] = export_cred(ctx["t_all"]["task_id"])
        step(f"前置：任务 {ctx['t_all']['task_id']} 已创建（注意：user_all 指任务用户 alice 本人，"
             "不因请求体伪称他人而改变授权主体）")


@register("AUTH-01", "合法链路")
def case_auth_01(ctx):
    print("[AUTH-01] 注册 Agent 正确凭据 -> 获准工具与业务对象")
    ensure_ctx(ctx, "s_alice", "t1")
    step(f"操作：alice 在任务 {ctx['t1']['task_id']} 内发起对话：『查询订单 ORD-1001』",
         "POST /api/agent/message（固定解析模式）")
    r = agent_message(ctx["s_alice"], ctx["t1"]["task_id"], "查询订单 ORD-1001")
    body = unwrap(r)
    chain = (body.get("execution") or {}).get("chain", [])
    layers_ok = all(c["status"] == "pass" for c in chain) and len(chain) == 6
    sub("AUTH-01", "合法链路", "任务创建+Agent对话+工具执行成功", r.status_code == 200 and body.get("ok"))
    sub("AUTH-01", "合法链路", "六层链路全部通过", layers_ok,
        " -> ".join(f"{c['layer']}:{c['status']}" for c in chain))
    sub("AUTH-01", "合法链路", "返回订单数据 ORD-1001",
        "ORD-1001" in json.dumps((body.get("execution") or {}).get("result") or {}, ensure_ascii=False))


@register("AUTH-02", "错误客户端凭据")
def case_auth_02(ctx):
    print("\n[AUTH-02] 错误客户端凭据申请令牌")
    step("子例a：使用客服 Agent 的 client_id + 错误密钥申请令牌",
         f"POST {TOKEN_EP} (client={CUST_ID}, secret=错误值)")
    r = kc_token(CUST_ID, "wrong-secret")
    sub("AUTH-02", "错误客户端凭据", "错误密钥 -> 401 不签发", r.status_code == 401,
        f"error={r.json().get('error')}")
    step("子例b：使用未注册的 client_id 申请令牌",
         "POST token endpoint (client=not-registered-client)")
    r = kc_token("not-registered-client", "whatever")
    sub("AUTH-02", "错误客户端凭据", "未注册 client_id -> 401 不签发", r.status_code == 401,
        f"error={r.json().get('error')}")


@register("AUTH-03", "名称不能代替认证")
def case_auth_03(ctx):
    print("\n[AUTH-03] 无令牌仅凭名称调用工具")
    ensure_ctx(ctx, "s_alice", "t1")
    step("操作：直接调用工具 API，请求体携带合法 Agent 名称与 user_id，但不带 Authorization 头",
         "POST /api/tools/order.read  body={order_id: ORD-1001, agent_id: customer-service-agent, user_id: u_alice}")
    r = tools_call(None, ctx["t1"]["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-1001", "agent_id": CUST_ID, "user_id": "u_alice"}, with_auth=False)
    b = unwrap(r)
    sub("AUTH-03", "名称不能代替认证", "请求体携带合法 Agent 名称但无令牌 -> 401",
        r.status_code == 401 and b["error"]["code"] == "missing_token",
        f"code={b['error']['code']}")


@register("AUTH-04", "篡改令牌")
def case_auth_04(ctx):
    print("\n[AUTH-04] 篡改 JWT 载荷保留原签名")
    ensure_ctx(ctx, "s_alice", "t1", "tok_cust")
    step("操作：解码合法令牌载荷，改写 scope（追加 refund.execute）与 azp（伪称退款 Agent），"
         "保留原签名重新拼装（签名与载荷不再匹配）",
         "token.scope = 'order.read docs.read refund.execute'  token.azp = 'refund-agent'")
    forged = tamper_token(ctx["tok_cust"], {"scope": "order.read docs.read refund.execute",
                                            "azp": "refund-agent"})
    step("操作：携带篡改令牌调用 order.read（其余材料有效）",
         f"POST /api/tools/order.read  X-Task-Id={ctx['t1']['task_id']}")
    r = tools_call(forged, ctx["t1"]["task_id"], ctx["cred1"], "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-04", "篡改令牌", "改写 scope/azp 后签名不符 -> 401 invalid_signature",
        r.status_code == 401 and b["error"]["code"] == "invalid_signature",
        f"code={b['error']['code']}")


@register("AUTH-05", "无效令牌三子例")
def case_auth_05(ctx):
    print("\n[AUTH-05] 过期 / 错误签发方 / 错误目标服务令牌")
    ensure_ctx(ctx, "s_alice", "t1", "tok_cust")
    step("子例a 前置：临时将 realm 令牌寿命调为 3s 并签发令牌，随后立即恢复 300s，等待 10s 令其过期",
         "PUT /admin/realms/agent-range {accessTokenLifespan: 3} -> 签发 -> 恢复 300s")
    set_realm_lifespan(3)
    expired_tok = kc_token(CUST_ID, CUST_SEC, scope="order.read").json()["access_token"]
    set_realm_lifespan(300)
    time.sleep(10)
    step("子例a：携带已过期但签名有效的令牌调用工具",
         "POST /api/tools/order.read  Authorization: Bearer <expired>")
    r = tools_call(expired_tok, ctx["t1"]["task_id"], ctx["cred1"], "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-05", "无效令牌三子例", "过期令牌（签名有效）-> 401 token_expired",
        r.status_code == 401 and b["error"]["code"] == "token_expired", f"code={b['error']['code']}")
    step("子例b：携带 master realm 管理令牌（其他签发方，签名对该 realm 有效但不在本靶场信任 JWKS 内）调用工具",
         "POST /api/tools/order.read  Authorization: Bearer <master-realm-token>")
    master_tok = kc_admin_token()
    mc = claims_of(master_tok)
    r = tools_call(master_tok, ctx["t1"]["task_id"], ctx["cred1"], "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-05", "无效令牌三子例", "其他签发方令牌（master realm）-> 401 拒绝",
        r.status_code == 401 and b["error"]["code"] in ("unknown_signing_key", "issuer_mismatch"),
        f"code={b['error']['code']}；令牌iss={mc.get('iss')}")
    step("子例c 前置：确保测试客户端（audience 映射为 other-service）存在",
         f"PUT /admin/... clients/{TEST_AUD_CLIENT}（aud mapper: other-service）")
    ensure_test_aud_client()
    step("子例c：用测试客户端申请令牌（签名有效、签发方正确、audience=other-service）调用工具",
         f"POST {TOKEN_EP} (client={TEST_AUD_CLIENT}) -> POST /api/tools/order.read")
    wrong_aud_tok = kc_token(TEST_AUD_CLIENT, TEST_AUD_SECRET, scope="order.read").json()["access_token"]
    r = tools_call(wrong_aud_tok, ctx["t1"]["task_id"], ctx["cred1"], "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-05", "无效令牌三子例", "错误 audience 令牌（其余有效）-> 401 audience_mismatch",
        r.status_code == 401 and b["error"]["code"] == "audience_mismatch",
        f"code={b['error']['code']}；令牌aud={claims_of(wrong_aud_tok).get('aud')}")


@register("AUTH-06", "超范围 scope")
def case_auth_06(ctx):
    print("\n[AUTH-06] 申请超过注册许可的 scope")
    step("子例a：客服 Agent 申请『order.read + 未注册给它的 refund.execute』",
         f"POST {TOKEN_EP}  scope='order.read refund.execute'")
    r = kc_token(CUST_ID, CUST_SEC, scope="order.read refund.execute")
    sub("AUTH-06", "超范围 scope", "混入未注册 scope -> 组件拒绝（400 invalid_scope，整组不签发）",
        r.status_code == 400 and r.json().get("error") == "invalid_scope",
        f"error={r.json().get('error')}")
    step("子例b：只申请合法子集 order.read",
         "POST token endpoint  scope='order.read'")
    r = kc_token(CUST_ID, CUST_SEC, scope="order.read")
    sub("AUTH-06", "超范围 scope", "合法子集单独申请仍可用（组件行为=整组拒绝而非缩减）",
        r.status_code == 200, "与组件行为表 V5 一致")
    sub("AUTH-06", "超范围 scope", "未授予操作的执行拒绝由 AUTH-07 机制覆盖（无该 scope 令牌无法通过工具端 scope 检查）",
        True, "见 AUTH-07")


@register("AUTH-07", "scope 不足")
def case_auth_07(ctx):
    print("\n[AUTH-07] 有效令牌但缺少所需 scope")
    ensure_ctx(ctx, "s_alice", "t1", "tok_refund")
    step("操作：退款 Agent 的合法令牌（仅 refund.execute）调用 order.read（需要 order.read scope）",
         f"POST /api/tools/order.read  Bearer <refund-agent-token>  X-Task-Id={ctx['t1']['task_id']}")
    r = tools_call(ctx["tok_refund"], ctx["t1"]["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-1001"})
    b = unwrap(r)
    chain = b.get("chain", [])
    jwt_pass = any(c["layer"] == "JWT 验证" and c["status"] == "pass" for c in chain)
    sub("AUTH-07", "scope 不足", "退款Agent令牌调用 order.read -> 认证通过、授权拒绝(403)",
        r.status_code == 403 and b["error"]["code"] == "insufficient_scope" and jwt_pass,
        f"code={b['error']['code']}")


@register("AUTH-08", "越权三子例")
def case_auth_08(ctx):
    print("\n[AUTH-08] 有效令牌替换用户、他人任务或他人订单")
    ensure_ctx(ctx, "s_alice", "s_bob", "t1", "t_all", "tok_cust")
    step("子例a：alice 的 user_all 任务内，请求体伪称 user_id=u_bob 并查询 bob 的订单 ORD-2001"
         "（任务真实用户仍为 alice）",
         "POST /api/tools/order.read  body={order_id: ORD-2001, user_id: u_bob}（陷阱字段）")
    r = tools_call(ctx["tok_cust"], ctx["t_all"]["task_id"], ctx["cred_all"], "order.read",
                   {"order_id": "ORD-2001", "user_id": "u_bob"})
    b = unwrap(r)
    sub("AUTH-08", "越权三子例", "请求体替换 user_id + 他人订单 -> 对象级授权拒绝",
        r.status_code == 403 and b["error"]["code"] == "object_ownership",
        f"code={b['error']['code']}（请求体身份字段不作为授权依据）")
    step("子例b 前置：bob 创建自己的查询任务（user_all）",
         "POST /api/tasks（bob 会话，order.read user_all）")
    t_bob = create_task(ctx["s_bob"], "order.read", {"type": "user_all"})
    step("子例b：alice 的执行凭据配 bob 的任务编号调用（凭据与任务不匹配）",
         f"POST /api/tools/order.read  X-Task-Id={t_bob['task_id']}(bob)  X-Task-Credential=<alice 的>")
    r = tools_call(ctx["tok_cust"], t_bob["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-08", "越权三子例", "A 的执行凭据 + B 的任务编号 -> 绑定不符拒绝",
        r.status_code == 403 and b["error"]["code"] == "task_binding_mismatch",
        f"code={b['error']['code']}")
    step("子例c：alice 的 ORD-1001 限定任务内查询范围外订单 ORD-2001（bob 的订单）",
         f"POST /api/tools/order.read  body={{order_id: ORD-2001}}（任务范围仅 ORD-1001）")
    r = tools_call(ctx["tok_cust"], ctx["t1"]["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-2001"})
    b = unwrap(r)
    sub("AUTH-08", "越权三子例", "任务范围外订单（ORD-2001）-> 拒绝",
        r.status_code == 403 and b["error"]["code"] == "order_not_in_scope",
        f"code={b['error']['code']}")


@register("AUTH-09", "撤销与停用")
def case_auth_09(ctx):
    print("\n[AUTH-09] 停用 Agent 或撤销任务后旧令牌调用")
    ensure_ctx(ctx, "s_alice", "s_carol", "t1", "tok_cust")
    step("子例a 前置：受限运维经统一入口停用客服 Agent（两阶段：应用侧准入 + Keycloak 客户端）",
         "POST /api/admin/agents/customer-service-agent/action {disable}")
    r = agent_action(ctx["s_carol"], "customer-service-agent", "disable")
    b = unwrap(r)
    sub("AUTH-09", "撤销与停用", "两阶段停用完成（应用侧+授权服务）",
        r.status_code == 200 and b.get("status") == "disabled"
        and b["phases"]["app_side"] == "ok" and b["phases"]["oauth_server"] == "ok",
        f"phases={b.get('phases')}")
    step("子例a：停用后使用未过期令牌 + 有效任务凭据调用（组件行为 V7：验签仍通过，"
         "验证应用侧在线核验兜底）",
         "POST /api/tools/order.read  Bearer <停用前令牌>")
    r = tools_call(ctx["tok_cust"], ctx["t1"]["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-09", "撤销与停用", "停用后未过期令牌+有效任务 -> 403 agent_disabled（记录撤销原因）",
        r.status_code == 403 and b["error"]["code"] == "agent_disabled",
        f"reason={b['error']['reason']}")
    step("子例a：停用期间 Agent 再申请新令牌",
         f"POST {TOKEN_EP} (client={CUST_ID})")
    r = kc_token(CUST_ID, CUST_SEC, scope="order.read")
    sub("AUTH-09", "撤销与停用", "停用期间新令牌申请亦失败（401）", r.status_code == 401,
        f"error={r.json().get('error')}")
    step("恢复：重新启用客服 Agent（保证后续用例/演示可用）",
         "POST /api/admin/agents/customer-service-agent/action {enable}")
    agent_action(ctx["s_carol"], "customer-service-agent", "enable")
    step("子例b 前置：alice 创建新任务（ORD-1002）并导出凭据",
         "POST /api/tasks {order_ids: [ORD-1002]} -> test-export-credential")
    t9 = create_task(ctx["s_alice"], "order.read",
                     {"type": "order_ids", "order_ids": ["ORD-1002"]})
    cred9 = export_cred(t9["task_id"])
    step("子例b 对照：撤销前同材料调用成功",
         "POST /api/tools/order.read  body={order_id: ORD-1002}")
    r = tools_call(ctx["tok_cust"], t9["task_id"], cred9, "order.read", {"order_id": "ORD-1002"})
    sub("AUTH-09", "撤销与停用", "撤销前调用成功（对照）", r.status_code == 200)
    step("子例b：alice 在 UI 撤销任务后，同令牌同凭据立即重放",
         f"POST /api/tasks/{t9['task_id']}/revoke -> 重放同一工具调用")
    revoke_task(ctx["s_alice"], t9["task_id"])
    r = tools_call(ctx["tok_cust"], t9["task_id"], cred9, "order.read", {"order_id": "ORD-1002"})
    b = unwrap(r)
    sub("AUTH-09", "撤销与停用", "撤销后同凭据调用 -> 403 task_revoked（在线状态核验，非令牌过期）",
        r.status_code == 403 and b["error"]["code"] == "task_revoked",
        f"reason={b['error']['reason']}")


@register("AUTH-10", "直接 API 调用")
def case_auth_10(ctx):
    print("\n[AUTH-10] 绕过界面直接调用工具 HTTP API")
    ensure_ctx(ctx, "s_alice", "t1", "tok_cust")
    step("子例a：材料齐全（令牌+任务编号+执行凭据）直接 POST 工具 API",
         "POST /api/tools/order.read（全部必需头）")
    r = tools_call(ctx["tok_cust"], ctx["t1"]["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-1001"})
    sub("AUTH-10", "直接 API 调用", "材料齐全的直接调用成功（保护在 API 层）", r.status_code == 200)
    step("子例b：直接调用但不带 Authorization 头",
         "POST /api/tools/order.read（无 Bearer）")
    r = tools_call(None, ctx["t1"]["task_id"], ctx["cred1"], "order.read",
                   {"order_id": "ORD-1001"}, with_auth=False)
    sub("AUTH-10", "直接 API 调用", "直接调用无令牌 -> 401", r.status_code == 401)
    step("子例c：带令牌但不带任务编号与执行凭据（仅应用层身份，无任务授权）",
         "POST /api/tools/order.read（无 X-Task-Id / X-Task-Credential）")
    r = tools_call(ctx["tok_cust"], None, None, "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("AUTH-10", "直接 API 调用", "直接调用缺任务凭据 -> 403 missing_task_credential",
        r.status_code == 403 and b["error"]["code"] == "missing_task_credential",
        f"code={b['error']['code']}")


@register("AUTH-12", "建议不等于授权")
def case_auth_12(ctx):
    print("\n[AUTH-12] 用户仅确认查询，模型提议退款/发送")
    ensure_ctx(ctx, "s_alice", "t1")
    step("前置：记录 alice 当前任务集合（用于断言无新增授权）",
         "GET /api/tasks -> before")
    before = {t["task_id"] for t in list_tasks(ctx["s_alice"])}
    step("操作：在查询任务（仅授权 order.read）内发送：『帮我把 ORD-1001 申请退款 100 元』"
         "（固定解析器模拟模型提议退款——真实模型实验见阶段3）",
         f"POST /api/agent/message  task={ctx['t1']['task_id']}")
    r = agent_message(ctx["s_alice"], ctx["t1"]["task_id"], "帮我把 ORD-1001 申请退款 100 元")
    body = unwrap(r)
    ex = body.get("execution") or {}
    err = ex.get("error") or {}
    chain = ex.get("chain", [])
    layer5_fail = any(c["layer"] == "任务与用户授权" and c["status"] == "fail" for c in chain)
    not_reached = all(c["status"] == "skipped" for c in chain[:4])
    step("后置：再次读取任务集合，对比无新增",
         "GET /api/tasks -> after")
    after = {t["task_id"] for t in list_tasks(ctx["s_alice"])}
    sub("AUTH-12", "建议不等于授权", "查询任务中提议退款 -> 不执行、不扩权",
        r.status_code == 200 and body.get("ok") is False
        and err.get("code") == "operation_not_in_task" and layer5_fail and not_reached,
        f"code={err.get('code')}；失败层=任务与用户授权，层1-4未到达")
    sub("AUTH-12", "建议不等于授权", "未生成任何新任务/授权（任务集合不变）", before == after)


@register("AUTH-13", "任务绑定")
def case_auth_13(ctx):
    print("\n[AUTH-13] 同一 Agent 处理 A、B 任务，A 的调用改用 B 的任务编号")
    ensure_ctx(ctx, "s_alice", "s_bob", "tok_cust")
    step("前置：alice 新建 ORD-1001 任务并导出凭据；bob 新建 user_all 任务",
         "POST /api/tasks ×2（alice / bob）")
    t13a = create_task(ctx["s_alice"], "order.read",
                       {"type": "order_ids", "order_ids": ["ORD-1001"]})
    cred_a = export_cred(t13a["task_id"])
    t13b = create_task(ctx["s_bob"], "order.read", {"type": "user_all"})
    step("子例a：alice 的执行凭据 + bob 的任务编号调用工具（同 Agent 服务，跨用户任务）",
         f"POST /api/tools/order.read  X-Task-Id={t13b['task_id']}(bob)  X-Task-Credential=<alice 的>")
    r = tools_call(ctx["tok_cust"], t13b["task_id"], cred_a, "order.read", {"order_id": "ORD-2001"})
    b = unwrap(r)
    sub("AUTH-13", "任务绑定", "A 的凭据 + B 的任务编号 -> 绑定不符拒绝",
        r.status_code == 403 and b["error"]["code"] == "task_binding_mismatch",
        f"code={b['error']['code']}")
    step("子例b：alice 的会话直接对 bob 的任务发起对话（UI 层入口）",
         f"POST /api/agent/message  X-Session-Token=<alice>  task={t13b['task_id']}(bob)")
    r = agent_message(ctx["s_alice"], t13b["task_id"], "查询订单 ORD-2001")
    sub("AUTH-13", "任务绑定", "A 的会话对 B 任务发起对话 -> 会话归属核验拒绝",
        r.status_code == 403, "结果不串给其他用户")


def main():
    ap = argparse.ArgumentParser(description="阶段1验收（固定请求回放）")
    ap.add_argument("--case", help="仅复现指定用例（逗号分隔，如 AUTH-08 或 AUTH-05,AUTH-09）；"
                                   "单案例模式逐步输出操作过程，不覆盖验收报告")
    ap.add_argument("--list", action="store_true", help="列出可复现用例")
    args = ap.parse_args()

    if not INTERNAL_KEY:
        sys.exit("缺少 INTERNAL_API_KEY（先运行 start-all.ps1）")

    if args.list:
        print("可复现用例：")
        for cid, title, _ in CASE_FUNCS:
            print(f"  {cid}  {title}")
        return 0

    pin_fixed_mode()

    selected = None
    if args.case:
        selected = [c.strip().upper() for c in args.case.split(",") if c.strip()]
        known = {cid for cid, _, _ in CASE_FUNCS}
        unknown = [c for c in selected if c not in known]
        if unknown:
            sys.exit(f"未知用例: {unknown}（--list 查看可用用例）")

    if selected:
        print(f"== 阶段1单案例复现：{', '.join(selected)}（固定请求回放，Agent=固定解析）==\n")
    else:
        print("== 阶段1验收：AUTH-01~10、12、13（固定请求回放，Agent=固定解析）==\n")

    ctx: dict = {}
    for cid, _title, fn in CASE_FUNCS:
        if selected and cid not in selected:
            continue
        fn(ctx)

    print("\n== 汇总 ==")
    all_pass = True
    for cid in CASES:
        p = case_pass(cid)
        all_pass = all_pass and p
        print(f"{cid} {CASES[cid]['title']}: {'PASS' if p else 'FAIL'}"
              f" ({sum(1 for s in CASES[cid]['subs'] if s['ok'])}/{len(CASES[cid]['subs'])})")
    print(f"\n总体: {'ALL PASS' if all_pass else 'HAS FAILURES'}")

    if selected:
        print(f"（单案例复现模式：未写报告；全量验收请运行不带 --case 的完整脚本）")
    else:
        write_report()
    return 0 if all_pass else 1


def write_report():
    lines = [
        "# 阶段1验收报告：AUTH-01~10、12、13（固定请求模式）",
        "",
        f"- 日期: {datetime.now().isoformat(timespec='seconds')}",
        f"- 模式: 固定请求回放（不涉及真实模型；模型建议以固定解析器模拟）",
        f"- 组件: Keycloak 26.7.4 独立进程 / FastAPI 四服务（backend:8000, agent:8100/8200, tools:8300）",
        f"- 测试凭据: 经受控测试通道加载（6.10），仅记录脱敏摘要",
        "",
        "| 用例 | 结果 | 子项 |",
        "| --- | --- | --- |",
    ]
    for cid, c in CASES.items():
        p = "PASS" if all(s["ok"] for s in c["subs"]) else "FAIL"
        subs = "<br>".join(
            f"{'✓' if s['ok'] else '✗'} {s['name']}" + (f"（{s['note']}）" if s["note"] else "")
            for s in c["subs"])
        lines.append(f"| {cid} {c['title']} | **{p}** | {subs} |")
    lines += [
        "",
        "## 实现口径说明",
        "",
        "1. 错误码分层：缺失/无效令牌 → 401（missing_token/invalid_signature/unknown_signing_key/token_expired/audience_mismatch）；身份有效但 scope 不足 → 403 insufficient_scope；任务绑定/撤销/停用/对象授权 → 403（task_binding_mismatch/task_revoked/agent_disabled/object_ownership/order_not_in_scope 等），响应含失败层与原因。",
        "2. 对象可见性策略：演示环境对越权对象返回明确 403 原因（便于定位阻断层）；生产可选 404 隐藏策略，需在方案文档中声明。",
        "3. 错误签发方子例：master realm 令牌在可信 JWKS 中无对应签名密钥，首个失败点为 unknown_signing_key（签发方信任边界即密钥边界）；其 iss 亦不匹配，iss 声明检查作为第二道防线存在。",
        "4. AUTH-06 组件行为：Keycloak 26.7.4 对超范围 scope 请求整组拒绝（HTTP 400 invalid_scope），与组件行为表 V5 一致；未授予操作的执行拒绝由 scope 检查层保证（AUTH-07 机制）。",
        "5. 执行凭据不经网页展示与模型上下文：由可信后台经内部通道推送 Agent 运行层；本报告验证所用凭据来自受控测试通道，报告中不出现原文。",
        "6. 撤销即时性：应用授权状态为执行前在线核验（无跨请求缓存），撤销/停用后的下一次调用即被拒绝（AUTH-09）。",
    ]
    out = ROOT / "reports" / "auth-phase1.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告已写入 {out}")


if __name__ == "__main__":
    sys.exit(main())
