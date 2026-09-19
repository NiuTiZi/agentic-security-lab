"""阶段2验收：AUTH-14 委托链、AUTH-11 正常对照、审批/幂等、CRED-01~04 凭据盗用实验。

前置: Keycloak 与四服务运行中（scripts\\start-all.ps1）。
模式: 固定请求回放（需求稿第8节）——验证委托、审批、幂等与凭据盗用防护，不涉及真实模型。
凭据: 测试执行凭据经受控测试通道加载（需求稿6.10），报告仅展示脱敏摘要。
输出: reports/auth-phase2.md + 控制台摘要。

用法:
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase2.py                    # 全量验收（写报告）
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase2.py --case AUTH-14     # 单案例复现（逐步输出，不写报告）
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase2.py --case CRED-01,CRED-03
    .venv\\Scripts\\python.exe scripts\\verify_auth_phase2.py --list             # 列出可复现用例
单案例复现输出即验证复现手册（docs/08）中该用例的"预期输出"，可逐行对照。
"""
import argparse
import atexit
import json
import os
import sys
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
INTERNAL_KEY = os.environ.get("INTERNAL_API_KEY", "")
BACKEND = "http://127.0.0.1:8000"
AGENT = "http://127.0.0.1:8100"
REFUND_AGENT = "http://127.0.0.1:8200"
TOOLS = "http://127.0.0.1:8300"

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


def get_task(session, task_id):
    tasks = http("GET", f"{BACKEND}/api/tasks",
                 headers={"Authorization": f"Bearer {session}"}).json()["tasks"]
    return next((t for t in tasks if t["task_id"] == task_id), None)


def revoke_task(session, task_id):
    return http("POST", f"{BACKEND}/api/tasks/{task_id}/revoke",
                headers={"Authorization": f"Bearer {session}"})


def agent_message(session, task_id, message):
    return http("POST", f"{AGENT}/api/agent/message",
                headers={"X-Session-Token": session, "Content-Type": "application/json"},
                json={"task_id": task_id, "message": message})


def refund_message(session, task_id, message="执行退款"):
    return http("POST", f"{REFUND_AGENT}/api/agent/message",
                headers={"X-Session-Token": session, "Content-Type": "application/json"},
                json={"task_id": task_id, "message": message})


def approve(session, task_id, decision):
    return http("POST", f"{BACKEND}/api/tasks/{task_id}/approval",
                headers={"Authorization": f"Bearer {session}"},
                json={"decision": decision})


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


def agent_action(session, agent_id, action):
    return http("POST", f"{BACKEND}/api/admin/agents/{agent_id}/action",
                headers={"Authorization": f"Bearer {session}"}, json={"action": action})


def yuan(cents):
    return f"{cents / 100:g}"


def create_refund_parent(session, order_id, amount_cents, reason="验收测试退款"):
    return create_task(session, "refund.request",
                       {"type": "refund", "order_id": order_id,
                        "amount_cents": amount_cents, "reason": reason})


def delegate(session, parent_task_id, order_id, amount_cents):
    """经客服 Agent 对话发起退款委托，返回 (response, subtask_id)。"""
    r = agent_message(session, parent_task_id,
                      f"为 {order_id} 申请退款 {yuan(amount_cents)} 元")
    body = unwrap(r)
    subtask_id = ((body.get("execution") or {}).get("result") or {}).get("subtask_id")
    return r, subtask_id


# ---------- 固定模式与共享上下文 ----------

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
    if "s_carol" in keys and "s_carol" not in ctx:
        step("前置：carol（审批人）登录", "POST /api/auth/login {carol}")
        ctx["s_carol"] = login("carol", "carol123")
    if "tok_cust" in keys and "tok_cust" not in ctx:
        step("前置：客服 Agent 以客户端凭据申请令牌（scope=order.read）",
             f"POST {TOKEN_EP} (client_credentials, client={CUST_ID})")
        ctx["tok_cust"] = kc_token(CUST_ID, CUST_SEC, scope="order.read").json()["access_token"]
    if "tok_refund" in keys and "tok_refund" not in ctx:
        step("前置：退款 Agent 以自己的客户端凭据申请令牌（scope=refund.execute）",
             f"POST {TOKEN_EP} (client_credentials, client={REFUND_ID})")
        ctx["tok_refund"] = kc_token(REFUND_ID, REFUND_SEC, scope="refund.execute").json()["access_token"]
    if "cred_task" in keys and "cred_task" not in ctx:
        step("前置：alice 创建查询任务（order.read，限定 ORD-1001）并经受控测试通道导出执行凭据",
             "POST /api/tasks {order_ids: [ORD-1001]} -> POST /api/internal/test-export-credential")
        ctx["t_cred"] = create_task(ctx["s_alice"], "order.read",
                                    {"type": "order_ids", "order_ids": ["ORD-1001"]})
        ctx["cred_cred"] = export_cred(ctx["t_cred"]["task_id"])


# ---------- 验收用例 ----------

@register("AUTH-14", "委托链")
def case_auth_14(ctx):
    print("[AUTH-14] 客服按已确认范围委托退款；越界/撤销案例分别拒绝")
    ensure_ctx(ctx, "s_alice", "s_carol", "tok_refund")
    s_alice, s_carol, tok_refund = ctx["s_alice"], ctx["s_carol"], ctx["tok_refund"]

    # a. 合法链路：父任务(ORD-1002, 50元) -> 委托 -> 审批 -> 退款执行 -> 退款记录
    step("a 前置：alice 创建退款父任务（refund.request，ORD-1002 退款 50 元，用户确认参数）",
         "POST /api/tasks {operation: refund.request, order_id: ORD-1002, amount_cents: 5000}")
    parent1 = create_refund_parent(s_alice, "ORD-1002", 5000)
    step(f"a 操作：alice 在父任务 {parent1['task_id']} 内对客服 Agent 说『为 ORD-1002 申请退款 50 元』，"
         "客服按已确认参数提交委托（自身无 refund.execute 权限）",
         f"POST /api/agent/message  task={parent1['task_id']}")
    r, sub1 = delegate(s_alice, parent1["task_id"], "ORD-1002", 5000)
    body = unwrap(r)
    sub("AUTH-14", "委托链", "合法委托成功（客服对话提交，子任务签发给退款 Agent）",
        r.status_code == 200 and body.get("ok") and sub1 is not None,
        f"父任务 {parent1['task_id']} -> 子任务 {sub1}（pending）")
    step(f"a 操作：审批人 carol 批准子任务 {sub1}（审批绑定子任务/工具/订单/金额）",
         f"POST /api/tasks/{sub1}/approval {{decision: approve}}")
    r = approve(s_carol, sub1, "approve")
    b = unwrap(r)
    sub("AUTH-14", "委托链", "审批人批准（绑定子任务/工具/订单/金额）",
        r.status_code == 200 and b.get("approval_status") == "approved",
        f"审批参数={b.get('approval', {}).get('params')}")
    step(f"a 操作：alice 触发退款 Agent 在受限子任务 {sub1} 内执行退款",
         f"POST :8200/api/agent/message  task={sub1}")
    r = refund_message(s_alice, sub1)
    b = unwrap(r)
    refund = ((b.get("execution") or {}).get("result") or {}).get("refund") or {}
    sub("AUTH-14", "委托链", "退款 Agent 按审批执行模拟退款成功",
        r.status_code == 200 and b.get("ok") and refund.get("amount_cents") == 5000
        and refund.get("order_id") == "ORD-1002",
        f"退款单 {refund.get('refund_id')}，金额 ¥{refund.get('amount_cents', 0) / 100:g}")

    # b. 委托超父金额（父 30 元，委托 100 元）
    step("b 前置：alice 创建退款父任务（ORD-1001，用户确认金额 30 元）",
         "POST /api/tasks {order_id: ORD-1001, amount_cents: 3000}")
    parent2 = create_refund_parent(s_alice, "ORD-1001", 3000)
    step(f"b 操作：在父任务 {parent2['task_id']} 内委托 100 元（超出用户确认的 30 元）",
         f"POST /api/agent/message  task={parent2['task_id']}『为 ORD-1001 申请退款 100 元』")
    r, sub2 = delegate(s_alice, parent2["task_id"], "ORD-1001", 10000)
    b = unwrap(r)
    err = (b.get("execution") or {}).get("error") or {}
    sub("AUTH-14", "委托链", "委托金额超父任务确认值 -> 拒绝（委托只能收缩权限）",
        r.status_code == 200 and b.get("ok") is False
        and err.get("code") == "delegate_amount_exceeds_parent",
        f"code={err.get('code')}")

    # c. 子任务换订单执行（直接调工具，攻击者视角）
    step("c 前置：经受控测试通道导出子任务凭据（模拟凭据被窃取）",
         f"POST /api/internal/test-export-credential {sub1}")
    cred1 = export_cred(sub1)
    step(f"c 操作：退款 Agent 令牌 + 子任务 {sub1} 凭据，但订单换为 ORD-1001（子任务绑定 ORD-1002）",
         f"POST /api/tools/refund.execute  body={{order_id: ORD-1001, amount_cents: 5000}}")
    r = tools_call(tok_refund, sub1, cred1, "refund.execute",
                   {"order_id": "ORD-1001", "amount_cents": 5000})
    b = unwrap(r)
    sub("AUTH-14", "委托链", "子任务换订单执行 -> 拒绝（订单绑定子任务）",
        r.status_code == 403 and b["error"]["code"] == "order_not_in_subtask",
        f"code={b['error']['code']}")

    # d. 子任务提金额执行
    step(f"d 操作：同子任务 {sub1}，订单正确但金额从 50 元提高到 500 元（超出审批上限）",
         "POST /api/tools/refund.execute  body={order_id: ORD-1002, amount_cents: 50000}")
    r = tools_call(tok_refund, sub1, cred1, "refund.execute",
                   {"order_id": "ORD-1002", "amount_cents": 50000})
    b = unwrap(r)
    sub("AUTH-14", "委托链", "子任务提高金额执行 -> 拒绝（审批与授权不覆盖提额）",
        r.status_code == 403 and b["error"]["code"] == "amount_exceeds_limit",
        f"code={b['error']['code']}")

    # e. 撤销父任务后子任务执行
    step("e 前置：创建父任务（ORD-1001 20 元）-> 委托 -> 审批，随后 alice 撤销父任务",
         f"POST /api/tasks -> 委托 -> 审批 -> POST /api/tasks/{ '{父任务}' }/revoke")
    parent3 = create_refund_parent(s_alice, "ORD-1001", 2000)
    r, sub3 = delegate(s_alice, parent3["task_id"], "ORD-1001", 2000)
    approve(s_carol, sub3, "approve")
    revoke_task(s_alice, parent3["task_id"])
    step(f"e 操作：父任务已撤销，仍持子任务 {sub3}（已审批）触发退款 Agent 执行",
         f"POST :8200/api/agent/message  task={sub3}")
    r = refund_message(s_alice, sub3)
    b = unwrap(r)
    err = (b.get("execution") or {}).get("error") or {}
    sub("AUTH-14", "委托链", "撤销父任务后子任务执行 -> 拒绝（级联约束）",
        r.status_code == 200 and b.get("ok") is False
        and err.get("code") == "parent_task_revoked",
        f"code={err.get('code')}")

    # f. 未审批先执行
    step("f 前置：创建父任务（ORD-1001 20 元）-> 委托产生子任务（不做审批）",
         "POST /api/tasks -> 委托（跳过审批环节）")
    parent4 = create_refund_parent(s_alice, "ORD-1001", 2000)
    r, sub4 = delegate(s_alice, parent4["task_id"], "ORD-1001", 2000)
    cred4 = export_cred(sub4)
    step(f"f 操作：持未审批子任务 {sub4} 的凭据直接调用退款执行工具",
         "POST /api/tools/refund.execute  body={order_id: ORD-1001, amount_cents: 2000}")
    r = tools_call(tok_refund, sub4, cred4, "refund.execute",
                   {"order_id": "ORD-1001", "amount_cents": 2000})
    b = unwrap(r)
    sub("AUTH-14", "委托链", "未审批先执行 -> 拒绝（approval_required）",
        r.status_code == 403 and b["error"]["code"] == "approval_required",
        f"code={b['error']['code']}")

    # g. 幂等：重复执行同一子任务不重复退款
    step(f"g 操作：对已完成的子任务 {sub1} 再次触发退款 Agent 执行（重放）",
         f"POST :8200/api/agent/message  task={sub1}")
    r = refund_message(s_alice, sub1)
    b = unwrap(r)
    result = (b.get("execution") or {}).get("result") or {}
    sub("AUTH-14", "委托链", "重复执行同一子任务 -> 幂等返回，不重复退款",
        r.status_code == 200 and b.get("ok") and result.get("idempotent") is True
        and result.get("refund", {}).get("refund_id") == refund.get("refund_id"),
        f"退款单 {result.get('refund', {}).get('refund_id')}（与首次相同）")

    # h. 审批参数变更：同父任务第二个子任务（更低金额）需独立审批
    step(f"h 前置：同一父任务 {parent4['task_id']} 再委托一笔更低金额（10 元），产生新子任务",
         "POST /api/agent/message『为 ORD-1001 申请退款 10 元』")
    r, sub5 = delegate(s_alice, parent4["task_id"], "ORD-1001", 1000)
    cred5 = export_cred(sub5)
    step(f"h 操作：新子任务 {sub5} 未审批直接执行（检验旧审批不沿用）",
         "POST /api/tools/refund.execute  body={order_id: ORD-1001, amount_cents: 1000}")
    r = tools_call(tok_refund, sub5, cred5, "refund.execute",
                   {"order_id": "ORD-1001", "amount_cents": 1000})
    b = unwrap(r)
    sub("AUTH-14", "委托链", "修改金额产生新子任务 -> 旧审批不覆盖，未审批仍拒绝",
        r.status_code == 403 and b["error"]["code"] == "approval_required",
        f"新子任务 {sub5}（10元）未沿用 {sub4}（20元）的审批")
    step(f"h 操作：对新子任务 {sub5} 独立审批后再执行",
         f"POST /api/tasks/{sub5}/approval {{approve}} -> POST /api/tools/refund.execute")
    approve(s_carol, sub5, "approve")
    r = tools_call(tok_refund, sub5, cred5, "refund.execute",
                   {"order_id": "ORD-1001", "amount_cents": 1000})
    b = unwrap(r)
    sub("AUTH-14", "委托链", "新子任务独立审批后可执行（金额以新审批为准）",
        r.status_code == 200 and b.get("ok")
        and b["data"]["refund"]["amount_cents"] == 1000,
        f"退款 ¥{b['data']['refund']['amount_cents'] / 100:g} 完成")


@register("AUTH-11", "正常对照")
def case_auth_11(ctx):
    print("\n[AUTH-11] 保持防护启用，合法用户/Agent 正常任务全部可完成")
    ensure_ctx(ctx, "s_alice", "s_carol")
    s_alice, s_carol = ctx["s_alice"], ctx["s_carol"]

    step("操作：alice 创建查询任务（ORD-1001）并发起对话",
         "POST /api/tasks {order_ids: [ORD-1001]} -> POST /api/agent/message『查询订单 ORD-1001』")
    t = create_task(s_alice, "order.read", {"type": "order_ids", "order_ids": ["ORD-1001"]})
    r = agent_message(s_alice, t["task_id"], "查询订单 ORD-1001")
    b = unwrap(r)
    sub("AUTH-11", "正常对照", "合法查询任务完成（防护启用不影响正常业务）",
        r.status_code == 200 and b.get("ok"))
    step("操作：alice 创建资料检索任务（docs.read user_all）并检索部门资料",
         "POST /api/tasks {docs.read user_all} -> POST /api/agent/message『检索部门资料』")
    t = create_task(s_alice, "docs.read", {"type": "user_all"})
    r = agent_message(s_alice, t["task_id"], "检索部门资料")
    b = unwrap(r)
    sub("AUTH-11", "正常对照", "合法资料检索完成",
        r.status_code == 200 and b.get("ok"))
    step("操作：alice 走完整合法退款链路：确认退款（ORD-1001 20 元）-> 客服委托 -> 审批 -> 退款执行",
         "POST /api/tasks {refund.request} -> 委托 -> 审批 -> :8200 执行")
    parent = create_refund_parent(s_alice, "ORD-1001", 2000)
    r, st = delegate(s_alice, parent["task_id"], "ORD-1001", 2000)
    approve(s_carol, st, "approve")
    r = refund_message(s_alice, st)
    b = unwrap(r)
    rf = ((b.get("execution") or {}).get("result") or {}).get("refund") or {}
    sub("AUTH-11", "正常对照", "合法退款全链路完成（确认->委托->审批->执行）",
        r.status_code == 200 and b.get("ok") and rf.get("amount_cents") == 2000,
        f"退款单 {rf.get('refund_id')} ¥20 完成")


@register("CRED-01", "仅令牌")
def case_cred_01(ctx):
    print("\n[CRED-01] 盗用者仅持有 Agent Bearer 令牌（无任务执行凭据）")
    ensure_ctx(ctx, "tok_cust")
    step("操作：仅携带客服 Agent 令牌（scope=order.read）直接调用工具，不带任务编号与执行凭据",
         "POST /api/tools/order.read  Authorization: Bearer <token>（无 X-Task-Id / X-Task-Credential）")
    r = tools_call(ctx["tok_cust"], None, None, "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    jwt_layer_ok = any(c["layer"] == "JWT 验证" and c["status"] == "pass" for c in b.get("chain", []))
    sub("CRED-01", "仅令牌", "Agent 认证通过（JWT 验证层 pass）", jwt_layer_ok,
        "持有者令牌本身有效，认证层无法区分盗用")
    sub("CRED-01", "仅令牌", "缺任务执行凭据 -> 业务授权拒绝（两层结果分开报告）",
        r.status_code == 403 and b["error"]["code"] == "missing_task_credential",
        f"code={b['error']['code']}，失败层={b['error'].get('layer')}")


@register("CRED-02", "令牌+任务凭据")
def case_cred_02(ctx):
    print("\n[CRED-02] 盗用者同时持有令牌与有效任务执行凭据（持有者令牌的局限）")
    ensure_ctx(ctx, "tok_cust", "cred_task")
    t2, cred2 = ctx["t_cred"], ctx["cred_cred"]
    step(f"操作：令牌 + 任务 {t2['task_id']}（ORD-1001 限定）凭据，查询范围内订单",
         "POST /api/tools/order.read  body={order_id: ORD-1001}")
    r = tools_call(ctx["tok_cust"], t2["task_id"], cred2, "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("CRED-02", "令牌+任务凭据", "任务有效期内范围内查询成功（持有者令牌的局限）",
        r.status_code == 200 and b.get("ok"),
        "盗用者同时持有令牌与有效任务凭据时可冒用完成任务")
    step("操作：同一凭据查询任务范围外订单 ORD-2001（bob 的订单）",
         "POST /api/tools/order.read  body={order_id: ORD-2001}")
    r = tools_call(ctx["tok_cust"], t2["task_id"], cred2, "order.read", {"order_id": "ORD-2001"})
    b = unwrap(r)
    sub("CRED-02", "令牌+任务凭据", "更换任务范围外订单 -> 拒绝",
        r.status_code == 403 and b["error"]["code"] == "order_not_in_scope",
        f"code={b['error']['code']}")
    step("操作：同一凭据调用 docs.read（令牌 scope 仅 order.read，任务亦未授权）",
         "POST /api/tools/docs.read  body={query: 资料}")
    r = tools_call(ctx["tok_cust"], t2["task_id"], cred2, "docs.read", {"query": "资料"})
    b = unwrap(r)
    sub("CRED-02", "令牌+任务凭据", "扩大操作（docs.read）-> 拒绝",
        r.status_code == 403 and b["error"]["code"] == "insufficient_scope",
        f"code={b['error']['code']}（令牌 scope 仍限定 order.read）")


@register("CRED-03", "撤销后重放")
def case_cred_03(ctx):
    print("\n[CRED-03] 任务撤销后同材料重放")
    ensure_ctx(ctx, "tok_cust", "cred_task")
    t2, cred2 = ctx["t_cred"], ctx["cred_cred"]
    step(f"操作：alice 在 UI 撤销任务 {t2['task_id']}（盗用者不知情，仍持原凭据）",
         f"POST /api/tasks/{t2['task_id']}/revoke")
    revoke_task(ctx["s_alice"], t2["task_id"])
    step("操作：撤销后立即以原令牌 + 原任务凭据重放同一查询（令牌未过期）",
         "POST /api/tools/order.read  body={order_id: ORD-1001}")
    r = tools_call(ctx["tok_cust"], t2["task_id"], cred2, "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("CRED-03", "撤销后重放", "撤销任务后同材料重放 -> 应用授权拒绝（非令牌过期）",
        r.status_code == 403 and b["error"]["code"] == "task_revoked",
        f"code={b['error']['code']}——令牌未过期，失败源于在线状态核验")
    for k in ("cred_task", "t_cred", "cred_cred"):
        ctx.pop(k, None)  # 任务已撤销，后续用例需自建新任务


@register("CRED-04", "停用Agent")
def case_cred_04(ctx):
    print("\n[CRED-04] 另一未撤销任务 + 统一入口停用 Agent")
    ensure_ctx(ctx, "s_carol", "tok_cust")
    step("前置：alice 创建一个全新未撤销任务（ORD-1001）并导出凭据",
         "POST /api/tasks -> POST /api/internal/test-export-credential")
    t4 = create_task(ctx["s_alice"], "order.read", {"type": "order_ids", "order_ids": ["ORD-1001"]})
    cred4b = export_cred(t4["task_id"])
    step("操作：carol 经统一入口停用客服 Agent（两阶段：应用侧准入 + Keycloak 客户端）",
         "POST /api/admin/agents/customer-service-agent/action {disable}")
    r = agent_action(ctx["s_carol"], "customer-service-agent", "disable")
    b = unwrap(r)
    sub("CRED-04", "停用Agent", "统一入口两阶段停用完成",
        r.status_code == 200 and b["phases"]["app_side"] == "ok" and b["phases"]["oauth_server"] == "ok")
    step(f"操作：停用后以旧令牌 + 未撤销任务 {t4['task_id']} 凭据调用工具",
         "POST /api/tools/order.read  Bearer <停用前令牌>")
    r = tools_call(ctx["tok_cust"], t4["task_id"], cred4b, "order.read", {"order_id": "ORD-1001"})
    b = unwrap(r)
    sub("CRED-04", "停用Agent", "停用后已有令牌调用 -> 拒绝（应用侧在线核验）",
        r.status_code == 403 and b["error"]["code"] == "agent_disabled",
        f"code={b['error']['code']}")
    step("操作：停用期间客服 Agent 再申请新令牌",
         f"POST {TOKEN_EP} (client={CUST_ID})")
    r = kc_token(CUST_ID, CUST_SEC, scope="order.read")
    sub("CRED-04", "停用Agent", "停用期间新令牌申请亦失败（授权服务侧）",
        r.status_code == 401, f"error={r.json().get('error')}")
    step("恢复：重新启用客服 Agent（保证后续用例/演示可用）",
         "POST /api/admin/agents/customer-service-agent/action {enable}")
    agent_action(ctx["s_carol"], "customer-service-agent", "enable")


# ---------- 主流程 ----------

def main():
    ap = argparse.ArgumentParser(description="阶段2验收（固定请求回放）")
    ap.add_argument("--case", help="仅复现指定用例（逗号分隔，如 AUTH-14 或 CRED-01,CRED-03）；"
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
        print(f"== 阶段2单案例复现：{', '.join(selected)}（固定请求回放，Agent=固定解析）==\n")
    else:
        print("== 阶段2验收：AUTH-14 委托链、AUTH-11 正常对照、审批/幂等、CRED-01~04（固定请求回放，Agent=固定解析）==\n")

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
        print("（单案例复现模式：未写报告；全量验收请运行不带 --case 的完整脚本）")
    else:
        write_report()
    return 0 if all_pass else 1


def write_report():
    lines = ["# 阶段2验收报告：委托链、审批、幂等与凭据盗用实验",
             "",
             f"生成时间：{__import__('datetime').datetime.now().isoformat(timespec='seconds')}",
             "",
             "模式：固定请求回放（不涉及真实模型）。测试执行凭据经受控测试通道加载，仅展示脱敏摘要。",
             "",
             "| 编号 | 子项 | 结果 | 证据 |",
             "| --- | --- | --- | --- |"]
    for cid, case in CASES.items():
        for s in case["subs"]:
            lines.append(f"| {cid} | {s['name']} | {'PASS' if s['ok'] else 'FAIL'} | {s['note']} |")
    lines += [
        "",
        "## 结论要点",
        "",
        "1. 委托与执行权限分离：客服 Agent 持 refund.delegate 仅能提交委托；退款执行需要退款 Agent 的 refund.execute 令牌与受限子任务凭据。",
        "2. 受限子任务：更换订单（order_not_in_subtask）、提高金额（amount_exceeds_limit）、撤销父任务（parent_task_revoked）分别被拒，子任务不能扩大父任务授权范围。",
        "3. 审批绑定子任务、工具与关键参数：修改金额产生的新子任务不沿用旧审批（approval_required），需独立批准。",
        "4. 幂等：同一子任务重复执行返回既有退款单，不重复产生业务操作。",
        "5. Bearer 令牌防护边界：令牌+有效任务凭据可冒用完成范围内操作（CRED-02）；任务撤销（CRED-03）与 Agent 停用（CRED-04）通过在线状态核验阻断，均非依赖令牌自然过期。",
    ]
    out = ROOT / "reports" / "auth-phase2.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告已写入 {out}")


if __name__ == "__main__":
    sys.exit(main())
