"""可信后台 :8000 —— 用户会话、任务授权记录、执行凭据签发/撤销、Agent 两阶段停用。

任务执行凭据只通过可信内部通道推送给目标 Agent 运行层，不经网页展示、不进模型上下文。
"""
import hashlib
import json
import secrets
from datetime import datetime

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from services.backend import store
from shared import audit, config, db as dbm

app = FastAPI(title="agent-range 可信后台")
conn = dbm.connect("backend.db")
store.init(conn)

SESSION_TTL_MIN = 120
TASK_TTL_MIN = 15
TASK_AGENT_MAP = {  # 任务类型 -> 执行 Agent（退款经委托链到退款 Agent）
    "order.read": "customer-service-agent",
    "docs.read": "customer-service-agent",
    "refund.request": "customer-service-agent",   # 父任务：用户确认退款参数，客服 Agent 只能委托
    "refund.execute": "refund-agent",             # 子任务：由委托接口签发，用户不能直接创建
    "message.send": "customer-service-agent",     # 出站消息：收件人经用户确认固定为任务授权内容
}


# ---------- 依赖 ----------

def db():
    yield conn


def require_session(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    token = authorization[7:]
    h = hashlib.sha256(token.encode()).hexdigest()
    row = conn.execute("select * from user_sessions where token_hash=?", (h,)).fetchone()
    if not row or datetime.fromisoformat(row["expires_at"]) <= datetime.now().astimezone():
        raise HTTPException(401, "会话无效或已过期")
    user = conn.execute("select * from users where user_id=?", (row["user_id"],)).fetchone()
    if not user or not user["active"]:
        raise HTTPException(401, "用户已停用")
    return user


def require_internal(x_internal_key: str = Header(default="")):
    if not config.INTERNAL_API_KEY or x_internal_key != config.INTERNAL_API_KEY:
        raise HTTPException(401, "内部通道认证失败")
    return True


def require_admin(user=Depends(require_session)):
    if user["role"] not in ("approver", "admin"):
        raise HTTPException(403, "需要管理身份")
    return user


# ---------- 用户会话 ----------

class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginIn):
    user = conn.execute("select * from users where username=?", (body.username,)).fetchone()
    ok = bool(user) and user["active"] and store.verify_password(body.password, user["password_hash"])
    if not ok:
        audit.record(conn, service="backend", event="user_login", actor_type="user",
                     actor_id=body.username, decision="deny", reason="账号或密码错误")
        raise HTTPException(401, "账号或密码错误")
    token = "st_" + secrets.token_urlsafe(24)
    conn.execute("insert into user_sessions(token_hash,user_id,created_at,expires_at) values(?,?,?,?)",
                 (hashlib.sha256(token.encode()).hexdigest(), user["user_id"],
                  audit.now_iso(), store.now_plus(SESSION_TTL_MIN)))
    audit.record(conn, service="backend", event="user_login", actor_type="user",
                 actor_id=user["user_id"], decision="allow")
    return {"session_token": token,
            "user": _user_view(user)}


@app.post("/api/auth/logout")
def logout(user=Depends(require_session), authorization: str = Header(default="")):
    token = authorization[7:]
    conn.execute("delete from user_sessions where token_hash=?",
                 (hashlib.sha256(token.encode()).hexdigest(),))
    audit.record(conn, service="backend", event="user_logout", actor_type="user",
                 actor_id=user["user_id"], decision="allow")
    return {"ok": True}


def _user_view(user) -> dict:
    return {"user_id": user["user_id"], "username": user["username"],
            "display_name": user["display_name"], "role": user["role"],
            "dept": user["dept"], "perms": json.loads(user["perms"])}


@app.get("/api/me")
def me(user=Depends(require_session)):
    orders = conn.execute(
        "select order_id, title, amount_cents from orders_registry where owner_id=? order by order_id",
        (user["user_id"],)).fetchall()
    return {"user": _user_view(user), "orders": [dict(o) for o in orders]}


# ---------- 任务授权 ----------

class TaskIn(BaseModel):
    operation: str
    resource: dict  # {"type":"order_ids","order_ids":[...]} 或 {"type":"user_all"}


@app.post("/api/tasks")
def create_task(body: TaskIn, user=Depends(require_session)):
    perms = json.loads(user["perms"])
    if body.operation not in perms:
        raise HTTPException(403, f"当前用户无 {body.operation} 业务权限")
    if body.operation == "refund.execute":
        raise HTTPException(403, "退款执行子任务只能由委托链产生，用户不能直接创建")
    agent_id = TASK_AGENT_MAP.get(body.operation)
    if not agent_id:
        raise HTTPException(400, f"不支持的任务类型: {body.operation}")

    resource = body.resource
    if body.operation == "order.read" and resource.get("type") == "order_ids":
        for oid in resource.get("order_ids", []):
            row = conn.execute("select owner_id from orders_registry where order_id=?", (oid,)).fetchone()
            if not row or row["owner_id"] != user["user_id"]:
                raise HTTPException(403, f"订单 {oid} 不属于当前用户，不能纳入任务范围")

    if body.operation == "refund.request":
        # 敏感参数（订单、金额、用途）在此固定为用户确认值，后续委托只能在此范围内收缩
        if resource.get("type") != "refund":
            raise HTTPException(400, "退款任务 resource 需为 {type:'refund', order_id, amount_cents, reason}")
        order = conn.execute(
            "select * from orders_registry where order_id=?", (resource.get("order_id"),)).fetchone()
        if not order or order["owner_id"] != user["user_id"]:
            raise HTTPException(403, "退款订单不属于当前用户")
        amount = resource.get("amount_cents")
        if not isinstance(amount, int) or amount <= 0:
            raise HTTPException(400, "退款金额必须为正整数（分）")
        if amount > order["amount_cents"]:
            raise HTTPException(400, f"退款金额超过订单金额（¥{order['amount_cents'] / 100:.2f}）")
        if not resource.get("reason"):
            raise HTTPException(400, "缺少退款用途说明")

    if body.operation == "message.send":
        # 敏感参数（收件人）在此固定为用户确认值，发送只能面向确认过的收件人
        if resource.get("type") != "message":
            raise HTTPException(400, "消息任务 resource 需为 {type:'message', recipients:[...]}")
        recipients = resource.get("recipients")
        if (not isinstance(recipients, list) or not recipients
                or not all(isinstance(r, str) and "@" in r and " " not in r for r in recipients)):
            raise HTTPException(400, "recipients 需为非空字符串数组（邮箱格式）")
        if len(set(recipients)) != len(recipients):
            raise HTTPException(400, "recipients 不能有重复")

    trace_id = audit.new_trace_id()
    grant_id = "g_" + secrets.token_hex(8)
    cred_id = "ec_" + secrets.token_hex(6)
    cred_secret = "exc_" + secrets.token_urlsafe(24)
    task_id = store.next_task_id(conn)
    expires_at = store.now_plus(TASK_TTL_MIN)

    with dbm.tx(conn):
        conn.execute(
            "insert into task_grants(grant_id,task_id,user_id,agent_id,operation,resource_json,status,auth_version,created_at,expires_at)"
            " values(?,?,?,?,?,?,'active',1,?,?)",
            (grant_id, task_id, user["user_id"], agent_id, body.operation,
             json.dumps(resource, ensure_ascii=False), audit.now_iso(), expires_at))
        conn.execute(
            "insert into exec_credentials(cred_id,grant_id,agent_id,secret_hash,status,created_at,expires_at)"
            " values(?,?,?,?, 'active', ?, ?)",
            (cred_id, grant_id, agent_id, hashlib.sha256(cred_secret.encode()).hexdigest(),
             audit.now_iso(), expires_at))
        # 受控测试通道留存（需求稿6.10：实验服务端受控加载；生产部署不存在）
        conn.execute("insert into test_credentials(cred_id,task_id,secret,created_at) values(?,?,?,?)",
                     (cred_id, task_id, cred_secret, audit.now_iso()))

    # 执行凭据经可信内部通道推送目标 Agent 运行层（不返回给网页/模型）
    agent_row = conn.execute("select * from agents where agent_id=?", (agent_id,)).fetchone()
    agent_url = (config.CUSTOMER_AGENT_URL if agent_id == "customer-service-agent"
                 else config.REFUND_AGENT_URL)
    push = {"task_id": task_id, "user_id": user["user_id"], "agent_id": agent_id,
            "operation": body.operation, "resource": resource,
            "exec_credential": cred_secret, "expires_at": expires_at}
    try:
        with httpx.Client(timeout=10, trust_env=False) as c:
            r = c.post(f"{agent_url}/internal/task-context", json=push,
                       headers={"X-Internal-Key": config.INTERNAL_API_KEY})
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
    except Exception as e:
        audit.record(conn, service="backend", event="task_create", actor_type="user",
                     actor_id=user["user_id"], decision="deny", code="agent_push_failed",
                     reason=str(e), task_id=task_id, trace_id=trace_id)
        raise HTTPException(503, f"任务已记录但执行凭据推送失败: {e}")

    audit.record(conn, service="backend", event="task_create", actor_type="user",
                 actor_id=user["user_id"], decision="allow", task_id=task_id,
                 trace_id=trace_id,
                 detail={"operation": body.operation, "resource": resource,
                         "agent": agent_id, "expires_at": expires_at,
                         "exec_credential_digest": audit.token_digest(cred_secret)})
    return {"task_id": task_id, "operation": body.operation, "resource": resource,
            "agent": {"agent_id": agent_id, "display_name": agent_row["display_name"]},
            "expires_at": expires_at, "trace_id": trace_id}


@app.get("/api/tasks")
def list_tasks(user=Depends(require_session)):
    rows = conn.execute(
        "select task_id, operation, resource_json, status, created_at, expires_at, agent_id,"
        " parent_task_id, approval_status from task_grants where user_id=? order by created_at desc",
        (user["user_id"],)).fetchall()
    out = []
    for r in rows:
        expired = datetime.fromisoformat(r["expires_at"]) <= datetime.now().astimezone()
        status = r["status"] if not expired else ("expired" if r["status"] == "active" else r["status"])
        out.append({"task_id": r["task_id"], "operation": r["operation"],
                    "resource": json.loads(r["resource_json"]), "status": status,
                    "agent_id": r["agent_id"], "parent_task_id": r["parent_task_id"],
                    "approval_status": r["approval_status"],
                    "created_at": r["created_at"], "expires_at": r["expires_at"]})
    return {"tasks": out}


@app.post("/api/tasks/{task_id}/revoke")
def revoke_task(task_id: str, user=Depends(require_session)):
    row = conn.execute("select * from task_grants where task_id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "任务不存在")
    if row["user_id"] != user["user_id"] and user["role"] not in ("approver", "admin"):
        raise HTTPException(403, "只能撤销本人的任务")
    with dbm.tx(conn):
        conn.execute("update task_grants set status='revoked' where task_id=?", (task_id,))
        # 级联撤销子任务（父任务撤销约束后续子任务执行）
        children = conn.execute(
            "select grant_id from task_grants where parent_task_id=? and status='active'", (task_id,)).fetchall()
        conn.execute("update task_grants set status='revoked' where parent_task_id=? and status='active'",
                     (task_id,))
        for ch in children:
            conn.execute("update exec_credentials set status='revoked' where grant_id=? and status='active'",
                         (ch["grant_id"],))
        conn.execute("update exec_credentials set status='revoked' where grant_id=? and status='active'",
                     (row["grant_id"],))
    audit.record(conn, service="backend", event="task_revoke", actor_type="user",
                 actor_id=user["user_id"], decision="allow", task_id=task_id,
                 reason="用户主动撤销" if row["user_id"] == user["user_id"] else "管理员撤销",
                 detail={"cascaded_children": len(children)})
    return {"ok": True, "task_id": task_id, "status": "revoked",
            "cascaded_children": len(children)}


# ---------- 管理：Agent 两阶段停用（应用侧先行，授权服务随后） ----------

def _kc_admin_token() -> str:
    with httpx.Client(timeout=15, trust_env=False) as c:
        r = c.post(f"{config.KC_URL}/realms/master/protocol/openid-connect/token",
                   data={"grant_type": "password", "client_id": "admin-cli",
                         "username": config.KC_ADMIN_USERNAME,
                         "password": config.KC_ADMIN_PASSWORD})
    if r.status_code != 200:
        raise RuntimeError(f"Keycloak 管理员登录失败 HTTP {r.status_code}")
    return r.json()["access_token"]


def _kc_set_client_enabled(oauth_client_id: str, enabled: bool) -> None:
    tok = _kc_admin_token()
    with httpx.Client(timeout=15, trust_env=False) as c:
        h = {"Authorization": f"Bearer {tok}"}
        r = c.get(f"{config.KC_URL}/admin/realms/{config.KC_REALM}/clients",
                  headers=h, params={"clientId": oauth_client_id})
        matches = r.json()
        if not matches:
            raise RuntimeError(f"客户端 {oauth_client_id} 未找到")
        cl = matches[0]
        cl["enabled"] = enabled
        c.put(f"{config.KC_URL}/admin/realms/{config.KC_REALM}/clients/{cl['id']}",
              headers=h, json=cl).raise_for_status()


class AgentActionIn(BaseModel):
    action: str  # disable | enable


@app.get("/api/admin/agents")
def admin_agents(user=Depends(require_admin)):
    rows = conn.execute("select agent_id, display_name, oauth_client_id, active from agents").fetchall()
    return {"agents": [dict(r) for r in rows]}


@app.post("/api/admin/agents/{agent_id}/action")
def admin_agent_action(agent_id: str, body: AgentActionIn, user=Depends(require_admin)):
    row = conn.execute("select * from agents where agent_id=?", (agent_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Agent 不存在")
    if body.action not in ("disable", "enable"):
        raise HTTPException(400, "action 必须为 disable/enable")
    target = 0 if body.action == "disable" else 1

    # 阶段一：应用侧准入先禁止/恢复（工具执行前在线核验读取此状态）
    conn.execute("update agents set active=? where agent_id=?", (target, agent_id))
    app_side = "ok"
    oauth_side = "ok"
    # 阶段二：同步授权服务客户端状态；失败保留应用侧状态并报告部分完成
    try:
        _kc_set_client_enabled(row["oauth_client_id"], bool(target))
    except Exception as e:
        oauth_side = f"failed: {e}"

    status = "partial" if oauth_side != "ok" else ("disabled" if target == 0 else "enabled")
    audit.record(conn, service="backend", event="agent_status_change", actor_type="user",
                 actor_id=user["user_id"], decision="allow", task_id="",
                 detail={"agent_id": agent_id, "action": body.action,
                         "app_side": app_side, "oauth_server": oauth_side})
    return {"agent_id": agent_id, "status": status,
            "phases": {"app_side": app_side, "oauth_server": oauth_side}}


# ---------- 委托链：父任务(refund.request) -> 受限子任务(refund.execute) ----------

from shared.jwt_util import TokenError, token_scopes, verify_agent_token  # noqa: E402


class DelegateRefundIn(BaseModel):
    task_id: str            # 父任务编号
    order_id: str
    amount_cents: int       # 委托金额上限（只能 <= 父任务确认金额）
    reason: str = ""


@app.post("/api/internal/delegate-refund")
def delegate_refund(body: DelegateRefundIn, authorization: str = Header(default=""),
                    x_task_credential: str = Header(default=""),
                    _=Depends(require_internal)):
    """客服 Agent 提交退款委托（需求稿 6.5：发起委托与执行操作分开建模）。

    鉴权材料：客服 Agent OAuth 令牌（需 refund.delegate scope）+ 父任务执行凭据。
    后台核验通过后签发受限子任务（退款 Agent、同订单、金额上限收缩），等待审批。
    """
    trace_id = audit.new_trace_id()
    _actor = "unknown"

    def fail(status: int, layer: str, code: str, reason: str):
        audit.record(conn, service="backend", event="delegate_refund", actor_type="agent",
                     actor_id=_actor, decision="deny", layer=layer, code=code, reason=reason,
                     task_id=body.task_id, trace_id=trace_id,
                     detail={"order_id": body.order_id, "amount_cents": body.amount_cents})
        raise HTTPException(status, detail={"ok": False, "error": {"layer": layer, "code": code, "reason": reason},
                                            "trace_id": trace_id})

    # 层3：JWT 验证（委托方 Agent 身份）
    if not authorization.startswith("Bearer "):
        fail(401, "JWT 验证", "missing_token", "委托请求未携带 Agent 访问令牌")
    try:
        claims = verify_agent_token(authorization[7:])
    except TokenError as e:
        fail(401, "JWT 验证", e.code, e.message)
    _actor = claims.get("azp") or claims.get("client_id") or "unknown"

    # 层4：scope 检查（发起委托需要 refund.delegate，与执行权限 refund.execute 分离）
    if "refund.delegate" not in token_scopes(claims):
        fail(403, "scope 检查", "insufficient_scope",
             f"令牌缺少 refund.delegate（实际: {claims.get('scope')}）——发起委托与执行退款是不同权限")

    # 层5：父任务与用户授权（父执行凭据在线核验）
    v = internal_verify_exec(VerifyExecIn(task_id=body.task_id, exec_credential=x_task_credential,
                                          operation="refund.request", agent_client_id=_actor), True)
    if not v.get("allow"):
        fail(403, "任务与用户授权", v.get("code", "delegate_denied"), v.get("reason", "父任务核验未通过"))

    parent_resource = v["resource"]
    if parent_resource.get("type") != "refund":
        fail(403, "任务与用户授权", "not_a_refund_task", "父任务不是退款申请任务")
    if body.order_id != parent_resource.get("order_id"):
        fail(403, "任务与用户授权", "delegate_order_mismatch",
             f"委托订单 {body.order_id} 与父任务确认订单 {parent_resource.get('order_id')} 不符")
    if body.amount_cents <= 0:
        fail(400, "任务与用户授权", "delegate_amount_invalid", "委托金额必须为正整数（分）")
    if body.amount_cents > parent_resource.get("amount_cents", 0):
        fail(403, "任务与用户授权", "delegate_amount_exceeds_parent",
             f"委托金额 ¥{body.amount_cents / 100:.2f} 超出父任务确认金额 ¥{parent_resource.get('amount_cents', 0) / 100:.2f}"
             "（委托只能收缩权限，不能扩大）")

    # 层6：签发受限子任务（退款 Agent 执行，范围不大于父任务）
    sub_resource = {"type": "refund", "order_id": body.order_id,
                    "amount_limit_cents": body.amount_cents,
                    "reason": body.reason or parent_resource.get("reason", "")}
    grant_id = "g_" + secrets.token_hex(8)
    cred_id = "ec_" + secrets.token_hex(6)
    cred_secret = "exc_" + secrets.token_urlsafe(24)
    sub_task_id = store.next_task_id(conn)
    expires_at = store.now_plus(TASK_TTL_MIN)
    with dbm.tx(conn):
        conn.execute(
            "insert into task_grants(grant_id,task_id,user_id,agent_id,operation,resource_json,"
            "status,auth_version,created_at,expires_at,parent_task_id,approval_status)"
            " values(?,?,?,?,?,?,'active',1,?,?,?,'pending')",
            (grant_id, sub_task_id, v["user_id"], "refund-agent", "refund.execute",
             json.dumps(sub_resource, ensure_ascii=False), audit.now_iso(), expires_at, body.task_id))
        conn.execute(
            "insert into exec_credentials(cred_id,grant_id,agent_id,secret_hash,status,created_at,expires_at)"
            " values(?,?,?,?, 'active', ?, ?)",
            (cred_id, grant_id, "refund-agent", hashlib.sha256(cred_secret.encode()).hexdigest(),
             audit.now_iso(), expires_at))
        conn.execute("insert into test_credentials(cred_id,task_id,secret,created_at) values(?,?,?,?)",
                     (cred_id, sub_task_id, cred_secret, audit.now_iso()))

    # 子任务执行凭据经可信内部通道推送退款 Agent 运行层
    push = {"task_id": sub_task_id, "user_id": v["user_id"], "agent_id": "refund-agent",
            "operation": "refund.execute", "resource": sub_resource,
            "exec_credential": cred_secret, "expires_at": expires_at}
    try:
        with httpx.Client(timeout=10, trust_env=False) as c:
            r = c.post(f"{config.REFUND_AGENT_URL}/internal/task-context", json=push,
                       headers={"X-Internal-Key": config.INTERNAL_API_KEY})
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
    except Exception as e:
        audit.record(conn, service="backend", event="delegate_refund", actor_type="agent",
                     actor_id=_actor, decision="deny", code="agent_push_failed",
                     reason=str(e), task_id=sub_task_id, trace_id=trace_id)
        raise HTTPException(503, f"子任务已记录但执行凭据推送失败: {e}")

    audit.record(conn, service="backend", event="delegate_refund", actor_type="agent",
                 actor_id=_actor, decision="allow", task_id=sub_task_id, trace_id=trace_id,
                 detail={"parent_task_id": body.task_id, "operation": "refund.execute",
                         "resource": sub_resource, "approver_required": "refund.approve",
                         "exec_credential_digest": audit.token_digest(cred_secret)})
    return {"ok": True, "subtask_id": sub_task_id, "parent_task_id": body.task_id,
            "user": {"user_id": v["user_id"], "display_name": v["display_name"]},
            "resource": sub_resource, "approval_status": "pending",
            "expires_at": expires_at, "trace_id": trace_id}


# ---------- 审批流：绑定子任务、工具与关键业务参数 ----------

class ApprovalDecisionIn(BaseModel):
    decision: str  # approve | reject


@app.get("/api/approvals/pending")
def pending_approvals(user=Depends(require_admin)):
    rows = conn.execute(
        "select t.task_id, t.parent_task_id, t.resource_json, t.created_at, t.expires_at, u.display_name"
        " from task_grants t join users u on u.user_id=t.user_id"
        " where t.approval_status='pending' and t.status='active' order by t.created_at").fetchall()
    return {"pending": [{"task_id": r["task_id"], "parent_task_id": r["parent_task_id"],
                         "resource": json.loads(r["resource_json"]),
                         "user": r["display_name"],
                         "created_at": r["created_at"], "expires_at": r["expires_at"]} for r in rows]}


@app.post("/api/tasks/{task_id}/approval")
def approval_decision(task_id: str, body: ApprovalDecisionIn, user=Depends(require_admin)):
    if "refund.approve" not in json.loads(user["perms"]):
        raise HTTPException(403, "当前用户无 refund.approve 审批权限")
    if body.decision not in ("approve", "reject"):
        raise HTTPException(400, "decision 必须为 approve/reject")
    grant = conn.execute("select * from task_grants where task_id=?", (task_id,)).fetchone()
    if not grant:
        raise HTTPException(404, "任务不存在")
    if grant["approval_status"] != "pending":
        raise HTTPException(409, f"任务审批状态为 {grant['approval_status']}，不能重复审批")
    if grant["status"] != "active":
        raise HTTPException(409, f"任务已 {grant['status']}，不能审批")

    resource = json.loads(grant["resource_json"])
    # 审批绑定：用户、Agent、任务、工具及关键业务参数（订单、金额上限）
    approval = {"approval_id": "ap_" + secrets.token_hex(6), "task_id": task_id,
                "grant_id": grant["grant_id"], "approver_id": user["user_id"],
                "tool": grant["operation"],
                "params": {"order_id": resource.get("order_id"),
                           "amount_limit_cents": resource.get("amount_limit_cents")},
                "status": "approved" if body.decision == "approve" else "rejected",
                "created_at": grant["created_at"], "decided_at": audit.now_iso()}
    with dbm.tx(conn):
        conn.execute(
            "insert into approvals(approval_id,task_id,grant_id,approver_id,tool,params_json,status,created_at,decided_at)"
            " values(?,?,?,?,?,?,?,?,?)",
            (approval["approval_id"], task_id, grant["grant_id"], user["user_id"], grant["operation"],
             json.dumps(approval["params"], ensure_ascii=False), approval["status"],
             grant["created_at"], approval["decided_at"]))
        conn.execute("update task_grants set approval_status=? where task_id=?",
                     (approval["status"], task_id))
    audit.record(conn, service="backend", event="approval_decision", actor_type="user",
                 actor_id=user["user_id"], decision="allow", task_id=task_id,
                 detail={"decision": body.decision, "tool": grant["operation"],
                         "bound_params": approval["params"]})
    return {"ok": True, "task_id": task_id, "approval_status": approval["status"],
            "approval": approval}




class ResolveTaskIn(BaseModel):
    session_token: str
    task_id: str


@app.post("/api/internal/resolve-task")
def internal_resolve_task(body: ResolveTaskIn, _=Depends(require_internal)):
    """Agent 对话入口在线核验：用户会话有效 + 任务归属该用户。不返回执行凭据。"""
    h = hashlib.sha256(body.session_token.encode()).hexdigest()
    sess = conn.execute("select * from user_sessions where token_hash=?", (h,)).fetchone()
    if not sess or datetime.fromisoformat(sess["expires_at"]) <= datetime.now().astimezone():
        return {"ok": False, "code": "session_invalid", "reason": "用户会话无效或已过期"}
    grant = conn.execute("select * from task_grants where task_id=?", (body.task_id,)).fetchone()
    if not grant:
        return {"ok": False, "code": "task_not_found", "reason": "任务不存在"}
    if grant["user_id"] != sess["user_id"]:
        return {"ok": False, "code": "task_not_owned", "reason": "任务不属于当前会话用户"}
    if grant["status"] == "revoked":
        # 区分级联撤销根因：子任务因父任务撤销而失效时报告 parent_task_revoked
        if grant["parent_task_id"]:
            parent = conn.execute("select status from task_grants where task_id=?",
                                  (grant["parent_task_id"],)).fetchone()
            if parent and parent["status"] == "revoked":
                return {"ok": False, "code": "parent_task_revoked",
                        "reason": "父任务已撤销，子任务已级联失效"}
        return {"ok": False, "code": "task_revoked", "reason": "任务已被撤销"}
    if grant["status"] != "active" or datetime.fromisoformat(grant["expires_at"]) <= datetime.now().astimezone():
        return {"ok": False, "code": "task_expired", "reason": "任务已过期"}
    user = conn.execute("select * from users where user_id=?", (grant["user_id"],)).fetchone()
    return {"ok": True, "user_id": user["user_id"], "display_name": user["display_name"],
            "dept": user["dept"], "operation": grant["operation"],
            "resource": json.loads(grant["resource_json"])}


class VerifyExecIn(BaseModel):
    task_id: str
    exec_credential: str
    operation: str
    agent_client_id: str


@app.post("/api/internal/verify-exec")
def internal_verify_exec(body: VerifyExecIn, _=Depends(require_internal)):
    """工具服务执行前在线核验（无跨请求缓存）：凭据->任务->Agent绑定->准入->用户->操作。"""
    trace_id = audit.new_trace_id()
    digest = audit.token_digest(body.exec_credential)
    actor = f"agent:{body.agent_client_id}"

    def deny(code: str, reason: str):
        audit.record(conn, service="backend", event="verify_exec", actor_type="agent",
                     actor_id=actor, decision="deny", layer="任务与用户授权", code=code,
                     reason=reason, task_id=body.task_id, trace_id=trace_id,
                     detail={"operation": body.operation, "credential_digest": digest})
        return {"allow": False, "layer": "任务与用户授权", "code": code, "reason": reason,
                "trace_id": trace_id}

    cred = conn.execute(
        "select * from exec_credentials where secret_hash=?",
        (hashlib.sha256(body.exec_credential.encode()).hexdigest(),)).fetchone()
    if not cred:
        return deny("credential_invalid", "任务执行凭据无效（未知凭据）")
    grant = conn.execute("select * from task_grants where grant_id=?", (cred["grant_id"],)).fetchone()
    if not grant or grant["task_id"] != body.task_id:
        return deny("task_binding_mismatch", "执行凭据与任务编号不匹配")
    if grant["status"] == "revoked":
        # 级联撤销的子任务报告父任务撤销根因，避免 task_revoked 掩盖真实原因
        if grant["parent_task_id"]:
            parent = conn.execute("select status from task_grants where task_id=?",
                                  (grant["parent_task_id"],)).fetchone()
            if parent and parent["status"] == "revoked":
                return deny("parent_task_revoked", "父任务已撤销，子任务执行被拒绝")
        return deny("task_revoked", "任务已被撤销")
    if cred["status"] != "active":
        return deny("credential_invalid", "任务执行凭据已被单独撤销")
    if datetime.fromisoformat(cred["expires_at"]) <= datetime.now().astimezone():
        return deny("credential_expired", "任务执行凭据已过期")
    if datetime.fromisoformat(grant["expires_at"]) <= datetime.now().astimezone():
        return deny("task_expired", "任务已过期")
    # 子任务核验父任务状态：父任务撤销/过期后，子任务执行同样被拒绝
    if grant["parent_task_id"]:
        parent = conn.execute("select * from task_grants where task_id=?", (grant["parent_task_id"],)).fetchone()
        if not parent:
            return deny("parent_task_not_found", "父任务记录缺失，拒绝执行")
        if parent["status"] == "revoked":
            return deny("parent_task_revoked", "父任务已撤销，子任务执行被拒绝")
        if datetime.fromisoformat(parent["expires_at"]) <= datetime.now().astimezone():
            return deny("parent_task_expired", "父任务已过期，子任务执行被拒绝")
    agent = conn.execute("select * from agents where oauth_client_id=?", (body.agent_client_id,)).fetchone()
    if not agent or agent["agent_id"] != grant["agent_id"]:
        return deny("agent_mismatch", "执行凭据与调用方 Agent 不匹配")
    if not agent["active"]:
        return deny("agent_disabled", "Agent 已被停用（应用侧准入拒绝）")
    user = conn.execute("select * from users where user_id=?", (grant["user_id"],)).fetchone()
    if not user or not user["active"]:
        return deny("user_disabled", "任务原始用户已停用")
    if body.operation != grant["operation"]:
        return deny("operation_not_in_task", f"操作 {body.operation} 超出任务授权范围")

    audit.record(conn, service="backend", event="verify_exec", actor_type="agent",
                 actor_id=actor, decision="allow", layer="任务与用户授权",
                 task_id=body.task_id, trace_id=trace_id,
                 detail={"operation": body.operation, "credential_digest": digest})
    return {"allow": True, "user_id": user["user_id"], "display_name": user["display_name"],
            "dept": user["dept"], "operation": grant["operation"],
            "resource": json.loads(grant["resource_json"]),
            "approval_status": grant["approval_status"],
            "parent_task_id": grant["parent_task_id"], "trace_id": trace_id}


class TestExportIn(BaseModel):
    task_id: str


@app.post("/api/internal/test-export-credential")
def internal_test_export(body: TestExportIn, _=Depends(require_internal)):
    """受控测试通道（需求稿6.10）：仅供 AUTH/CRED 实验客户端在受控环境加载测试凭据。

    生产部署不存在此接口；每次导出均写入审计。
    """
    grant = conn.execute("select * from task_grants where task_id=?", (body.task_id,)).fetchone()
    if not grant:
        raise HTTPException(404, "任务不存在")
    cred = conn.execute(
        "select * from exec_credentials where grant_id=? and status='active'", (grant["grant_id"],)).fetchone()
    if not cred:
        raise HTTPException(404, "无有效执行凭据")
    # 凭据只存哈希，测试通道无法还原原文 —— 因此测试任务创建时同步留存原文（见 create_task 的 test_credentials 表）
    row = conn.execute("select secret from test_credentials where cred_id=?", (cred["cred_id"],)).fetchone()
    if not row:
        raise HTTPException(404, "测试凭据不可用（任务创建早于测试通道启用）")
    audit.record(conn, service="backend", event="test_credential_export", actor_type="system",
                 actor_id="test-client", decision="allow", task_id=body.task_id,
                 detail={"credential_digest": audit.token_digest(row["secret"])})
    return {"task_id": body.task_id, "exec_credential": row["secret"],
            "digest": audit.token_digest(row["secret"])}


@app.get("/health")
def health():
    return {"service": "backend", "status": "ok"}


@app.get("/api/inbox")
def inbox(user=Depends(require_session)):
    """本地测试接收端视图（RISK-04 观察点）：转发工具服务 inbox，供演示核对实际投递内容。"""
    try:
        with httpx.Client(timeout=10, trust_env=False) as c:
            r = c.get(f"{config.TOOLS_URL}/api/internal/inbox",
                      headers={"X-Internal-Key": config.INTERNAL_API_KEY})
    except httpx.ConnectError:
        raise HTTPException(503, "工具服务不可用")
    if r.status_code != 200:
        raise HTTPException(502, "接收端查询失败")
    return r.json()


@app.get("/api/experiment/config")
def experiment_config(user=Depends(require_session)):
    """聚合实验配置与风险披露（Agent 侧 + 工具侧），页面展示当前实验状态。"""
    out = {}
    for base in (config.CUSTOMER_AGENT_URL, config.TOOLS_URL):
        try:
            with httpx.Client(timeout=5, trust_env=False) as c:
                r = c.get(f"{base}/api/experiment/config")
            if r.status_code == 200:
                out.update(r.json().get("config", {}))
        except httpx.HTTPError:
            pass
    return {"ok": True, "config": out}


AGENT_EXP_KEYS = {"agent_mode", "llm_outbound_redact", "untrusted_marking", "runtime_task_check"}
TOOLS_EXP_KEYS = {"tools_task_verify", "tools_ownership_check", "outbound_dest_limit",
                  "outbound_redact", "injection_detect"}


@app.post("/api/experiment/config")
def experiment_config_set(changes: dict, user=Depends(require_session)):
    """受控实验配置切换（仅影响实验环境）：按开关归属分发到对应服务的内部端点。"""
    agent_changes = {k: v for k, v in changes.items() if k in AGENT_EXP_KEYS}
    tools_changes = {k: v for k, v in changes.items() if k in TOOLS_EXP_KEYS}
    unknown = set(changes) - AGENT_EXP_KEYS - TOOLS_EXP_KEYS
    if unknown:
        raise HTTPException(400, f"未知实验开关: {sorted(unknown)}")
    if not agent_changes and not tools_changes:
        raise HTTPException(400, "缺少有效开关")
    failed = []
    for base, payload in ((config.CUSTOMER_AGENT_URL, agent_changes),
                          (config.TOOLS_URL, tools_changes)):
        if not payload:
            continue
        try:
            with httpx.Client(timeout=5, trust_env=False) as c:
                r = c.post(f"{base}/api/internal/experiment-config",
                           headers={"X-Internal-Key": config.INTERNAL_API_KEY},
                           json={"changes": payload})
            if r.status_code != 200:
                failed.append(base)
        except httpx.HTTPError:
            failed.append(base)
    if failed:
        raise HTTPException(502, f"实验配置下发失败: {failed}")
    return experiment_config(user)


@app.post("/api/experiment/reset")
def experiment_reset(user=Depends(require_session)):
    """实验重置：恢复默认防护配置并清空接收端与注入文档。"""
    for base in (config.CUSTOMER_AGENT_URL, config.TOOLS_URL):
        try:
            with httpx.Client(timeout=5, trust_env=False) as c:
                c.post(f"{base}/api/internal/experiment-reset",
                       headers={"X-Internal-Key": config.INTERNAL_API_KEY})
        except httpx.HTTPError:
            raise HTTPException(502, f"实验重置失败: {base}")
    return experiment_config(user)


@app.get("/")
def index():
    return FileResponse(config.ROOT / "services" / "backend" / "static" / "index.html")
