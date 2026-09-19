"""退款 Agent :8200 —— 独立 OAuth 客户端，仅 refund.execute 权限。

仅执行委托链签发的受限子任务（refund.execute）：核验用户会话与子任务归属后，
经统一执行入口调用工具服务。审批、金额上限、订单绑定与幂等在工具服务权威核验。
"""
import json

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from shared import agent_runtime as rt
from shared import audit, config, db as dbm
from shared.token_client import AgentTokenClient

app = FastAPI(title="退款 Agent")
conn = dbm.connect("agent_refund.db")
rt.init_store(conn)
tokens = AgentTokenClient(config.REFUND_AGENT_CLIENT_ID, config.REFUND_AGENT_CLIENT_SECRET)

SERVICE = "agent_refund"


class TaskContextIn(BaseModel):
    task_id: str
    user_id: str
    agent_id: str
    operation: str
    resource: dict
    exec_credential: str
    expires_at: str


@app.post("/internal/task-context")
def task_context(body: TaskContextIn, x_internal_key: str = Header(default="")):
    if not config.INTERNAL_API_KEY or x_internal_key != config.INTERNAL_API_KEY:
        raise HTTPException(401, "内部通道认证失败")
    rt.upsert_task_context(conn, body.model_dump())
    audit.record(conn, service=SERVICE, event="task_context_received", actor_type="system",
                 actor_id="backend", decision="allow", task_id=body.task_id,
                 detail={"operation": body.operation,
                         "credential_digest": audit.token_digest(body.exec_credential)})
    return {"ok": True}


class MessageIn(BaseModel):
    task_id: str
    message: str


@app.post("/api/agent/message")
def message(body: MessageIn, x_session_token: str = Header(default="")):
    """退款执行入口：仅接受受限子任务（refund.execute）的执行指令。

    会话核验 + 子任务归属核验后，按子任务授权参数执行（审批/上限/幂等在工具端权威核验）。
    核验失败返回结构化结果（ok=False + 六层链 + 错误码），不掩盖根因（如父任务级联撤销）。
    """
    trace_id = audit.new_trace_id()

    def deny(code: str, reason: str, actor_id: str = "unknown"):
        audit.record(conn, service=SERVICE, event="conversation_resolve", actor_type="user",
                     actor_id=actor_id, decision="deny", layer="任务与用户授权", code=code,
                     reason=reason, task_id=body.task_id, trace_id=trace_id)
        chain = [rt.mark_stub(l) for l in audit.LAYERS[:4]]
        chain.append({"layer": "任务与用户授权", "status": "fail", "detail": reason})
        chain.append({"layer": "业务执行", "status": "skipped", "detail": "未到达"})
        return {"ok": False, "reply": f"退款未执行。失败层：任务与用户授权；原因：{reason}。",
                "execution": {"operation": "refund.execute", "params": None, "chain": chain,
                              "result": None,
                              "error": {"layer": "任务与用户授权", "code": code, "reason": reason}},
                "trace_id": trace_id}

    try:
        with httpx.Client(timeout=10, trust_env=False) as c:
            r = c.post(f"{config.BACKEND_URL}/api/internal/resolve-task",
                       headers={"X-Internal-Key": config.INTERNAL_API_KEY},
                       json={"session_token": x_session_token, "task_id": body.task_id})
        v = r.json()
    except httpx.ConnectError:
        raise HTTPException(503, "后台不可用")
    if r.status_code != 200 or not v.get("ok"):
        return deny(v.get("code", "resolve_failed"), v.get("reason", "会话或任务无效"))

    ctx = rt.load_task_context(conn, body.task_id)
    if ctx is None:
        return deny("task_context_missing", "子任务上下文不存在或已失效", v["user_id"])

    if ctx["operation"] != "refund.execute":
        return deny("not_refund_subtask", f"任务 {body.task_id} 不是退款执行子任务", v["user_id"])

    if "退款" not in body.message and "执行" not in body.message:
        return {"ok": True, "reply": "我是退款 Agent，仅执行已审批的退款子任务。请说“执行退款”。",
                "execution": None, "trace_id": trace_id}

    resource = json.loads(ctx["resource_json"])
    params = {"order_id": resource.get("order_id"),
              "amount_cents": resource.get("amount_limit_cents")}
    audit.record(conn, service=SERVICE, event="intent_parse", actor_type="user",
                 actor_id=v["user_id"], decision="allow", task_id=body.task_id,
                 trace_id=trace_id,
                 detail={"message": body.message, "operation": "refund.execute", "params": params})

    ok, chain, data, err = rt.execute_tool(conn, SERVICE, tokens, ctx,
                                           "refund.execute", params, trace_id)
    if ok:
        refund = data.get("refund", {})
        if data.get("idempotent"):
            reply = (f"该子任务此前已执行过退款（幂等保护）：退款单 {refund.get('refund_id')}，"
                     f"金额 ¥{refund.get('amount_cents', 0) / 100:.2f}，不重复产生退款操作。")
        else:
            reply = (f"退款执行成功：退款单 {refund.get('refund_id')}，订单 {refund.get('order_id')}，"
                     f"金额 ¥{refund.get('amount_cents', 0) / 100:.2f}，订单状态已更新为“已退款”。")
    else:
        reply = (f"退款未执行。失败层：{err.get('layer')}；原因：{err.get('reason')}。")
    return {"ok": ok, "reply": reply,
            "execution": {"operation": "refund.execute", "params": params,
                          "chain": chain, "result": data if ok else None,
                          "error": err},
            "trace_id": trace_id}


@app.get("/health")
def health():
    return {"service": "agent_refund", "status": "ok"}
