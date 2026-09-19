"""客服 Agent :8100 —— 任务对话入口 + 统一执行入口。

对话模式（实验配置 agent_mode，默认 llm）：
- llm：DeepSeek 真实工具调用循环（需求稿7），失败明确上报，不静默切换固定规则；
- fixed：固定解析回放（需求稿8 固定请求模式，阶段1/2 验收使用）。
执行凭据由本服务保管并注入工具调用，不进入提示词与回复。
"""
import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from shared import agent_runtime as rt
from shared import audit, config, db as dbm, exp_config
from shared.token_client import AgentTokenClient

app = FastAPI(title="客服 Agent")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["*"], allow_headers=["*"])

conn = dbm.connect("agent_customer.db")
rt.init_store(conn)
tokens = AgentTokenClient(config.CUSTOMER_AGENT_CLIENT_ID, config.CUSTOMER_AGENT_CLIENT_SECRET)

SERVICE = "agent_customer"
EXP = exp_config.ExpConfig(exp_config.AGENT_DEFAULTS)


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


def _current_mode() -> str:
    mode = EXP.get("agent_mode")
    return mode if mode in ("llm", "fixed") else config.AGENT_MODE


class MessageIn(BaseModel):
    task_id: str
    message: str


@app.post("/api/agent/message")
def message(body: MessageIn, x_session_token: str = Header(default="")):
    trace_id = audit.new_trace_id()

    # 对话入口核验：用户会话 + 任务归属（后台在线核验，防止串任务对话）
    try:
        with httpx.Client(timeout=10, trust_env=False) as c:
            r = c.post(f"{config.BACKEND_URL}/api/internal/resolve-task",
                       headers={"X-Internal-Key": config.INTERNAL_API_KEY},
                       json={"session_token": x_session_token, "task_id": body.task_id})
        v = r.json()
    except httpx.ConnectError:
        raise HTTPException(503, "后台不可达")
    if r.status_code != 200 or not v.get("ok"):
        audit.record(conn, service=SERVICE, event="conversation_resolve", actor_type="user",
                     actor_id="unknown", decision="deny", code=v.get("code", "resolve_failed"),
                     reason=v.get("reason", ""), task_id=body.task_id, trace_id=trace_id)
        raise HTTPException(403, f"对话核验失败: {v.get('reason', '会话或任务无效')}")

    ctx = rt.load_task_context(conn, body.task_id)
    if ctx is None:
        audit.record(conn, service=SERVICE, event="conversation_resolve", actor_type="user",
                     actor_id=v["user_id"], decision="deny", code="task_context_missing",
                     reason="任务上下文不存在或已失效", task_id=body.task_id, trace_id=trace_id)
        raise HTTPException(403, "任务上下文不存在或已失效，请重新发起任务")

    if _current_mode() == "llm":
        return _message_llm(body, v, ctx, trace_id)
    return _message_fixed(body, v, ctx, trace_id)


def _message_llm(body: MessageIn, v: dict, ctx, trace_id: str) -> dict:
    """真实模型路径：DeepSeek 工具调用循环。"""
    result = rt.run_llm_loop(conn, SERVICE, tokens, ctx, v.get("display_name", ""),
                             body.message, trace_id, EXP.get_all())
    audit.record(conn, service=SERVICE, event="llm_conversation", actor_type="user",
                 actor_id=v["user_id"], decision="allow" if result["ok"] else "deny",
                 code=(result["error"] or {}).get("code", ""), task_id=body.task_id,
                 trace_id=trace_id,
                 detail={"mode": "llm", "model": result["model"].get("model"),
                         "rounds": result["model"].get("rounds"),
                         "proposed": [e["operation"] for e in result["executions"]],
                         "outcomes": [("ok" if e["ok"] else (e["error"] or {}).get("code", "?"))
                                      for e in result["executions"]]})
    # execution 字段保留委托结果（若有）供既有消费方使用；executions 为完整列表
    delegate_exec = next((e for e in result["executions"] if e["operation"] == "refund.delegate"),
                         None)
    execution = delegate_exec or (result["executions"][-1] if result["executions"] else None)
    return {"ok": result["ok"], "reply": result["reply"],
            "execution": execution, "executions": result["executions"],
            "model": {"mode": "llm", **result["model"]},
            "error": result["error"], "trace_id": trace_id}


def _message_fixed(body: MessageIn, v: dict, ctx, trace_id: str) -> dict:
    """固定解析回放路径（阶段1/2 验收，页面明确标注为回放模式）。"""
    intent = rt.parse_intent(body.message)
    if intent is None:
        audit.record(conn, service=SERVICE, event="intent_parse", actor_type="user",
                     actor_id=v["user_id"], decision="allow", task_id=body.task_id,
                     trace_id=trace_id, detail={"message": body.message, "result": "no_tool_call"})
        return {"ok": True, "reply": "抱歉，我目前支持：查询订单（提供订单号或说“查我的所有订单”）、检索部门资料。",
                "execution": None, "trace_id": trace_id}

    audit.record(conn, service=SERVICE, event="intent_parse", actor_type="user",
                 actor_id=v["user_id"], decision="allow", task_id=body.task_id,
                 trace_id=trace_id,
                 detail={"message": body.message, "operation": intent["operation"],
                         "params": intent["params"]})

    if intent["operation"] == "refund.request":
        # 委托路径：客服 Agent 只提交退款委托，不直接执行退款（发起委托与执行操作分开建模）
        ok, chain, data, err = rt.delegate_refund(conn, SERVICE, tokens, ctx,
                                                  intent["params"], trace_id)
        if ok:
            reply = (f"退款委托已提交。受限子任务 {data['subtask_id']} 已签发给退款 Agent"
                     f"（订单 {data['resource']['order_id']}，金额上限 ¥{data['resource']['amount_limit_cents'] / 100:.2f}），"
                     f"等待审批人批准后由退款 Agent 执行。")
        else:
            reply = (f"退款委托未提交。失败层：{err.get('layer')}；原因：{err.get('reason')}。"
                     f"如需调整金额或订单，请重新确认任务参数。")
        return {"ok": ok, "reply": reply,
                "execution": {"operation": "refund.delegate", "params": intent["params"],
                              "chain": chain, "result": data if ok else None,
                              "error": err},
                "trace_id": trace_id}

    ok, chain, data, err = rt.execute_tool(conn, SERVICE, tokens, ctx,
                                           intent["operation"], intent["params"], trace_id)

    if ok:
        reply = _render_reply(intent, data)
    else:
        reply = (f"该操作未执行。失败层：{err.get('layer')}；原因：{err.get('reason')}。"
                 f"如需该操作，请在任务发起页创建对应类型的新任务。")

    return {"ok": ok, "reply": reply,
            "execution": {"operation": intent["operation"], "params": intent["params"],
                          "chain": chain, "result": data if ok else None,
                          "error": err},
            "trace_id": trace_id}


def _render_reply(intent: dict, data: dict) -> str:
    if intent["operation"] == "order.read":
        if "order" in data:
            o = data["order"]
            return (f"订单 {o['order_id']}（{o['title']}）查询成功："
                    f"金额 ¥{o['amount_cents'] / 100:.2f}，状态 {o['status']}，"
                    f"收货信息 {o['address']}，联系电话 {o['customer_phone']}。")
        orders = data.get("orders", [])
        if not orders:
            return "查询完成，您名下暂无订单。"
        lines = [f"- {o['order_id']} {o['title']}：¥{o['amount_cents'] / 100:.2f}（{o['status']}）"
                 for o in orders]
        return "您名下全部订单：\n" + "\n".join(lines)
    if intent["operation"] == "docs.read":
        if "doc" in data:
            d = data["doc"]
            return f"资料《{d['title']}》：{d['content']}"
        docs = data.get("docs", [])
        if not docs:
            return "您部门暂无可检索资料。"
        lines = [f"- {d['doc_id']}《{d['title']}》" for d in docs]
        return "您部门的资料列表：\n" + "\n".join(lines)
    return "操作已完成。"


# ---------- 实验配置（需求稿9.1：仅内部通道，默认全防护，变更入审计） ----------

class ExpConfigIn(BaseModel):
    changes: dict


@app.get("/api/experiment/config")
def exp_get():
    cfg = EXP.get_all()
    cfg["agent_mode"] = _current_mode()
    return {"ok": True, "config": cfg, "risk_flags": EXP.risk_flags(),
            "risk_desc": exp_config.describe_risk(EXP.risk_flags())}


@app.post("/api/internal/experiment-config")
def exp_set(body: ExpConfigIn, x_internal_key: str = Header(default="")):
    if not config.INTERNAL_API_KEY or x_internal_key != config.INTERNAL_API_KEY:
        raise HTTPException(401, "内部通道认证失败")
    try:
        cfg = EXP.update(body.changes)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit.record(conn, service=SERVICE, event="experiment_config", actor_type="system",
                 actor_id="runner", decision="allow",
                 detail={"changes": body.changes, "risk_flags": EXP.risk_flags()})
    cfg["agent_mode"] = _current_mode()
    return {"ok": True, "config": cfg, "risk_flags": EXP.risk_flags()}


@app.post("/api/internal/experiment-reset")
def exp_reset(x_internal_key: str = Header(default="")):
    if not config.INTERNAL_API_KEY or x_internal_key != config.INTERNAL_API_KEY:
        raise HTTPException(401, "内部通道认证失败")
    cfg = EXP.reset()
    audit.record(conn, service=SERVICE, event="experiment_config", actor_type="system",
                 actor_id="runner", decision="allow", detail={"reset": True})
    cfg["agent_mode"] = _current_mode()
    return {"ok": True, "config": cfg}


@app.get("/health")
def health():
    return {"service": "agent_customer", "status": "ok", "mode": _current_mode(),
            "risk_flags": EXP.risk_flags()}
