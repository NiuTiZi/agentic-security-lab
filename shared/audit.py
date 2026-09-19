"""统一审计事件：六层展示口径 + 不落完整令牌/密钥。"""
import hashlib
import json
import uuid
from datetime import datetime

SCHEMA = """
create table if not exists audit_events(
  id integer primary key autoincrement,
  ts text not null,
  service text not null,
  actor_type text,
  actor_id text,
  event text not null,
  decision text,
  layer text,
  code text,
  reason text,
  task_id text,
  trace_id text,
  detail text
);
"""

# 实验界面六层展示口径（需求稿 6.8）
LAYERS = ["客户端认证", "令牌签发", "JWT 验证", "scope 检查", "任务与用户授权", "业务执行"]


def init(conn) -> None:
    conn.executescript(SCHEMA)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


def record(conn, *, service: str, event: str, actor_type: str = "", actor_id: str = "",
           decision: str = "", layer: str = "", code: str = "", reason: str = "",
           task_id: str = "", trace_id: str = "", detail: dict | None = None) -> None:
    conn.execute(
        "insert into audit_events(ts,service,actor_type,actor_id,event,decision,layer,code,reason,task_id,trace_id,detail)"
        " values(?,?,?,?,?,?,?,?,?,?,?,?)",
        (now_iso(), service, actor_type, actor_id, event, decision, layer, code, reason,
         task_id, trace_id, json.dumps(detail, ensure_ascii=False) if detail else None),
    )


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]
