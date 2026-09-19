"""可信后台存储：用户/会话/Agent注册表/订单登记/任务授权记录/执行凭据 + 种子数据。"""
import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta

from shared import audit

SCHEMA = """
create table if not exists users(
  user_id text primary key,
  username text unique not null,
  password_hash text not null,
  display_name text not null,
  role text not null,
  dept text not null,
  perms text not null,
  active integer not null default 1
);
create table if not exists user_sessions(
  token_hash text primary key,
  user_id text not null,
  created_at text not null,
  expires_at text not null
);
create table if not exists agents(
  agent_id text primary key,
  display_name text not null,
  oauth_client_id text not null,
  active integer not null default 1
);
create table if not exists orders_registry(
  order_id text primary key,
  owner_id text not null,
  title text not null,
  amount_cents integer not null
);
create table if not exists task_grants(
  grant_id text primary key,
  task_id text unique not null,
  user_id text not null,
  agent_id text not null,
  operation text not null,
  resource_json text not null,
  status text not null default 'active',
  auth_version integer not null default 1,
  created_at text not null,
  expires_at text not null,
  parent_task_id text,
  approval_status text not null default 'not_required'
);
create table if not exists approvals(
  approval_id text primary key,
  task_id text not null,
  grant_id text not null,
  approver_id text not null,
  tool text not null,
  params_json text not null,
  status text not null,
  created_at text not null,
  decided_at text not null
);
create table if not exists exec_credentials(
  cred_id text primary key,
  grant_id text not null,
  agent_id text not null,
  secret_hash text not null,
  status text not null default 'active',
  created_at text not null,
  expires_at text not null
);
create index if not exists idx_exec_hash on exec_credentials(secret_hash);
create table if not exists test_credentials(
  cred_id text primary key,
  task_id text not null,
  secret text not null,
  created_at text not null
);
"""

# 本地教学账号（演示用，非 OIDC；用户 OIDC 为后续扩展项）
SEED_USERS = [
    # (user_id, username, password, display, role, dept, perms)
    ("u_alice", "alice", "alice123", "张敏（客服A·华东组）", "customer_service", "dept-east",
     ["order.read", "docs.read", "refund.request"]),
    ("u_bob", "bob", "bob123", "王强（客服B·华北组）", "customer_service", "dept-north",
     ["order.read", "docs.read", "refund.request"]),
    ("u_carol", "carol", "carol123", "赵静（审批人·财务）", "approver", "dept-finance",
     ["order.read", "docs.read", "refund.approve"]),
]

SEED_AGENTS = [
    ("customer-service-agent", "客服 Agent", "customer-service-agent"),
    ("refund-agent", "退款 Agent", "refund-agent"),
]

# 订单登记表（仅归属与概要，供任务创建核验；业务明细在工具服务）
SEED_ORDERS = [
    ("ORD-1001", "u_alice", "无线蓝牙耳机", 29900),
    ("ORD-1002", "u_alice", "机械键盘", 59900),
    ("ORD-2001", "u_bob", "27寸显示器", 159900),
    ("ORD-2002", "u_bob", "USB-C 扩展坞", 39900),
]


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 60000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 60000).hex()
    return secrets.compare_digest(calc, digest)


def now_plus(minutes: int) -> str:
    return (datetime.now().astimezone() + timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _migrate(conn: sqlite3.Connection) -> None:
    cols = {r["name"] for r in conn.execute("pragma table_info(task_grants)").fetchall()}
    if "parent_task_id" not in cols:
        conn.execute("alter table task_grants add column parent_task_id text")
    if "approval_status" not in cols:
        conn.execute("alter table task_grants add column approval_status text not null default 'not_required'")
    for row in conn.execute("select user_id, perms from users").fetchall():
        perms = json.loads(row["perms"])
        changed = False
        if "refund.request" not in perms and "refund.approve" not in perms:
            perms = perms + ["refund.request"]  # 阶段2迁移：退款申请权限
            changed = True
        # 阶段3迁移：出站消息权限单独授予 alice（RISK 实验前提：合法出站样例需要，
        # 需求稿6.5 message.send 按实验配置授予，报告中披露）
        if row["user_id"] == "u_alice" and "message.send" not in perms:
            perms = perms + ["message.send"]
            changed = True
        if changed:
            conn.execute("update users set perms=? where user_id=?",
                         (json.dumps(perms), row["user_id"]))


def init(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    _migrate(conn)
    audit.init(conn)
    if conn.execute("select count(*) from users").fetchone()[0] == 0:
        for uid, uname, pwd, disp, role, dept, perms in SEED_USERS:
            conn.execute(
                "insert into users(user_id,username,password_hash,display_name,role,dept,perms,active) values(?,?,?,?,?,?,?,1)",
                (uid, uname, hash_password(pwd), disp, role, dept, json.dumps(perms)))
        for aid, disp, cid in SEED_AGENTS:
            conn.execute("insert into agents(agent_id,display_name,oauth_client_id,active) values(?,?,?,1)",
                         (aid, disp, cid))
        for oid, owner, title, amount in SEED_ORDERS:
            conn.execute("insert into orders_registry(order_id,owner_id,title,amount_cents) values(?,?,?,?)",
                         (oid, owner, title, amount))


def next_task_id(conn: sqlite3.Connection) -> str:
    n = conn.execute("select count(*) from task_grants").fetchone()[0] + 1
    return f"T-{n:04d}"
