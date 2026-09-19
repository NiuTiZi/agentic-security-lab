"""DeepSeek 客户端 + 统一出站适配层（需求稿7）。

出站适配层职责：
1. 数据策略执行——每次实际模型请求发出前，对全部待发送内容（用户输入、工具结果、
   多轮历史）执行受限字段检查：虚构手机号按任务隔离映射替换为占位符，可逆恢复仅用于
   最终对用户的可见回复，不因模型要求而恢复原值（RISK-01）。
2. 证据留存——记录实际序列化请求体摘要、受限字段出现情况与脱敏状态；实验核查使用
   全文（均为虚构标记数据），日常审计仅保留摘要。
3. 凭据边界自检——Agent OAuth 令牌与客户端密钥不得进入模型请求。

模型 API 失败时抛出 LLMError，由调用方明确上报，不允许静默切换为固定规则。
"""
import hashlib
import json
import re
import threading
import time

import httpx

from . import config

PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")  # 虚构手机号标记（138xxx/139xxx）
PLACEHOLDER_FMT = "‹脱敏手机号#{n}›"

_maps_lock = threading.Lock()
_task_maps: dict[str, dict[str, str]] = {}  # task_id -> {placeholder: original}


class LLMError(RuntimeError):
    """模型 API 调用失败（网络/HTTP/格式）。"""


def find_restricted(text: str) -> list[str]:
    """返回文本中出现的受限字段（用于证据与检测，不修改原文）。"""
    return PHONE_RE.findall(text or "")


def redact_text(text: str, task_id: str) -> tuple[str, list[str]]:
    """按任务隔离映射替换受限字段。同任务内相同号码使用相同占位符（跨轮稳定）。"""
    if not text:
        return text, []
    with _maps_lock:
        mapping = _task_maps.setdefault(task_id, {})
        inv = {orig: ph for ph, orig in mapping.items()}
    found: list[str] = []

    def _sub(m: re.Match) -> str:
        orig = m.group(0)
        found.append(orig)
        ph = inv.get(orig)
        if ph is None:
            ph = PLACEHOLDER_FMT.format(n=len(mapping) + 1)
            with _maps_lock:
                mapping[ph] = orig
                inv[orig] = ph
        return ph

    return PHONE_RE.sub(_sub, text), found


def restore_text(text: str, task_id: str) -> str:
    """占位符恢复原值（仅用于本任务用户可见的最终回复；不用于工具参数）。"""
    if not text:
        return text
    with _maps_lock:
        mapping = dict(_task_maps.get(task_id, {}))
    for ph, orig in mapping.items():
        text = text.replace(ph, orig)
    return text


def drop_task_map(task_id: str) -> None:
    with _maps_lock:
        _task_maps.pop(task_id, None)


def _evidence_path():
    config.EXPERIMENT_DIR.mkdir(parents=True, exist_ok=True)
    return config.EXPERIMENT_DIR / "outbound_evidence.jsonl"


def record_evidence(entry: dict) -> None:
    """追加出站证据记录（JSONL）。含实际请求体全文（虚构数据），供实验核查。"""
    with open(_evidence_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _check_credential_leak(payload: dict) -> bool:
    """凭据边界自检：模型请求不得包含访问令牌或平台密钥片段。"""
    blob = json.dumps(payload, ensure_ascii=False)
    return not ("Bearer " in blob or "sk-" in blob
                or config.DEEPSEEK_API_KEY and config.DEEPSEEK_API_KEY in blob)


def redact_messages(messages: list[dict], task_id: str) -> tuple[list[dict], list[str]]:
    """对整条消息序列做出站脱敏（覆盖用户输入/工具结果/历史，需求稿7）。"""
    out, all_found = [], []
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            new_content, found = redact_text(content, task_id)
            all_found += found
            m = dict(m, content=new_content)
        out.append(m)
    return out, all_found


def chat(task_id: str, trace_id: str, messages: list[dict], tools: list[dict] | None,
         outbound_redact: bool) -> dict:
    """发起一次模型请求。返回完整响应 JSON；失败抛 LLMError。

    outbound_redact 为实验配置：True=防护（发送前替换受限字段），False=风险（原文出站）。
    每次请求记录证据：脱敏状态、受限字段发现情况、请求体摘要与全文、耗时与用量。
    """
    send_messages = messages
    restricted_found: list[str] = []
    if outbound_redact:
        send_messages, restricted_found = redact_messages(messages, task_id)
    else:
        for m in messages:
            if isinstance(m.get("content"), str):
                restricted_found += find_restricted(m["content"])

    payload = {
        "model": config.DEEPSEEK_MODEL,
        "messages": send_messages,
        "max_tokens": 2048,
        "temperature": float(config.LLM_TEMPERATURE),
        "stream": False,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    leak_ok = _check_credential_leak(payload)
    body_blob = json.dumps(payload, ensure_ascii=False)
    t0 = time.time()
    try:
        with httpx.Client(timeout=config.LLM_TIMEOUT, trust_env=False) as c:
            r = c.post(f"{config.DEEPSEEK_BASE_URL}/chat/completions",
                       headers={"Authorization": f"Bearer {config.DEEPSEEK_API_KEY}"},
                       json=payload)
    except httpx.HTTPError as e:
        record_evidence({"ts": _now(), "task_id": task_id, "trace_id": trace_id,
                         "event": "llm_request_failed", "redact": outbound_redact,
                         "restricted_in_request": restricted_found,
                         "body_sha256": hashlib.sha256(body_blob.encode()).hexdigest(),
                         "error": f"{type(e).__name__}: {e}"})
        raise LLMError(f"模型请求失败: {type(e).__name__}: {e}")

    if r.status_code != 200:
        record_evidence({"ts": _now(), "task_id": task_id, "trace_id": trace_id,
                         "event": "llm_http_error", "redact": outbound_redact,
                         "restricted_in_request": restricted_found,
                         "body_sha256": hashlib.sha256(body_blob.encode()).hexdigest(),
                         "status": r.status_code, "error": r.text[:300]})
        raise LLMError(f"模型 HTTP {r.status_code}: {r.text[:200]}")

    try:
        resp = r.json()
    except ValueError as e:
        raise LLMError(f"模型响应非 JSON: {e}")

    record_evidence({
        "ts": _now(), "task_id": task_id, "trace_id": trace_id, "event": "llm_request",
        "redact": outbound_redact,
        "restricted_in_request": restricted_found,      # 发送前在待发内容中发现的受限字段
        "restricted_reached_model": restricted_found if not outbound_redact else [],
        "body_sha256": hashlib.sha256(body_blob.encode()).hexdigest(),
        "body": payload,                                 # 实际序列化发送的请求体（虚构数据）
        "credential_leak_check": "pass" if leak_ok else "FAIL",
        "elapsed_ms": int((time.time() - t0) * 1000),
        "usage": resp.get("usage", {}),
        "model": resp.get("model", config.DEEPSEEK_MODEL),
    })
    return resp


def _now() -> str:
    from datetime import datetime
    return datetime.now().astimezone().isoformat(timespec="milliseconds")
