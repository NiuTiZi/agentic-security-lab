"""DeepSeek API 最小连通验证（W0.5）。

用法:
    .venv\\Scripts\\python.exe scripts\\verify_deepseek.py

行为:
    1. GET /models 列出账户可用模型（不计费）
    2. POST /chat/completions 发送一次最小请求（max_tokens=16, 费用忽略不计）
    3. 记录模型名、返回内容、token 用量与耗时，结论写入控制台

密钥来源: .env 的 DEEPSEEK_API_KEY（或进程环境变量，二者等价）。
"""
import os
import sys
import time

import httpx
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

if not API_KEY or API_KEY.startswith("sk-xxxx"):
    sys.exit("[deepseek] .env 缺少 DEEPSEEK_API_KEY")

headers = {"Authorization": f"Bearer {API_KEY}"}

with httpx.Client(timeout=30, trust_env=False) as c:
    r = c.get(f"{BASE_URL}/models", headers=headers)
    if r.status_code == 200:
        models = [m["id"] for m in r.json().get("data", [])]
        print(f"[deepseek] 可用模型: {', '.join(models)}")
    else:
        print(f"[deepseek] /models HTTP {r.status_code}: {r.text[:150]}")

    t0 = time.time()
    r = c.post(
        f"{BASE_URL}/chat/completions",
        headers=headers,
        json={
            "model": MODEL,
            "messages": [{"role": "user", "content": "只回复两个字：正常"}],
            "max_tokens": 2048,
            "temperature": 0,
        },
    )
    dt = time.time() - t0
    if r.status_code == 200:
        j = r.json()
        content = j["choices"][0]["message"]["content"]
        usage = j.get("usage", {})
        print(f"[deepseek] 模型: {j.get('model')} | 响应: {content!r} | 耗时 {dt:.1f}s")
        print(f"[deepseek] token 用量: prompt={usage.get('prompt_tokens')} completion={usage.get('completion_tokens')}")
        print("[deepseek] 结论: 连通验证通过，接口配置可用")
    else:
        print(f"[deepseek] chat HTTP {r.status_code}: {r.text[:200]}")
        sys.exit(1)

    # --- Tool Calls 验证（靶场核心依赖） ---
    tools = [{
        "type": "function",
        "function": {
            "name": "query_order",
            "description": "查询订单信息",
            "parameters": {
                "type": "object",
                "properties": {
                    "order_id": {"type": "string", "description": "订单编号，如 ORD-1001"},
                },
                "required": ["order_id"],
            },
        },
    }]
    t0 = time.time()
    r = c.post(
        f"{BASE_URL}/chat/completions",
        headers=headers,
        json={
            "model": MODEL,
            "messages": [{"role": "user", "content": "帮我查一下订单 ORD-1001 的信息"}],
            "tools": tools,
            "max_tokens": 2048,
        },
    )
    dt = time.time() - t0
    if r.status_code == 200:
        j = r.json()
        msg = j["choices"][0]["message"]
        tcs = msg.get("tool_calls") or []
        if tcs:
            tc = tcs[0]
            print(f"[deepseek] ToolCalls: 通过 | 函数={tc['function']['name']} 参数={tc['function']['arguments']} | finish={j['choices'][0].get('finish_reason')} | 耗时 {dt:.1f}s")
        else:
            print(f"[deepseek] ToolCalls: 未触发（content={msg.get('content')!r} finish={j['choices'][0].get('finish_reason')}）")
            sys.exit(1)
    else:
        print(f"[deepseek] tools HTTP {r.status_code}: {r.text[:200]}")
        sys.exit(1)
