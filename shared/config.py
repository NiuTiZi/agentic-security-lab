"""靶场全局配置：统一从项目根目录 .env 加载，密钥不进代码库。"""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


# --- 授权服务 (Keycloak) ---
KC_URL = _env("KEYCLOAK_URL", "http://127.0.0.1:8080").rstrip("/")
KC_REALM = _env("KEYCLOAK_REALM", "agent-range")
ISSUER = _env("KEYCLOAK_ISSUER", f"{KC_URL}/realms/{KC_REALM}").rstrip("/")
TOOLS_AUDIENCE = _env("TOOLS_AUDIENCE", "tools-service")
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
KC_ADMIN_USERNAME = _env("KC_ADMIN_USERNAME", "range-admin")
KC_ADMIN_PASSWORD = _env("KC_ADMIN_PASSWORD", "")

# --- Agent OAuth 客户端 ---
CUSTOMER_AGENT_CLIENT_ID = _env("CUSTOMER_AGENT_CLIENT_ID", "customer-service-agent")
CUSTOMER_AGENT_CLIENT_SECRET = _env("CUSTOMER_AGENT_CLIENT_SECRET", "")
REFUND_AGENT_CLIENT_ID = _env("REFUND_AGENT_CLIENT_ID", "refund-agent")
REFUND_AGENT_CLIENT_SECRET = _env("REFUND_AGENT_CLIENT_SECRET", "")

# --- 服务地址（全部回环，避开本机代理对 localhost 的劫持） ---
BACKEND_URL = "http://127.0.0.1:8000"
CUSTOMER_AGENT_URL = "http://127.0.0.1:8100"
REFUND_AGENT_URL = "http://127.0.0.1:8200"
TOOLS_URL = "http://127.0.0.1:8300"

# --- 可信服务间内部通道（本机演示：回环 + 共享内部密钥；生产应为 mTLS） ---
INTERNAL_API_KEY = _env("INTERNAL_API_KEY", "")

# --- DeepSeek（阶段3使用，与 Agent OAuth 凭据相互独立） ---
DEEPSEEK_API_KEY = _env("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = _env("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
DEEPSEEK_MODEL = _env("DEEPSEEK_MODEL", "deepseek-flash")

# --- 真实模型调用循环（需求稿7：限制与用量记录） ---
LLM_MAX_TURNS = int(_env("LLM_MAX_TURNS", "6"))       # 每条消息最多工具调用轮次
LLM_TIMEOUT = int(_env("LLM_TIMEOUT", "90"))           # 单次模型请求超时（秒）
LLM_TEMPERATURE = _env("LLM_TEMPERATURE", "0")         # 采样参数（记录进报告）
AGENT_MODE = _env("AGENT_MODE", "llm" if DEEPSEEK_API_KEY else "fixed")  # llm=真实模型 / fixed=固定解析回放

DATA_DIR = ROOT / "data"
EXPERIMENT_DIR = DATA_DIR / "experiments"

# JWT 校验参数
CLOCK_SKEW_SECONDS = 5
ACCESS_TOKEN_TTL = 300
