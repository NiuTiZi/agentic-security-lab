"""实验配置开关（需求稿9.1 对照配置）。

用途：RISK 实验在“风险复现/单项防护/组合防护”配置间切换。默认全部防护开启；
关闭任一防护即进入实验状态，必须披露并在实验结束后恢复。

边界约束：
- 仅经内部通道（X-Internal-Key）修改，每次变更写入审计；
- 认证类防护（JWT 验签、scope 检查）不可关闭——风险实验只针对任务/对象/出站层控制；
- 开关只影响本受控实验环境（需求稿9.1）。

开关归属：
- agent 侧（agent_customer）：agent_mode / llm_outbound_redact / untrusted_marking / runtime_task_check
- 工具侧（tools）：tools_task_verify / tools_ownership_check / outbound_dest_limit /
  outbound_redact / injection_detect
"""
import threading

AGENT_DEFAULTS = {
    "agent_mode": "",            # 空=取 config.AGENT_MODE；llm=真实模型；fixed=固定解析回放
    "llm_outbound_redact": True,   # RISK-01：模型请求出站脱敏
    "untrusted_marking": True,     # RISK-04：不可信内容标记（系统提示护栏 + 工具结果包裹）
    "runtime_task_check": True,    # RISK-04：运行层任务范围预检（操作/参数须在任务授权内）
}

TOOLS_DEFAULTS = {
    "tools_task_verify": True,     # RISK-04：工具端任务与用户授权在线核验（verify-exec）
    "tools_ownership_check": True,  # RISK-03：对象归属检查
    "outbound_dest_limit": True,   # RISK-04：出站目的地白名单（仅本地测试接收端）
    "outbound_redact": True,       # RISK-01：出站工具参数脱敏（message.send 正文）
    "injection_detect": True,      # RISK-04：辅助检测（文档疑似指令注入标记）
}


class ExpConfig:
    def __init__(self, defaults: dict[str, object]):
        self._lock = threading.Lock()
        self._defaults = dict(defaults)
        self._values = dict(defaults)

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._values)

    def get(self, key: str):
        with self._lock:
            return self._values.get(key, self._defaults.get(key))

    def update(self, changes: dict) -> dict:
        unknown = {k for k in changes if k not in self._defaults}
        if unknown:
            raise ValueError(f"未知实验配置项: {sorted(unknown)}")
        with self._lock:
            self._values.update(changes)
            return dict(self._values)

    def reset(self) -> dict:
        with self._lock:
            self._values = dict(self._defaults)
            return dict(self._values)

    def risk_flags(self) -> list[str]:
        """当前处于关闭状态的防护项（用于告警与报告披露）。"""
        with self._lock:
            return [k for k, v in self._values.items()
                    if isinstance(v, bool) and not v and k != "agent_mode"]


def describe_risk(flags: list[str]) -> str:
    names = {
        "llm_outbound_redact": "模型请求出站脱敏",
        "untrusted_marking": "不可信内容标记",
        "runtime_task_check": "运行层任务范围预检",
        "tools_task_verify": "工具端任务授权核验",
        "tools_ownership_check": "对象归属检查",
        "outbound_dest_limit": "出站目的地白名单",
        "outbound_redact": "出站参数脱敏",
        "injection_detect": "注入辅助检测",
    }
    return "、".join(names.get(f, f) for f in flags)
