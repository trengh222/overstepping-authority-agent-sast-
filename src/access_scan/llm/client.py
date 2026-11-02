"""LLM 调用封装 + 重试（方案 §9.1）。

默认走 DeepSeek 的 Anthropic 兼容端点（模型 `deepseek-v4-pro`），通过 anthropic SDK
（Messages API）。可用性契约：未装 anthropic SDK 或缺少认证 token 时 available=False，
判定层整体降级为静态 LIKELY（§9.5：静态证据不丢失）。

配置优先级：显式参数 > config/llm.yaml > 环境变量。
config/llm.yaml（config 目录）：
  model / base_url / auth_token
环境变量（fallback）：ACCESS_SCAN_LLM_MODEL / ANTHROPIC_MODEL /
  ACCESS_SCAN_LLM_BASE_URL / ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN。
"""
import json
import os
import re
import time
from typing import Any, Dict, Optional

from . import prompts
from .verdict import validate
from ..config import load_llm

try:
    import anthropic  # type: ignore
    _ANTHROPIC_AVAILABLE = True
except ImportError:  # 未安装 SDK → 优雅降级
    anthropic = None
    _ANTHROPIC_AVAILABLE = False

_DEFAULT_MODEL = "deepseek-v4-pro"


class LLMError(Exception):
    pass


def parse_json_response(text: str) -> Any:
    """从 LLM 回复中提取首个 JSON 对象（容忍前后杂文本）。"""
    text = (text or "").strip()
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        text = m.group(0)
    return json.loads(text)


class LLMJudge:
    """单个证据包的 LLM 判定器 + 对抗复核（Anthropic 兼容 Messages API）。"""

    def __init__(self, model: Optional[str] = None, auth_token: Optional[str] = None,
                 base_url: Optional[str] = None, max_retries: int = 1,
                 timeout: float = 30.0):
        cfg = load_llm()
        self.model = (model or cfg.get("model")
                      or os.environ.get("ACCESS_SCAN_LLM_MODEL")
                      or os.environ.get("ANTHROPIC_MODEL") or _DEFAULT_MODEL)
        self.auth_token = (auth_token or cfg.get("auth_token")
                           or os.environ.get("ANTHROPIC_AUTH_TOKEN")
                           or os.environ.get("ANTHROPIC_API_KEY"))
        self.base_url = (base_url or cfg.get("base_url")
                         or os.environ.get("ACCESS_SCAN_LLM_BASE_URL")
                         or os.environ.get("ANTHROPIC_BASE_URL"))
        self.max_retries = max_retries
        self.timeout = timeout
        self.calls = 0  # 成功发起的 API 调用数（成本/测试统计用）
        self.available = _ANTHROPIC_AVAILABLE and bool(self.auth_token)
        kwargs: Dict[str, Any] = {}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        self._client = (
            anthropic.Anthropic(auth_token=self.auth_token, timeout=self.timeout, **kwargs)
            if self.available else None
        )

    def _complete(self, system: str, user: str) -> str:
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = self._client.messages.create(
                    model=self.model,
                    # deepseek-v4-pro 为 reasoning 模型：先输出 thinking 块再 text，
                    # 需足够 max_tokens，否则 thinking 耗尽上限导致 text 为空。
                    max_tokens=8192,                                            
                    temperature=0,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
                self.calls += 1
                return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
            except Exception as e:  # 网络/限流/服务端错误 → 线性退避重试（D10：快速失败）
                last_err = e
                time.sleep(min(3.0, 1.0 * (attempt + 1)))
        raise LLMError(f"LLM 调用失败: {last_err}")

    def judge(self, evidence_pkg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """返回经 schema 校验的判定；失败/不可用 → None（上游按 LIKELY 兜底）。"""
        if not self.available:
            return None
        try:
            text = self._complete(prompts.SYSTEM_PROMPT, prompts.build_user_prompt(evidence_pkg))
            return validate(parse_json_response(text))
        except Exception:
            return None

    def adversarial(self, evidence_pkg: Dict[str, Any], verdict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """对抗复核（§9.4）：返回 {"refuted": bool, "reasoning": str}；失败 → None（维持原判定）。"""
        if not self.available:
            return None
        try:
            user = prompts.ADVERSARIAL_PROMPT + prompts.build_adversarial_prompt(evidence_pkg, verdict)
            text = self._complete(prompts.SYSTEM_PROMPT, user)
            raw = parse_json_response(text)
            if not isinstance(raw, dict) or not isinstance(raw.get("refuted"), bool):
                return None
            return {"refuted": raw["refuted"], "reasoning": str(raw.get("reasoning") or "")}
        except Exception:
            return None
