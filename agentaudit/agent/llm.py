"""LLM clients: Groq (OpenAI-compatible, free tier) and a scripted stand-in for offline tests.

Free-tier survival kit built into GroqClient:
  * sliding-window pacing for requests/minute and tokens/minute
  * 429 handling: waits out short limits, stops cleanly (DailyLimitReached) on daily limits
  * an on-disk response cache, so a re-run or a resumed run costs zero tokens
  * a local daily token budget, so one long run cannot burn the whole day's quota
"""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class LLMError(RuntimeError):
    """Unrecoverable problem talking to the model API."""


class DailyLimitReached(LLMError):
    """The daily quota (or the local daily budget) is used up; resume the run later."""


class LLMFormatError(LLMError):
    """The model produced a malformed tool call; the caller may nudge it and retry."""


@dataclass
class LLMResult:
    message: dict
    usage: dict
    cached: bool = False
    latency_s: float = 0.0


# ----------------------------------------------------------------------------- pacing
class RateLimiter:
    """Sliding 60-second window over request count and token count."""

    def __init__(self, rpm=25, tpm=7000, clock=time.monotonic, sleep=time.sleep):
        self.rpm, self.tpm, self.clock, self.sleep = rpm, tpm, clock, sleep
        self.events = deque()  # (timestamp, tokens)

    def _trim(self, now):
        while self.events and now - self.events[0][0] >= 60:
            self.events.popleft()

    def wait_for(self, est_tokens: int):
        est = min(est_tokens, self.tpm)  # one oversized request may go alone
        while True:
            now = self.clock()
            self._trim(now)
            used = sum(t for _, t in self.events)
            if len(self.events) < self.rpm and used + est <= self.tpm:
                return
            wait = (60 - (now - self.events[0][0]) + 0.05) if self.events else 0.05
            self.sleep(max(wait, 0.05))

    def record(self, tokens: int):
        self.events.append((self.clock(), tokens))


# ----------------------------------------------------------------------------- transport
def urllib_transport(url, headers, body: bytes, timeout=120):
    """POST and return (status, lower-cased headers, body bytes). Never raises on HTTP errors."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except urllib.error.URLError as e:
        raise LLMError(f"cannot reach the API: {e.reason}") from e


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _clean_message(raw: dict) -> dict:
    """Keep only what the conversation needs; drop 'reasoning' so it is not re-sent as tokens."""
    msg = {"role": "assistant", "content": raw.get("content")}
    calls = raw.get("tool_calls") or []
    if calls:
        msg["tool_calls"] = [
            {
                "id": c.get("id", f"call_{i}"),
                "type": "function",
                "function": {
                    "name": c["function"]["name"],
                    "arguments": c["function"].get("arguments") or "{}",
                },
            }
            for i, c in enumerate(calls)
        ]
    return msg


class GroqClient:
    def __init__(
        self,
        model: str = None,
        api_key: str = None,
        cache_dir: str = None,
        usage_path: str = None,
        daily_token_budget: int = 180_000,
        rpm: int = 25,
        tpm: int = 7000,
        temperature: float = 0.0,
        seed: int = 42,
        max_completion_tokens: int = 512,
        extra_params: Optional[dict] = None,
        max_retries: int = 6,
        transport: Callable = urllib_transport,
        clock=time.monotonic,
        sleep=time.sleep,
        today: Callable[[], str] = lambda: time.strftime("%Y-%m-%d", time.gmtime()),
    ):
        self.model = model or os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.cache_dir, self.usage_path = cache_dir, usage_path
        self.budget = daily_token_budget
        self.temperature, self.seed = temperature, seed
        self.max_completion_tokens = max_completion_tokens
        if extra_params is None:
            # Keep gpt-oss answers short: low reasoning effort, and do not return the reasoning text.
            extra_params = (
                {"reasoning_effort": "low", "include_reasoning": False}
                if self.model.startswith("openai/gpt-oss")
                else {}
            )
        self.extra = extra_params
        self.max_retries = max_retries
        self.transport, self.sleep, self.today = transport, sleep, today
        self.limiter = RateLimiter(rpm, tpm, clock, sleep)
        self.stats = {"calls": 0, "cache_hits": 0, "prompt_tokens": 0, "completion_tokens": 0, "waited_s": 0.0}
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    # -- request building
    def _payload(self, messages, tools):
        p = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "seed": self.seed,
            "max_completion_tokens": self.max_completion_tokens,
        }
        if tools:
            p["tools"] = tools
            p["tool_choice"] = "auto"
        p.update(self.extra)
        return p

    @staticmethod
    def _estimate(payload) -> int:
        # chars/3.5 over-estimates prompt tokens a little; completions on 'low' effort are short
        return int(len(_canon(payload["messages"]) + _canon(payload.get("tools", []))) / 3.5) + 200

    # -- cache
    def _cache_path(self, payload):
        if not self.cache_dir:
            return None
        key = hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()
        return os.path.join(self.cache_dir, key + ".json")

    # -- daily budget (local, advisory; the 429 handler is the authority)
    def _used_today(self) -> int:
        if not self.usage_path or not os.path.exists(self.usage_path):
            return 0
        try:
            with open(self.usage_path) as f:
                return int(json.load(f).get(self.today(), 0))
        except (OSError, ValueError):
            return 0

    def _add_usage(self, tokens: int):
        if not self.usage_path:
            return
        data = {}
        if os.path.exists(self.usage_path):
            try:
                with open(self.usage_path) as f:
                    data = json.load(f)
            except (OSError, ValueError):
                data = {}
        day = self.today()
        data[day] = int(data.get(day, 0)) + tokens
        with open(self.usage_path, "w") as f:
            json.dump(data, f)

    # -- main call
    def chat(self, messages, tools=None) -> LLMResult:
        payload = self._payload(messages, tools)
        cpath = self._cache_path(payload)
        if cpath and os.path.exists(cpath):
            with open(cpath) as f:
                hit = json.load(f)
            self.stats["cache_hits"] += 1
            return LLMResult(hit["message"], hit["usage"], cached=True)

        est = self._estimate(payload)
        if self.budget and self._used_today() + est > self.budget:
            raise DailyLimitReached(
                f"local daily token budget reached ({self._used_today()} of {self.budget} tokens used today); "
                "rerun tomorrow, the cache makes the run resume where it stopped"
            )
        if not self.api_key:
            raise LLMError("GROQ_API_KEY is not set. Create a free key at console.groq.com and set it as an "
                           "environment variable.")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            # Cloudflare in front of some APIs rejects Python's default User-Agent with a 403
            "User-Agent": "agentaudit-research/0.1",
        }
        body = _canon(payload).encode("utf-8")

        for attempt in range(self.max_retries):
            t_wait = time.monotonic()
            self.limiter.wait_for(est)
            self.stats["waited_s"] += time.monotonic() - t_wait
            t0 = time.monotonic()
            status, rh, raw = self.transport(GROQ_URL, headers, body)
            latency = time.monotonic() - t0
            text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)

            if status == 200:
                data = json.loads(text)
                usage = data.get("usage") or {}
                total = int(usage.get("total_tokens") or 0)
                self.limiter.record(total or est)
                self._add_usage(total)
                self.stats["calls"] += 1
                self.stats["prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
                self.stats["completion_tokens"] += int(usage.get("completion_tokens") or 0)
                msg = _clean_message(data["choices"][0]["message"])
                usage = {k: usage.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens")}
                if cpath:
                    with open(cpath, "w") as f:
                        json.dump({"message": msg, "usage": usage}, f)
                return LLMResult(msg, usage, cached=False, latency_s=latency)

            err = self._error_text(text)
            if status == 429:
                low = err.lower()
                if "per day" in low or "(tpd)" in low or "(rpd)" in low:
                    raise DailyLimitReached(err)
                m = re.search(r"try again in ([0-9.]+)\s*(ms|s|m)\b", low)
                if m:
                    secs = float(m.group(1)) * {"ms": 0.001, "s": 1, "m": 60}[m.group(2)]
                else:
                    secs = float(rh.get("retry-after", 10))
                if secs > 900:
                    raise DailyLimitReached(err)
                self.stats["waited_s"] += secs
                self.sleep(min(secs + 0.5, 120))
                continue
            if status >= 500:
                self.sleep(min(2 ** attempt, 30))
                continue
            if status == 400 and ("failed_generation" in text or "tool_use_failed" in text):
                raise LLMFormatError(err)
            if status in (401, 403):
                raise LLMError(f"{status}: the API rejected the request ({err}). Check GROQ_API_KEY.")
            raise LLMError(f"{status}: {err}")
        raise LLMError(f"gave up after {self.max_retries} attempts")

    @staticmethod
    def _error_text(text: str) -> str:
        try:
            e = json.loads(text).get("error", {})
            return e.get("message") or str(e) or text[:300]
        except (ValueError, AttributeError):
            return text[:300]


# ----------------------------------------------------------------------------- offline stand-in
def tool_call_msg(name: str, args: dict, call_id: str = None) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": call_id or f"call_{name}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
        ],
    }


def text_msg(text: str) -> dict:
    return {"role": "assistant", "content": text}


class ScriptedLLM:
    """Returns pre-written assistant messages in order, or whatever a callable decides."""

    def __init__(self, script):
        self.script, self.calls, self.requests = script, 0, []

    def chat(self, messages, tools=None) -> LLMResult:
        self.requests.append((list(messages), tools))
        if callable(self.script):
            item = self.script(messages, tools)
        else:
            if self.calls >= len(self.script):
                raise LLMError("scripted LLM ran out of messages")
            item = self.script[self.calls]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        return LLMResult(item, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
