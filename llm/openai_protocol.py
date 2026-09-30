"""OpenAI-compatible chat API (LM Studio, Ollama /v1, vLLM, llama.cpp server).

    POST /v1/chat/completions {"model", "messages": [...], "stream": false}   # OpenAI default: NOT streaming

With "stream": true the answer arrives as Server-Sent Events (SSE), one event per piece:
    data: {"choices": [{"delta": {"content": "Hal"}, "finish_reason": null}], ...}
    data: {"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 30}}   # if include_usage
    data: [DONE]
Unlike Ollama's native API there are no per-stage timings (no model load / eval durations), only
token counts - an observability difference this lab measures.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

OPENAI_CHAT = "/v1/chat/completions"


def extract_prompt(body: dict[str, Any]) -> str | None:
    """Last user message; content may be a string or a list of parts (text/image)."""
    for message in reversed(body.get("messages") or []):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, list):
                return " ".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
            return None if content is None else str(content)
    return None


@dataclass
class OpenAIResponseAssembler:
    """Same interface as OllamaResponseAssembler, for SSE streams or a single JSON answer."""

    endpoint: str = OPENAI_CHAT
    text_parts: list[str] = field(default_factory=list)
    chunks: int = 0
    first_chunk_at: float | None = None
    last_chunk_at: float | None = None
    model: str | None = None
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    done: bool = False
    error: str | None = None
    _buffer: bytes = b""
    _whole_json: bool | None = None  # True: one JSON answer (not SSE), parsed as a whole in close()

    def feed_bytes(self, data: bytes, at: float) -> None:
        self._buffer += data
        if self._whole_json is None and self._buffer.strip():
            # SSE starts with "data:" or ":"; a non-streamed answer is one JSON object that LM Studio
            # pretty-prints over many lines, so newlines are not message boundaries there.
            self._whole_json = self._buffer.lstrip()[:1] == b"{"
        if self._whole_json:
            return
        *lines, self._buffer = self._buffer.split(b"\n")
        for line in lines:
            self.feed_line(line.decode("utf-8", errors="replace"), at)

    def close(self, at: float) -> None:
        if self._buffer.strip():
            self.feed_line(self._buffer.decode("utf-8", errors="replace"), at)
        self._buffer = b""

    def feed_line(self, line: str, at: float) -> None:
        """One SSE line, or a complete JSON answer (which may span several lines)."""
        line = line.strip()
        if not line or line.startswith(":"):  # blank separator or SSE comment
            return
        if line.startswith("data:"):
            line = line[5:].strip()
        if line == "[DONE]":
            self.done = True
            return
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            self.error = self.error or f"invalid JSON from upstream: {line[:100]}"
            return
        if not isinstance(obj, dict):
            return
        if "error" in obj:
            err = obj["error"]
            self.error = str(err.get("message", err)) if isinstance(err, dict) else str(err)
            return
        self.model = self.model or obj.get("model")
        if isinstance(obj.get("usage"), dict):
            self.usage = obj["usage"]
        for choice in obj.get("choices") or []:
            piece = (choice.get("delta") or choice.get("message") or {}).get("content")
            if piece:
                self.text_parts.append(piece)
                if self.first_chunk_at is None:
                    self.first_chunk_at = at
            if choice.get("finish_reason"):
                self.finish_reason = choice["finish_reason"]
                if "message" in choice:  # non-streaming answer is complete in one object
                    self.done = True
        self.chunks += 1
        self.last_chunk_at = at

    @property
    def text(self) -> str:
        return "".join(self.text_parts)

    def summary(self) -> dict[str, Any]:
        """Same keys as the Ollama summary so logs stay uniform; model-side timings are not available.

        tokens_per_s is an ESTIMATE from when the first and last pieces reached this host (the API
        reports no generation time), so it includes network jitter; None without streaming.
        """
        tokens = self.usage.get("completion_tokens")
        span = (self.last_chunk_at - self.first_chunk_at) if self.first_chunk_at and self.last_chunk_at else 0
        return {
            "api_style": "openai",
            "model": self.model,
            "done": self.done or self.finish_reason is not None,
            "done_reason": self.finish_reason,
            "chunks": self.chunks,
            "prompt_tokens": self.usage.get("prompt_tokens"),
            "response_tokens": tokens,
            "tokens_per_s": round((tokens - 1) / span, 2) if tokens and tokens > 1 and span > 0 else None,
            "ollama_total_ms": None,
            "ollama_load_ms": None,
            "ollama_prompt_eval_ms": None,
            "ollama_eval_ms": None,
            "error": self.error,
        }
