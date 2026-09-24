"""PHASE 4: helpers for the Ollama HTTP API, shared by the gateway and the LLM client.

Ollama endpoints used here:
  POST /api/generate  {"model", "prompt", "stream"}                -> chunks with "response"
  POST /api/chat      {"model", "messages": [{role, content}], ...} -> chunks with "message.content"
With "stream": true (Ollama's default) the answer arrives as NDJSON: one JSON object per line,
each carrying a piece of text, and a final object with "done": true plus timing statistics
(durations are in nanoseconds). With "stream": false it is a single JSON object.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

LLM_ENDPOINTS = ("/api/generate", "/api/chat")
NS_PER_MS = 1_000_000


def extract_prompt(endpoint: str, body: dict[str, Any]) -> str | None:
    """The user's prompt: "prompt" for /api/generate, the last user message for /api/chat."""
    if endpoint == "/api/chat":
        messages = body.get("messages") or []
        for message in reversed(messages):
            if isinstance(message, dict) and message.get("role") == "user":
                return str(message.get("content", ""))
        return None
    prompt = body.get("prompt")
    return None if prompt is None else str(prompt)


@dataclass
class OllamaResponseAssembler:
    """Collects a (streamed or single) Ollama response into the full text plus statistics."""

    endpoint: str
    text_parts: list[str] = field(default_factory=list)
    chunks: int = 0
    first_chunk_at: float | None = None  # perf_counter time of the first piece of text
    last_chunk_at: float | None = None
    final: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    _buffer: bytes = b""

    def feed_bytes(self, data: bytes, at: float) -> None:
        """Feed raw bytes; lines may be split across network chunks, so buffer until newline."""
        self._buffer += data
        *lines, self._buffer = self._buffer.split(b"\n")
        for line in lines:
            self.feed_line(line.decode("utf-8", errors="replace"), at)

    def close(self, at: float) -> None:
        """Process a trailing object without newline (non-streaming responses)."""
        if self._buffer.strip():
            self.feed_line(self._buffer.decode("utf-8", errors="replace"), at)
        self._buffer = b""

    def feed_line(self, line: str, at: float) -> None:
        line = line.strip()
        if not line:
            return
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            self.error = self.error or f"invalid JSON from Ollama: {line[:100]}"
            return
        if not isinstance(obj, dict):
            return
        if "error" in obj:
            self.error = str(obj["error"])
            return
        piece = obj.get("response") if self.endpoint != "/api/chat" else (obj.get("message") or {}).get("content")
        if piece:
            self.text_parts.append(piece)
            if self.first_chunk_at is None:
                self.first_chunk_at = at
        self.chunks += 1
        self.last_chunk_at = at
        if obj.get("done"):
            self.final = obj

    @property
    def text(self) -> str:
        return "".join(self.text_parts)

    def summary(self) -> dict[str, Any]:
        """Statistics reported by Ollama in its final object, converted to milliseconds."""
        f = self.final

        def ms(key: str) -> float | None:
            value = f.get(key)
            return round(value / NS_PER_MS, 3) if isinstance(value, (int, float)) else None

        eval_count = f.get("eval_count")
        eval_ms = ms("eval_duration")
        tokens_per_s = round(eval_count / (eval_ms / 1000), 2) if eval_count and eval_ms else None
        return {
            "model": f.get("model"),
            "done": bool(f.get("done")),
            "done_reason": f.get("done_reason"),
            "chunks": self.chunks,
            "prompt_tokens": f.get("prompt_eval_count"),
            "response_tokens": eval_count,
            "tokens_per_s": tokens_per_s,
            "ollama_total_ms": ms("total_duration"),
            "ollama_load_ms": ms("load_duration"),  # model loading = the real "cold start"
            "ollama_prompt_eval_ms": ms("prompt_eval_duration"),
            "ollama_eval_ms": eval_ms,
            "error": self.error,
        }
