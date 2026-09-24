"""A stand-in for Ollama, for labs without a real model (e.g. a laptop without a GPU).

It speaks the same HTTP API shape as Ollama for /api/generate, /api/chat, /api/tags and
/api/version, including NDJSON streaming and the final statistics object (nanoseconds).
The "answer" is canned text built from the prompt; it is clearly marked as simulated.

    python tools/mock_ollama.py                       # 127.0.0.1:11434, like Ollama
    python tools/mock_ollama.py --token-delay-ms 80 --load-ms 1500
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from llm.ollama_protocol import extract_prompt

MOCK_MODELS = ("mock-llm", "mock-llm:latest")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _answer_tokens(prompt: str) -> list[str]:
    text = (f"[SIMULASI mock-ollama] Ini jawaban tiruan untuk prompt: \"{prompt[:80]}\". "
            "Model asli akan menghasilkan teks yang berbeda; bagian ini hanya meniru "
            "bentuk respons streaming Ollama untuk keperluan observasi.")
    words = text.split(" ")
    return [w + (" " if i < len(words) - 1 else "") for i, w in enumerate(words)]


def create_app(token_delay_ms: float = 30.0, load_ms: float = 500.0) -> FastAPI:
    app = FastAPI(title="mock-ollama")
    state = {"loaded": False}

    @app.get("/api/version")
    async def version() -> dict[str, str]:
        return {"version": "0.0.0-mock"}

    @app.get("/api/tags")
    async def tags() -> dict[str, Any]:
        return {"models": [{"name": "mock-llm:latest", "model": "mock-llm:latest", "size": 0}]}

    async def generate(request: Request, endpoint: str) -> Any:
        try:
            body = json.loads(await request.body())
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        model = body.get("model", "")
        if model not in MOCK_MODELS:
            return JSONResponse({"error": f"model '{model}' not found, try pulling it first"}, status_code=404)
        prompt = extract_prompt(endpoint, body) or ""
        tokens = _answer_tokens(prompt)
        stream = body.get("stream", True)
        started = time.perf_counter_ns()

        # First request "loads the model", like a real cold start.
        load_ns = 0
        if not state["loaded"]:
            await asyncio.sleep(load_ms / 1000)
            load_ns = int(load_ms * 1_000_000)
            state["loaded"] = True

        def piece(text: str, done: bool) -> dict[str, Any]:
            obj: dict[str, Any] = {"model": model, "created_at": _now(), "done": done}
            if endpoint == "/api/chat":
                obj["message"] = {"role": "assistant", "content": text}
            else:
                obj["response"] = text
            return obj

        def final_stats(eval_ns: int) -> dict[str, Any]:
            return {
                "done_reason": "stop",
                "total_duration": time.perf_counter_ns() - started,
                "load_duration": load_ns,
                "prompt_eval_count": max(1, len(prompt.split())),
                "prompt_eval_duration": 5_000_000,
                "eval_count": len(tokens),
                "eval_duration": max(eval_ns, 1),
            }

        if not stream:
            eval_start = time.perf_counter_ns()
            await asyncio.sleep(token_delay_ms * len(tokens) / 1000)
            obj = piece("".join(tokens), True) | final_stats(time.perf_counter_ns() - eval_start)
            return JSONResponse(obj)

        async def lines() -> AsyncIterator[bytes]:
            eval_start = time.perf_counter_ns()
            for token in tokens:
                await asyncio.sleep(token_delay_ms / 1000)
                yield (json.dumps(piece(token, False)) + "\n").encode()
            last = piece("", True) | final_stats(time.perf_counter_ns() - eval_start)
            yield (json.dumps(last) + "\n").encode()

        return StreamingResponse(lines(), media_type="application/x-ndjson")

    @app.post("/api/generate")
    async def api_generate(request: Request) -> Any:
        return await generate(request, "/api/generate")

    @app.post("/api/chat")
    async def api_chat(request: Request) -> Any:
        return await generate(request, "/api/chat")

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mock Ollama API for labs without a real model")
    parser.add_argument("--host", default="127.0.0.1", help="keep 127.0.0.1: only the local gateway should reach it")
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--token-delay-ms", type=float, default=30.0, help="delay between streamed tokens")
    parser.add_argument("--load-ms", type=float, default=500.0, help="simulated model load on the first request")
    args = parser.parse_args(argv)
    print(f"[mock-ollama] listening on http://{args.host}:{args.port}  model=mock-llm  "
          f"token_delay={args.token_delay_ms}ms load={args.load_ms}ms")
    uvicorn.run(create_app(args.token_delay_ms, args.load_ms), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
