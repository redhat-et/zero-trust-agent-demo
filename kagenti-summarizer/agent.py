"""A2A-compatible agent server for the S3 document summarizer.

Serves:
  GET  /.well-known/agent-card.json  — static agent card
  GET  /health                       — health check
  POST /                             — JSON-RPC 2.0 (A2A message/send)

Run with:  uv run python agent.py
"""

import asyncio
import json
import logging
import os
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from summarizer import fetch_and_summarize

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("agent")

_AGENT_CARD_PATH = Path(__file__).parent / "agent-card.json"


def _load_agent_card() -> dict:
    """Load the agent card JSON from disk."""
    with open(_AGENT_CARD_PATH) as f:
        return json.load(f)


AGENT_CARD = _load_agent_card()


def _extract_text(message: dict) -> str:
    """Extract concatenated text from A2A message parts."""
    parts = message.get("parts", [])
    texts = []
    for part in parts:
        if part.get("type") == "text" or "text" in part:
            texts.append(part.get("text", ""))
    return "\n".join(texts).strip()


def _build_task_result(task_id: str, text: str) -> dict:
    """Build an A2A Task result with a text artifact."""
    return {
        "id": task_id,
        "status": {"state": "completed"},
        "artifacts": [
            {
                "parts": [{"type": "text", "text": text}],
            }
        ],
    }


def _handle_jsonrpc(body: dict) -> dict:
    """Dispatch a JSON-RPC 2.0 request and return a response."""
    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params", {})

    if method in ("message/send", "tasks/send"):
        message = params.get("message", {})
        user_text = _extract_text(message)
        if not user_text:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32602,
                    "message": "No text found in message parts",
                },
            }

        logger.info("Processing message: %s", user_text[:120])

        # Run the async summarizer in a new event loop
        try:
            result_text = asyncio.run(fetch_and_summarize(user_text))
        except Exception as exc:
            logger.error("Summarization failed: %s", exc)
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32000, "message": str(exc)},
            }

        task_id = params.get("id", str(uuid.uuid4()))
        task = _build_task_result(task_id, result_text)
        return {"jsonrpc": "2.0", "id": rpc_id, "result": task}

    # Unknown method
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


class AgentHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the A2A agent."""

    def do_GET(self):
        if self.path == "/.well-known/agent-card.json":
            self._json_response(200, AGENT_CARD)
        elif self.path == "/health":
            self._json_response(200, {"status": "healthy"})
        else:
            self._json_response(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/", "/a2a"):
            self._json_response(404, {"error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid JSON"})
            return

        response = _handle_jsonrpc(body)
        self._json_response(200, response)

    def _json_response(self, status: int, data: dict):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        """Route HTTP access logs through the module logger."""
        logger.info(format, *args)


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))

    server = HTTPServer((host, port), AgentHandler)
    logger.info("A2A agent listening on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
