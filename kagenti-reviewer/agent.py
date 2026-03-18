"""A2A-compatible agent server for the S3 document reviewer.

Uses the official a2a-sdk to serve:
  GET  /.well-known/agent-card.json  -- static agent card
  GET  /health                       -- health check
  POST /                             -- JSON-RPC 2.0 (A2A protocol)

Run with:  uv run python agent.py
"""

import json
import logging
import os
import uuid
from pathlib import Path

import uvicorn
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.apps.jsonrpc.starlette_app import A2AStarletteApplication
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers.default_request_handler import (
    DefaultRequestHandler,
)
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types import (
    AgentCard,
    Artifact,
    Part,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TextPart,
)

from reviewer import fetch_and_review

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("agent")

_AGENT_CARD_PATH = Path(__file__).parent / "agent-card.json"


def _load_agent_card() -> AgentCard:
    """Load the agent card JSON from disk and return an AgentCard model."""
    with open(_AGENT_CARD_PATH) as f:
        data = json.load(f)
    return AgentCard(**data)


class ReviewerExecutor(AgentExecutor):
    """Execute review requests via the A2A protocol."""

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        task_id = context.task_id
        ctx_id = context.context_id

        # Signal that work is in progress.
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                taskId=task_id, contextId=ctx_id, final=False,
                status=TaskStatus(state=TaskState.working),
            )
        )

        # Extract text from the incoming message parts.
        user_text = self._extract_text(context)
        if not user_text:
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    taskId=task_id, contextId=ctx_id, final=True,
                    status=TaskStatus(state=TaskState.failed),
                )
            )
            return

        logger.info("Processing message: %s", user_text[:120])

        try:
            result_text = await fetch_and_review(user_text)
        except Exception as exc:
            logger.error("Review failed: %s", exc)
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    taskId=task_id, contextId=ctx_id, final=True,
                    status=TaskStatus(
                        state=TaskState.failed,
                        message=str(exc),
                    ),
                )
            )
            return

        # Publish the result artifact.
        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                taskId=task_id, contextId=ctx_id,
                artifact=Artifact(
                    artifactId=str(uuid.uuid4()),
                    parts=[Part(root=TextPart(text=result_text))],
                ),
            )
        )

        # Mark the task as completed.
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                taskId=task_id, contextId=ctx_id, final=True,
                status=TaskStatus(state=TaskState.completed),
            )
        )

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                taskId=context.task_id, contextId=context.context_id,
                final=True,
                status=TaskStatus(state=TaskState.canceled),
            )
        )

    @staticmethod
    def _extract_text(context: RequestContext) -> str:
        """Extract concatenated text from the request message parts."""
        parts = context.message.parts
        texts: list[str] = []
        for part in parts:
            root = part.root
            if hasattr(root, "text"):
                texts.append(root.text)
        return "\n".join(texts).strip()


async def _health(request: Request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse({"status": "healthy"})


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))

    agent_card = _load_agent_card()

    handler = DefaultRequestHandler(
        agent_executor=ReviewerExecutor(),
        task_store=InMemoryTaskStore(),
    )

    app_builder = A2AStarletteApplication(
        agent_card=agent_card, http_handler=handler
    )
    app = app_builder.build()

    # Add a health endpoint alongside the SDK-provided routes.
    app.routes.append(Route("/health", _health, methods=["GET"]))

    logger.info("A2A agent listening on %s:%d", host, port)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
