FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY *.py agent-card.json ./

EXPOSE 8000
USER 1000
CMD [".venv/bin/python", "agent.py"]
