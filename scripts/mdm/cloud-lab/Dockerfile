FROM ghcr.io/astral-sh/uv:0.9.26-python3.12-bookworm-slim

WORKDIR /hol-guard

COPY pyproject.toml uv.lock README.md ./
COPY docs ./docs
COPY src ./src
COPY scripts/mdm ./scripts/mdm

RUN uv sync --extra dev --frozen

RUN mkdir -p /state /artifacts /etc/hol-guard \
    && chmod 1777 /state /artifacts

ENV PATH="/hol-guard/.venv/bin:${PATH}" \
    PYTHONPATH="/hol-guard/src" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONUNBUFFERED="1"

USER 10001:10001

ENTRYPOINT ["python"]
