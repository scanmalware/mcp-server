ARG PYTHON_IMAGE=python:3.14-slim
FROM ${PYTHON_IMAGE}

WORKDIR /app

# Basic hardening: disable .pyc writes, keep logs unbuffered.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m pip install -U pip

COPY pyproject.toml README.md /app/
COPY scanmalware_mcp /app/scanmalware_mcp

RUN pip install .

# Run as a non-root user inside the container.
RUN adduser --disabled-password --gecos "" --home /home/app --uid 10001 app

EXPOSE 8000

# Default to Streamable HTTP transport on port 8000.
ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

USER app

CMD ["scanmalware-mcp"]
