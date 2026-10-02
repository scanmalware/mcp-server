ARG PYTHON_IMAGE=python:3.14.8-slim-trixie@sha256:89fb7d3da20043c370643435258bdd7ab755d326d359001d02988ed15ae5219e
FROM ${PYTHON_IMAGE}

WORKDIR /app

# Refresh distribution security patches even when the upstream image digest is pinned.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Basic hardening: disable .pyc writes, keep logs unbuffered.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.lock /app/
RUN python -m pip install --require-hashes -r requirements.lock

COPY pyproject.toml README.md /app/
COPY scanmalware_mcp /app/scanmalware_mcp

RUN python -m pip install --no-deps --no-build-isolation .

# The running service never installs packages. Drop pip and its vendored libraries.
RUN python -m pip check && python -m pip uninstall -y pip

# Run as a non-root user inside the container.
RUN adduser --disabled-password --gecos "" --home /home/app --uid 10001 app

EXPOSE 8000

# Default to Streamable HTTP transport on port 8000.
ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

USER app

CMD ["scanmalware-mcp"]
