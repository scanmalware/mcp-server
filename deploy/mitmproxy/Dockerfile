FROM python:3.14.8-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/mitmproxy
COPY requirements.lock /tmp/requirements.lock
RUN python -m pip install --require-hashes -r /tmp/requirements.lock \
    && python -m pip check \
    && python -m pip uninstall -y pip \
    && rm /tmp/requirements.lock \
    && mkdir -p /home/mitmproxy/.mitmproxy
CMD ["mitmdump"]
