FROM python:3.12.9-slim-bookworm

LABEL org.opencontainers.image.title="oxfuzz Scapy automotive sidecar"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.licenses="MIT AND GPL-2.0-only AND LGPL-3.0-only"

ARG IPROUTE2_VERSION=6.1.0-3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OXFUZZ_SCAPY_INPUT_ROOT=/workspace/input \
    OXFUZZ_SCAPY_OUTPUT_ROOT=/workspace/output

WORKDIR /opt/oxfuzz-scapy-automotive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends "iproute2=${IPROUTE2_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-can.txt pyproject.toml README.md LICENSE-DISTRIBUTION.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --no-deps -r requirements-can.txt \
    && python -m pip install --no-cache-dir --no-deps . \
    && addgroup --system --gid 65532 sidecar \
    && adduser --system --uid 65532 --ingroup sidecar --home /nonexistent sidecar \
    && mkdir -p /workspace/input /workspace/output \
    && chown -R sidecar:sidecar /workspace/output

USER 65532:65532

CMD ["python3", "-m", "oxfuzz_scapy_automotive"]
