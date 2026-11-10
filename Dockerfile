FROM python:3.12.10-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY packages/icuhub-schemas ./packages/icuhub-schemas

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

RUN python -m pip install --no-cache-dir ./packages/icuhub-schemas . \
    && chmod -R u=rwX,g=rX,o=rX /opt/venv

FROM python:3.12.10-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    TMPDIR=/tmp

COPY --from=builder --chown=10001:0 /opt/venv /opt/venv

RUN chmod 1777 /tmp

USER 10001:0

EXPOSE 8080

# Worker override: python -m icuhub worker
# Migration override: python -m icuhub migrate
ENTRYPOINT ["python", "-m", "icuhub"]
CMD ["api", "--host", "0.0.0.0", "--port", "8080"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]
