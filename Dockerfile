# syntax=docker/dockerfile:1
#
# Two stages so the build tooling stays out of the image that ships. The
# runtime carries the installed package and nothing that built it.
FROM python:3.14-slim AS build

# hatch-vcs derives the version by asking git, so the build stage needs both
# the binary and the history. Passing a version in as a build argument would
# work too, and would read 0.0.0 the first time somebody forgot it.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY .git /app/.git
COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist

FROM python:3.14-slim

ARG HTTP_PORT=8000
ENV HTTP_PORT=${HTTP_PORT} \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY --from=build /dist /dist
RUN pip install --no-cache-dir /dist/*.whl && rm -rf /dist

# Not root: the service reads a signing key and writes nothing.
RUN useradd --create-home --uid 10001 issuer
USER issuer

EXPOSE ${HTTP_PORT}

CMD ["sh", "-c", "uvicorn edutap.oid4vci_issuer.app:app --proxy-headers --host 0.0.0.0 --port $HTTP_PORT --access-log"]
