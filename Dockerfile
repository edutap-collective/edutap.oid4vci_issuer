# syntax=docker/dockerfile:1
#
# Two stages so the build tooling stays out of the image that ships. The
# runtime carries the installed package and nothing that built it.
FROM python:3.13-slim AS build

WORKDIR /app

# hatch-vcs reads the version from git, so the metadata has to be there when
# the wheel is built. Without it the build fails rather than guessing.
COPY .git /app/.git
COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist

FROM python:3.13-slim

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
