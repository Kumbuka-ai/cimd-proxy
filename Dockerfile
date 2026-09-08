# syntax=docker/dockerfile:1.7
FROM python:3.13-slim AS build

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip wheel --no-cache-dir --wheel-dir=/wheels .


FROM python:3.13-slim AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --system --gid "${APP_GID}" cimd \
 && useradd  --system --uid "${APP_UID}" --gid "${APP_GID}" --home /app --shell /sbin/nologin cimd \
 && install -d -o cimd -g cimd /app

WORKDIR /app

# Only wheels come across from build; the toolchain does not.
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels cimd-proxy \
 && rm -rf /wheels

USER cimd

EXPOSE 8080

# HEALTHCHECK hits /healthz without auth — it does not touch the auth path.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
port=os.environ.get('PROXY_PORT','8080'); \
r=urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=2); \
sys.exit(0 if r.status==200 else 1)"

ENTRYPOINT ["python", "-m", "cimd_proxy"]
