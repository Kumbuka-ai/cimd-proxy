# syntax=docker/dockerfile:1.7
FROM python:3.13-slim AS build

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip wheel --no-cache-dir --wheel-dir=/wheels .


FROM python:3.13-slim AS runtime

# Patch the base image's OS packages before anything else lands. A base image is
# rebuilt on its own schedule and routinely carries packages whose fixes are
# already published; upgrading here closes that gap at build time rather than
# waiting for the upstream rebuild.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --system --gid "${APP_GID}" cimd \
 && useradd  --system --uid "${APP_UID}" --gid "${APP_GID}" --home /app --shell /sbin/nologin cimd \
 && install -d -o cimd -g cimd /app

WORKDIR /app

# The wheels are bind-mounted from the build stage, not copied in.
#
# `COPY --from=build /wheels /wheels` followed by `rm -rf /wheels` looks
# equivalent and is not: the COPY writes a layer, and deleting the directory
# afterwards only adds a whiteout on top. The wheel files stay in the image's
# layer history, where an image scanner still finds them — which is how this
# image reported msgpack 1.1.2 while 1.2.2 was the version actually installed.
#
# A bind mount exists only for the duration of the RUN, so nothing is written
# and there is nothing to clean up.
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels cimd-proxy

# Raise the two packages the image scan flags, neither of which this project
# declares: setuptools comes preinstalled in python:3.13-slim, and msgpack
# arrives transitively through uvicorn[standard]. Both have published fixes, so
# leaving them means shipping a known-vulnerable package because the base image
# has not caught up.
# Raise setuptools, then remove pip itself.
#
# The image scan reported setuptools 70.3.0 and msgpack 1.1.2 next to the
# 84.0.0 and 1.2.2 that were demonstrably installed. Neither phantom was in
# site-packages; both come from `pip/_vendor/vendor.txt`, which pins the copies
# pip carries for its own use — the file says `msgpack==1.1.2` and
# `setuptools==70.3.0` in as many words, and Trivy reads it.
#
# So the versions were never the problem and no amount of upgrading moved them.
# What removes them is removing pip: this image starts with
# `python -m cimd_proxy` and installs nothing at run time, so a package manager
# in the runtime layer is dependency surface kept for nothing. Same reasoning as
# dropping npm from the Node images.
#
# setuptools is still raised first: it comes with the base image, is used at
# build time here, and the upgrade is what the scanner will look at once pip's
# vendored copy is gone.
RUN pip install --no-cache-dir --upgrade "setuptools>=78.1.1" \
 && PY_SITE=$(python -c 'import site; print(site.getsitepackages()[0])') \
 && rm -rf "$PY_SITE"/pip "$PY_SITE"/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.*

USER cimd

EXPOSE 8080

# HEALTHCHECK hits /healthz without auth — it does not touch the auth path.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
port=os.environ.get('PROXY_PORT','8080'); \
r=urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=2); \
sys.exit(0 if r.status==200 else 1)"

ENTRYPOINT ["python", "-m", "cimd_proxy"]
