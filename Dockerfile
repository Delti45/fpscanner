# syntax=docker/dockerfile:1
# Obraz aplikacji (API) i narzędzi (provision, smoke test). Nie zawiera żadnych sekretów:
# klucze i certyfikaty powstają w wolumenie /data (patrz docker-compose.yml).

FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[postgres]"

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FP_HOST=0.0.0.0 \
    FP_PORT=8000
RUN useradd --system --uid 10001 --create-home --home-dir /home/fp fp \
    && mkdir /data && chown fp:fp /data
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels "fpscanner[postgres]" && rm -rf /wheels
COPY docker/entrypoint.sh /usr/local/bin/fp-entrypoint
RUN chmod +x /usr/local/bin/fp-entrypoint

USER fp
WORKDIR /data
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('FP_PORT', '8000') + '/healthz', timeout=2)"
ENTRYPOINT ["fp-entrypoint"]
CMD ["fp-server"]
