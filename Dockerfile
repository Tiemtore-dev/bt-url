FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10001 app

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Dépendances minimales : aiohttp, FastAPI, uvicorn. Le modèle ML (extra « ml ») n'est ni installé ni livré.
RUN pip install ".[api]"

USER app
ENV PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ['PORT'],timeout=3)"

# UN SEUL worker : cache et limites de débit sont en mémoire du processus
CMD ["sh", "-c", "exec uvicorn bt_url.api.app:app_factory --factory --host 0.0.0.0 --port ${PORT} --workers 1"]
