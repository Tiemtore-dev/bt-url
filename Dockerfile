FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/Tiemtore-dev/bt-url" \
      org.opencontainers.image.title="bt-url" \
      org.opencontainers.image.description="Analyse d'URL par Threat Intelligence (API + page web)"

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --create-home --uid 10001 app

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Dépendances minimales : aiohttp, FastAPI, uvicorn. Le modèle ML (extra « ml ») n'est ni installé ni livré.
RUN pip install ".[api]"

USER app
# Réglages non secrets embarqués dans l'image (surchargeables à l'exécution). Les CLÉS API ne sont
# JAMAIS dans l'image : elles viennent du .env au déploiement.
ENV PORT=8000 \
    BT_URL_RATE_PER_MIN=3 \
    BT_URL_RATE_PER_HOUR=20 \
    BT_URL_GLOBAL_PER_MIN=4 \
    BT_URL_DAILY_BUDGET=300 \
    BT_URL_CACHE_TTL=3600 \
    BT_URL_MAX_CONCURRENT=4 \
    BT_URL_COLLECT=true \
    BT_URL_ML_ENABLED=false
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ['PORT'],timeout=3)"

# UN SEUL worker : cache et limites de débit sont en mémoire du processus
CMD ["sh", "-c", "exec uvicorn bt_url.api.app:app_factory --factory --host 0.0.0.0 --port ${PORT} --workers 1"]
