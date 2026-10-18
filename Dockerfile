FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    BT_URL_MODEL_PATH=/opt/model/best_model_pipeline.pkl \
    BT_URL_TRUST_PROXY=true

# libgomp1 : requis par LightGBM
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 app

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[api]"

# Modèle téléchargé au build, SHA256 vérifié (le build échoue si le hash ne correspond pas)
RUN mkdir -p /opt/model && python -m bt_url.ml.fetch && chmod -R a+rX /opt/model

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'),timeout=3)"

# UN SEUL worker : cache et limites de débit sont en mémoire du processus
CMD ["sh", "-c", "exec uvicorn bt_url.api.app:app_factory --factory --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
