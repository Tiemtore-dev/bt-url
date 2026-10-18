"""Application FastAPI : API JSON + page web statique (même origine, CSP stricte)."""

import asyncio
import ipaddress
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from bt_url import __version__
from bt_url.analyzer import URLAnalyzer
from bt_url.api.limits import RateLimited
from bt_url.api.service import AnalysisService, AnalysisTimeout, Busy, InvalidURL
from bt_url.api.settings import ApiSettings

log = logging.getLogger("bt_url.api")
STATIC = Path(__file__).parent / "static"

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

SCOPE_MESSAGES = {
    "ip_minute": "Trop d'analyses depuis votre adresse (limite par minute).",
    "ip_hour": "Trop d'analyses depuis votre adresse (limite horaire).",
    "global_minute": "Le service est très sollicité : réessayez dans un instant.",
    "daily_budget": "Le quota quotidien de la démo est épuisé. Revenez demain.",
}


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


def client_ip(request: Request, trust_proxy: bool) -> str:
    """
    IP cliente. Derrière un proxy de confiance on prend l'entrée de DROITE de X-Forwarded-For
    (celle ajoutée par notre proxy ; celles de gauche sont falsifiables par le client).
    """
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for", "")
        candidate = xff.split(",")[-1].strip() if xff else ""
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"


def create_app(analyzer: Optional[URLAnalyzer] = None, settings: Optional[ApiSettings] = None,
               preload_ml: bool = True) -> FastAPI:
    cfg = settings or ApiSettings()
    analyzer = analyzer or URLAnalyzer()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if preload_ml and analyzer.settings.ml_enabled:
            # Chargement du modèle hors de la boucle d'événements (183 Mo, vérifié par SHA256)
            await asyncio.get_running_loop().run_in_executor(None, analyzer._get_ml)
        yield

    app = FastAPI(title="bt-url", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.service = AnalysisService(analyzer, cfg)
    service: AnalysisService = app.state.service

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def error(status: int, code: str, message: str, headers: Optional[dict] = None) -> JSONResponse:
        return JSONResponse({"error": {"code": code, "message": message}},
                            status_code=status, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, __: RequestValidationError):
        return error(422, "invalid_request", "Requête invalide : {\"url\": \"http(s)://…\"} attendu (2048 car. max).")

    @app.post("/api/analyze")
    async def analyze(body: AnalyzeRequest, request: Request):
        ip = client_ip(request, cfg.trust_proxy)
        try:
            result, cache = await service.analyze(body.url, ip)
        except InvalidURL as e:
            return error(422, "invalid_url", str(e))
        except RateLimited as e:
            return error(429, "rate_limited", SCOPE_MESSAGES.get(e.scope, "Limite atteinte."),
                         {"Retry-After": str(e.retry_after)})
        except Busy:
            return error(503, "busy", "Service occupé, réessayez dans quelques secondes.",
                         {"Retry-After": "5"})
        except AnalysisTimeout:
            return error(504, "timeout", "L'analyse a pris trop de temps. Réessayez : "
                         "le résultat partiel sera peut-être en cache.")
        except Exception:
            log.exception("Erreur d'analyse")  # détails côté serveur uniquement
            return error(500, "internal", "Erreur interne lors de l'analyse.")
        return {**result, "cache": cache}

    @app.get("/api/status")
    async def status():
        ml = getattr(analyzer, "_ml", None)
        return {
            "version": __version__,
            "ml_loaded": ml is not None,
            "sources": [s.name for s in analyzer.sources],
            "limits": {"per_ip_per_minute": cfg.rate_per_ip_minute, "per_ip_per_hour": cfg.rate_per_ip_hour,
                       "cache_ttl_seconds": cfg.cache_ttl},
            "quota": {"daily_remaining": service.limits.daily.remaining(),
                      "daily_limit": cfg.daily_budget},
        }

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html", media_type="text/html; charset=utf-8")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def app_factory() -> FastAPI:
    """Point d'entrée uvicorn : `uvicorn bt_url.api.app:app_factory --factory`."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return create_app()
