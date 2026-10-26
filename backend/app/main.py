"""FastAPI application entry point.

Builds the app via a factory so tests can construct isolated instances. Wires
CORS (explicit origins only), a consistent error envelope, structured logging,
and the router set. Scanner/scan routers are added in later phases; the health
router is live now.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.errors import ApiError
from app.api.routes import contract, findings, health, reports, scans, ws
from app.api.schemas.contract import CONTRACT_VERSION
from app.config import settings
from app.core.checks.registry import validate_registry_at_startup
from app.utils.logging import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks."""
    configure_logging()
    # Fail fast if a check is implemented without a spec in checks.yaml.
    validate_registry_at_startup()
    logger.info(
        "starting cawasma backend env=%s debug=%s", settings.ENVIRONMENT, settings.DEBUG
    )
    if settings.MOCK_API:
        logger.warning("MOCK_API=true: contract routes return example data, not scans")
    else:
        await _fail_interrupted_scans()
    yield
    logger.info("shutting down cawasma backend")


async def _fail_interrupted_scans() -> None:
    """Scans this process was running died with it (BackgroundTasks)."""
    from app.db.session import session_scope
    from app.services.scan_service import fail_interrupted_scans

    try:
        async with session_scope() as session:
            n = await fail_interrupted_scans(session)
        if n:
            logger.warning("marked %d interrupted scan(s) as FAILED", n)
    except Exception as exc:  # noqa: BLE001 - a DB hiccup must not stop the api
        logger.warning("could not check for interrupted scans: %s", exc)


def _error_body(code: str, message: str) -> dict:
    """Build the standard error envelope (spec section 44)."""
    return {"success": False, "error": {"code": code, "message": message}}


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="CAWASMA — Context-Aware Web & API Security Misconfiguration Analyzer",
        description=(
            "Defensive black-box security misconfiguration analyzer. "
            f"Public routes follow API contract v{CONTRACT_VERSION} "
            "(tag 'contract v1'; docs/api-contract.md). Deprecated routes serve the "
            "pre-contract frontend and will be removed."
        ),
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # --- CORS: explicit origins only, never "*" --------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.frontend_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        # Let browser code read these (POST /api/scan's Location, exports).
        expose_headers=["Location", "X-Contract-Version", "Content-Disposition"],
    )

    # --- Consistent error handling ---------------------------------------
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        code = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            501: "NOT_IMPLEMENTED",
        }.get(exc.status_code, "HTTP_ERROR")
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse(
            status_code=exc.status_code, content=_error_body(code, detail)
        )

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status_code, content=_error_body(exc.code, exc.message)
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        return JSONResponse(
            status_code=422,
            content=_error_body(
                "VALIDATION_ERROR", "Request validation failed."
            )
            # loc/msg/type only: "input" would echo the body, "ctx" may hold
            # exception objects that aren't JSON.
            | {"details": [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]}
                           for e in exc.errors()]},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Never leak stack traces to clients (spec section 27/44).
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content=_error_body(
                "INTERNAL_ERROR", "An internal error occurred."
            ),
        )

    # Every response says which API contract it follows.
    @app.middleware("http")
    async def contract_version_header(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Contract-Version"] = CONTRACT_VERSION
        return response

    # --- Routers ---------------------------------------------------------
    app.include_router(health.router)
    app.include_router(contract.router)
    # Pre-contract routes used by the current Vite SPA; kept until it migrates.
    for legacy in (scans.router, findings.router, reports.router, ws.router):
        app.include_router(legacy, deprecated=True)

    _add_contract_version_to_openapi(app)
    return app


def _add_contract_version_to_openapi(app: FastAPI) -> None:
    base_openapi = app.openapi

    def openapi() -> dict:
        if app.openapi_schema is None:
            schema = base_openapi()
            schema["info"]["x-contract-version"] = CONTRACT_VERSION
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]


app = create_app()
