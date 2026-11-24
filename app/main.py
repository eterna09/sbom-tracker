from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api_keys.router import router as api_keys_router
from app.auth.router import router as auth_router
from app.db import SessionDep
from app.exposure.router import router as exposure_router
from app.findings.router import router as findings_router
from app.middleware import limit_request_size
from app.products.router import router as products_router
from app.sboms.router import router as sboms_router

app = FastAPI(title="SBOM Tracker")
app.middleware("http")(limit_request_size)
app.include_router(auth_router)
app.include_router(products_router)
app.include_router(api_keys_router)
app.include_router(sboms_router)
app.include_router(findings_router)
app.include_router(exposure_router)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def readiness(session: SessionDep) -> dict[str, str]:
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ready"}
