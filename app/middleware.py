import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from http import HTTPStatus

from fastapi import Request, Response
from fastapi.responses import JSONResponse

MAX_REQUEST_BYTES = 5 * 1024 * 1024


async def limit_request_size(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    declared_length = request.headers.get("content-length", "")
    if declared_length.isdigit() and int(declared_length) > MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Request body too large"},
        )
    return await call_next(request)


request_logger = logging.getLogger("app.requests")


async def log_requests(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Log one line per request (no headers, bodies or query strings) and return its id."""
    request_id = uuid.uuid4().hex
    started = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    response.headers["X-Request-ID"] = request_id
    request_logger.info(
        "request",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    return response
