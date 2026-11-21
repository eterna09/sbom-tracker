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
