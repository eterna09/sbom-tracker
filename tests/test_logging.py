import json
import logging

import pytest
from fastapi.testclient import TestClient

from app.logging_config import JsonFormatter
from app.models import Organization, User
from tests.helpers import bearer_header


def test_log_lines_are_json_with_extra_fields() -> None:
    record = logging.LogRecord(
        "app.example", logging.INFO, __file__, 1, "hello %s", ("world",), None
    )
    record.request_id = "abc123"

    line = json.loads(JsonFormatter().format(record))

    assert line["message"] == "hello world"
    assert line["level"] == "INFO"
    assert line["logger"] == "app.example"
    assert line["request_id"] == "abc123"
    assert "timestamp" in line


def test_every_request_is_logged_with_its_request_id(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.requests"):
        response = client.get("/health")

    [record] = [r for r in caplog.records if r.name == "app.requests"]
    assert record.method == "GET"
    assert record.path == "/health"
    assert record.status == 200
    assert record.duration_ms >= 0
    assert response.headers["X-Request-ID"] == record.request_id


def test_credentials_never_appear_in_the_logs(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    acme: Organization,
    viewer: User,
) -> None:
    headers = bearer_header(viewer.id)
    token = headers["Authorization"].removeprefix("Bearer ")

    with caplog.at_level(logging.DEBUG):
        client.get(f"/organizations/{acme.id}/findings?status=new", headers=headers)
        client.put(
            "/ci/products/1/versions/1.0/sbom",
            json={"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
            headers={"X-API-Key": "sbom_this-key-must-not-be-logged"},
        )

    everything_logged = caplog.text + " ".join(str(vars(r)) for r in caplog.records)
    assert token not in everything_logged
    assert "sbom_this-key-must-not-be-logged" not in everything_logged


def test_rate_limited_login_is_logged_as_a_warning(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    form = {"username": "admin@acme.example", "password": "wrong-password"}

    with caplog.at_level(logging.WARNING, logger="app.auth.rate_limit"):
        for _ in range(6):
            client.post("/auth/token", data=form)

    [record] = [r for r in caplog.records if r.name == "app.auth.rate_limit"]
    assert record.levelname == "WARNING"
    assert "wrong-password" not in caplog.text
