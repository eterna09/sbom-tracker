"""A security analyst browsing the API: exposure summary and findings lists."""

import os

from locust import HttpUser, between, task

TOKEN = os.environ["SBOM_TOKEN"]
ORGANIZATION_ID = os.environ.get("SBOM_ORGANIZATION_ID", "1")


class SecurityAnalyst(HttpUser):
    wait_time = between(0.5, 1.5)

    def on_start(self) -> None:
        self.client.headers["Authorization"] = f"Bearer {TOKEN}"

    @task(3)
    def exposure_summary(self) -> None:
        self.client.get(f"/organizations/{ORGANIZATION_ID}/exposure", name="exposure")

    @task(2)
    def findings(self) -> None:
        self.client.get(f"/organizations/{ORGANIZATION_ID}/findings?limit=50", name="findings")

    @task(1)
    def known_exploited_findings(self) -> None:
        self.client.get(
            f"/organizations/{ORGANIZATION_ID}/findings?known_exploited=true",
            name="findings (KEV)",
        )
