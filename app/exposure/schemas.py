from pydantic import BaseModel


class ProductExposureOut(BaseModel):
    product_id: int
    product_name: str
    latest_version: str | None
    open_findings: int
    open_critical: int
    open_high: int
    open_known_exploited: int
