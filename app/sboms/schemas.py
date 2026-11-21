from typing import Literal

from pydantic import BaseModel, Field


class CycloneDxComponent(BaseModel):
    name: str
    version: str | None = None
    purl: str | None = None


class CycloneDxBom(BaseModel):
    """The subset of a CycloneDX JSON document this API reads; all other fields are ignored."""

    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    spec_version: str = Field(alias="specVersion")
    components: list[CycloneDxComponent] = Field(default_factory=list)
