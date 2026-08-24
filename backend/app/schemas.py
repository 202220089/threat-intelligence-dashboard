from typing import Literal

from pydantic import BaseModel, Field


LogFormat = Literal["pfsense", "auth", "network", "custom"]


class IngestLogRequest(BaseModel):
    format: LogFormat
    raw_message: str = Field(min_length=1)


class BlacklistRequest(BaseModel):
    ip_address: str = Field(min_length=1)
    reason: str = Field(default="Added by analyst", min_length=1)
    source: str = Field(default="analyst", min_length=1)


class PfsenseLogRequest(BaseModel):
    raw_message: str = Field(min_length=1)


class PfsenseLogRequest(BaseModel):
    raw_message: str = Field(min_length=1)
