from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="Raw log text")
    log_type: Optional[str] = Field(None, description="Optional log type override")
    mode: str = Field("standard", description="quick | standard | deep")


class AnalyzeResponse(BaseModel):
    id: str
    mode: str
    detected_types: list
    stats: dict
    chunk_count: int
    report: str
    chunk_summaries: list
