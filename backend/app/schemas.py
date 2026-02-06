"""Pydantic schemas for request/response validation."""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class EventSchema(BaseModel):
    """Event schema matching JSONL format."""
    ts: float
    pid: int
    event: str
    family: str
    proto: str
    dst_ip: str
    dst_port: int
    result: str
    errno: Optional[str] = None
    resolved_domain: Optional[str] = None
    cmd: Optional[str] = None
    container_image: Optional[str] = None
    run_id: Optional[str] = None


class ReportCreate(BaseModel):
    """Schema for creating a report."""
    run_metadata: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    top_events: List[EventSchema] = []
    flags: List[Dict[str, Any]] = []


class ReportUploadResponse(BaseModel):
    """Response after uploading a report."""
    report_id: str


class ReportResponse(BaseModel):
    """Full report response."""
    id: str
    created_at: datetime
    metadata: Dict[str, Any]
    summary: Dict[str, Any]
    flags: List[Dict[str, Any]]
    top_events: List[EventSchema]
