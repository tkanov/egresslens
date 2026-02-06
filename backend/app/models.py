"""SQLAlchemy database models."""
from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timezone
import uuid

Base = declarative_base()


class Report(Base):
    """Report model for storing egress monitoring data."""
    __tablename__ = "reports"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    run_metadata = Column(JSON, default=dict)  # From run.json
    summary = Column(JSON, default=dict)  # Aggregated stats
    top_events = Column(JSON, default=list)  # Top N events
    flags = Column(JSON, default=list)  # Flags
