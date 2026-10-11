from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, ConfigDict, EmailStr


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ClusterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    context_name: str = Field(min_length=1, max_length=200)


class ClusterRecord(ClusterCreate):
    id: str
    owner_id: str
    status: Literal["registered", "online", "offline"] = "registered"
    created_at: datetime = Field(default_factory=utc_now)


class ScanJobCreate(BaseModel):
    cluster_id: str = Field(min_length=1)
    scan_type: Literal["scan_cluster"] = "scan_cluster"


class ScanJobRecord(BaseModel):
    id: str
    owner_id: str
    cluster_id: str
    status: Literal[
        "queued", "running", "completed", "failed"
    ] = "queued"
    created_at: datetime = Field(default_factory=utc_now)


class GraphSnapshotCreate(BaseModel):
    cluster_id: str = Field(min_length=1)
    scan_id: str = Field(min_length=1)
    graph: dict[str, Any]


class GraphSnapshotRecord(GraphSnapshotCreate):
    id: str
    owner_id: str
    created_at: datetime = Field(default_factory=utc_now)


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1)


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str = Field(min_length=1)
    target: str = Field(min_length=1)

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class UserRecord(BaseModel):
    id: str
    email: str
    password_hash: str
    role: Literal["admin", "analyst", "viewer"] = "viewer"
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class AgentJobComplete(BaseModel):
    graph: dict


class AgentJobFailure(BaseModel):
    error: str = Field(min_length=1, max_length=1000)