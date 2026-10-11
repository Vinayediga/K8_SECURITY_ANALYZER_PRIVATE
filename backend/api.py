from contextlib import asynccontextmanager
from datetime import datetime, timezone,timedelta
from fastapi import Depends, HTTPException
from .models import ScanJobCreate, GraphSnapshotCreate
from .repositories import scan_jobs, clusters, graph_snapshots
from analysis.graph_engine import GraphEngine, GraphError
from bson import ObjectId
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt.exceptions import InvalidTokenError
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from pymongo.errors import DuplicateKeyError
import hashlib
import secrets
import asyncio
import requests


from pymongo import ReturnDocument

from .database import get_database

from .models import ClusterCreate
from .repositories import clusters

from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from .config import settings
from .database import (
    close_database_connection,
    connect_to_database,
)
from .models import AgentJobComplete, AgentJobFailure, UserCreate
from .repositories import create_indexes, users

security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_database()
    try:
        await create_indexes()
        yield
    finally:
        await close_database_connection()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "k8s-attack-path-visualizer",
    }


@app.get("/health/database")
async def database_health_check():
    from .database import get_database

    await get_database().command("ping")
    return {"status": "ok", "database": "connected"}


@app.post("/auth/register", status_code=201)
async def register_user(user: UserCreate):
    email = str(user.email).lower().strip()

    try:
        result = await users().insert_one({
            "email": email,
            "password_hash": hash_password(user.password),
            "role": "viewer",
            "is_active": True,
        })
    except DuplicateKeyError:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )

    return {
        "id": str(result.inserted_id),
        "email": email,
        "role": "viewer",
    }


@app.post("/auth/login")
async def login_user(user: UserCreate):
    email = str(user.email).lower().strip()
    record = await users().find_one({"email": email})

    if (
        not record
        or not record.get("is_active", False)
        or not verify_password(user.password, record["password_hash"])
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    return {
        "access_token": create_access_token(str(record["_id"])),
        "token_type": "bearer",
        "expires_in": 900,
    }


@app.post("/auth/google")
async def login_with_google(payload: dict):
    credential = str(payload.get("credential", "")).strip()
    if not credential:
        raise HTTPException(status_code=400, detail="Google credential is required")
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Google sign-in is not configured")

    def verify_google_token():
        response = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": credential},
            timeout=5,
        )
        response.raise_for_status()
        return response.json()

    try:
        token = await asyncio.to_thread(verify_google_token)
    except (requests.RequestException, ValueError):
        raise HTTPException(status_code=401, detail="Invalid Google credential")

    if token.get("aud") != settings.GOOGLE_CLIENT_ID or token.get("email_verified") != "true":
        raise HTTPException(status_code=401, detail="Google account could not be verified")

    email = str(token.get("email", "")).lower().strip()
    if not email:
        raise HTTPException(status_code=401, detail="Google account did not provide an email")

    record = await users().find_one({"email": email})
    if not record:
        result = await users().insert_one({
            "email": email,
            "password_hash": hash_password(secrets.token_urlsafe(32)),
            "role": "viewer",
            "is_active": True,
            "auth_provider": "google",
            "google_subject": token.get("sub"),
        })
        user_id = str(result.inserted_id)
    elif not record.get("is_active", False):
        raise HTTPException(status_code=403, detail="User account is inactive")
    else:
        user_id = str(record["_id"])

    return {
        "access_token": create_access_token(user_id),
        "token_type": "bearer",
        "expires_in": 900,
    }

agent_security = HTTPBearer()


async def get_current_agent(
    credentials: HTTPAuthorizationCredentials = Depends(agent_security),
):
    token_hash = hashlib.sha256(
        credentials.credentials.encode()
    ).hexdigest()

    agent = await get_database()["agents"].find_one({
        "token_hash": token_hash,
        "is_active": True,
    })

    if not agent:
        raise HTTPException(
            status_code=401,
            detail="Invalid agent credentials",
        )

    return agent


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = payload["sub"]

        if not ObjectId.is_valid(user_id):
            raise ValueError("Invalid user ID")

        record = await users().find_one({"_id": ObjectId(user_id)})

        if not record or not record.get("is_active", False):
            raise ValueError("Inactive or missing user")

        return {
            "id": str(record["_id"]),
            "email": record["email"],
            "role": record["role"],
        }

    except (InvalidTokenError, ValueError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/agents/register", status_code=201)
async def register_agent(
    cluster_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(cluster_id):
        raise HTTPException(400, "Invalid cluster ID")

    cluster = await clusters().find_one({
        "_id": ObjectId(cluster_id),
        "owner_id": current_user["id"],
    })

    if not cluster:
        raise HTTPException(404, "Cluster not found")

    context_name = cluster.get("context_name")
    if not context_name:
        raise HTTPException(
            422,
            "Cluster has no registered Kubernetes context",
        )

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    result = await get_database()["agents"].insert_one({
        "owner_id": current_user["id"],
        "cluster_id": cluster_id,
        "context_name": context_name,
        "token_hash": token_hash,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    })

    return {
        "agent_id": str(result.inserted_id),
        "cluster_id": cluster_id,
        "context_name": context_name,
        "agent_token": token,
        "message": "Save this token securely; it will not be shown again.",
    }


@app.post("/agents/{agent_id}/rotate-token")
async def rotate_agent_token(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(agent_id):
        raise HTTPException(400, "Invalid agent ID")

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    result = await get_database()["agents"].update_one(
        {
            "_id": ObjectId(agent_id),
            "owner_id": current_user["id"],
            "is_active": True,
        },
        {
            "$set": {
                "token_hash": token_hash,
                "rotated_at": datetime.now(timezone.utc),
            }
        },
    )

    if result.matched_count == 0:
        raise HTTPException(404, "Active agent not found")

    agent = await get_database()["agents"].find_one({"_id": ObjectId(agent_id)})
    return {
        "agent_id": agent_id,
        "cluster_id": agent["cluster_id"],
        "context_name": agent["context_name"],
        "agent_token": token,
        "message": "The previous token is no longer valid. Save this token securely; it will not be shown again.",
    }


@app.post("/agent/jobs/claim")
async def claim_agent_job(
    agent: dict = Depends(get_current_agent),
):
    now = datetime.now(timezone.utc)

    job = await get_database()["scan_jobs"].find_one_and_update(
        {
            "owner_id": agent["owner_id"],
            "cluster_id": agent["cluster_id"],
            "status": "queued",
        },
        {
            "$set": {
                "status": "running",
                "agent_id": str(agent["_id"]),
                "claimed_at": now,
                "lease_expires_at": now + timedelta(minutes=5),
            }
        },
        sort=[("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )

    if not job:
        return {"job": None}

    return {
        "job": {
            "id": str(job["_id"]),
            "cluster_id": job["cluster_id"],
            "scan_type": job["scan_type"],
        }
    }

@app.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.post("/clusters", status_code=201)
async def register_cluster(
    cluster: ClusterCreate,
    current_user: dict = Depends(get_current_user),
):
    document = {
        "name": cluster.name.strip(),
        "context_name": cluster.context_name.strip(),
        "owner_id": current_user["id"],
        "status": "registered",
        "created_at": datetime.now(timezone.utc),
    }

    if not document["name"] or not document["context_name"]:
        raise HTTPException(400, "Name and context are required")

    try:
        result = await clusters().insert_one(document)
    except DuplicateKeyError:
        raise HTTPException(409, "Cluster already registered")

    return {
        "id": str(result.inserted_id),
        "name": document["name"],
        "context_name": document["context_name"],
        "owner_id": document["owner_id"],
        "status": document["status"],
        "created_at": document["created_at"].isoformat(),
    }


@app.get("/clusters")
async def list_clusters(
    current_user: dict = Depends(get_current_user),
):
    cursor = clusters().find({"owner_id": current_user["id"]})
    results = []

    async for cluster in cursor:
        cluster["id"] = str(cluster.pop("_id"))
        cluster["created_at"] = cluster["created_at"].isoformat()
        results.append(cluster)

    return results


@app.get("/clusters/{cluster_id}")
async def get_cluster(
    cluster_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(cluster_id):
        raise HTTPException(400, "Invalid cluster ID")

    cluster = await clusters().find_one({
        "_id": ObjectId(cluster_id),
        "owner_id": current_user["id"],
    })

    if not cluster:
        raise HTTPException(404, "Cluster not found")

    cluster["id"] = str(cluster.pop("_id"))
    cluster["created_at"] = cluster["created_at"].isoformat()
    return cluster


@app.put("/clusters/{cluster_id}")
async def update_cluster(
    cluster_id: str,
    cluster: ClusterCreate,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(cluster_id):
        raise HTTPException(400, "Invalid cluster ID")
    name = cluster.name.strip()
    context_name = cluster.context_name.strip()
    if not name or not context_name:
        raise HTTPException(400, "Name and context are required")
    try:
        updated = await clusters().find_one_and_update(
            {"_id": ObjectId(cluster_id), "owner_id": current_user["id"]},
            {"$set": {"name": name, "context_name": context_name}},
            return_document=ReturnDocument.AFTER,
        )
    except DuplicateKeyError:
        raise HTTPException(409, "Cluster name already registered")
    if not updated:
        raise HTTPException(404, "Cluster not found")
    updated["id"] = str(updated.pop("_id"))
    updated["created_at"] = updated["created_at"].isoformat()
    return updated


@app.delete("/clusters/{cluster_id}")
async def delete_cluster(
    cluster_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(cluster_id):
        raise HTTPException(400, "Invalid cluster ID")
    cluster_filter = {"_id": ObjectId(cluster_id), "owner_id": current_user["id"]}
    if not await clusters().find_one(cluster_filter):
        raise HTTPException(404, "Cluster not found")
    await get_database()["agents"].delete_many({"cluster_id": cluster_id})
    await graph_snapshots().delete_many({"cluster_id": cluster_id, "owner_id": current_user["id"]})
    await scan_jobs().delete_many({"cluster_id": cluster_id, "owner_id": current_user["id"]})
    await clusters().delete_one(cluster_filter)
    return {"deleted": True, "cluster_id": cluster_id}


@app.post("/scans", status_code=201)
async def create_scan(
    scan: ScanJobCreate,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(scan.cluster_id):
        raise HTTPException(status_code=400, detail="Invalid cluster ID")

    cluster = await clusters().find_one({
        "_id": ObjectId(scan.cluster_id),
        "owner_id": current_user["id"],
    })

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    document = {
        "owner_id": current_user["id"],
        "cluster_id": scan.cluster_id,
        "scan_type": "scan_cluster",
        "status": "queued",
        "created_at": datetime.now(timezone.utc),
    }

    result = await scan_jobs().insert_one(document)

    return {
    "id": str(result.inserted_id),
    "owner_id": document["owner_id"],
    "cluster_id": document["cluster_id"],
    "scan_type": document["scan_type"],
    "status": document["status"],
    "created_at": document["created_at"].isoformat(),
}


@app.get("/scans")
async def list_scans(
    current_user: dict = Depends(get_current_user),
):
    cursor = scan_jobs().find(
        {"owner_id": current_user["id"]}
    ).sort("created_at", -1)

    results = []

    async for scan in cursor:
        scan["id"] = str(scan.pop("_id"))
        scan["created_at"] = scan["created_at"].isoformat()
        results.append(scan)

    return results


@app.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    scan = await scan_jobs().find_one({
        "_id": ObjectId(scan_id),
        "owner_id": current_user["id"],
    })

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan["id"] = str(scan.pop("_id"))
    scan["created_at"] = scan["created_at"].isoformat()
    return scan


@app.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(scan_id):
        raise HTTPException(400, "Invalid scan ID")
    scan_filter = {"_id": ObjectId(scan_id), "owner_id": current_user["id"]}
    result = await scan_jobs().delete_one(scan_filter)
    if result.deleted_count == 0:
        raise HTTPException(404, "Scan not found")
    await graph_snapshots().delete_many({"scan_id": scan_id, "owner_id": current_user["id"]})
    return {"deleted": True, "scan_id": scan_id}

@app.post("/snapshots", status_code=201)
async def save_snapshot(
    snapshot: GraphSnapshotCreate,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(snapshot.cluster_id):
        raise HTTPException(400, "Invalid cluster ID")

    if not ObjectId.is_valid(snapshot.scan_id):
        raise HTTPException(400, "Invalid scan ID")

    cluster = await clusters().find_one({
        "_id": ObjectId(snapshot.cluster_id),
        "owner_id": current_user["id"],
    })
    if not cluster:
        raise HTTPException(404, "Cluster not found")

    scan = await scan_jobs().find_one({
        "_id": ObjectId(snapshot.scan_id),
        "owner_id": current_user["id"],
        "cluster_id": snapshot.cluster_id,
        "status": "completed",
    })
    if not scan:
        raise HTTPException(400, "Completed scan not found for this cluster")

    graph = snapshot.graph
    nodes = graph.get("nodes")
    edges = graph.get("edges")

    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise HTTPException(422, "Graph must contain nodes and edges arrays")

    node_ids = set()
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise HTTPException(422, "Every node must have a string id")
        if node["id"] in node_ids:
            raise HTTPException(422, "Duplicate node id")
        node_ids.add(node["id"])

    for edge in edges:
        if not isinstance(edge, dict):
            raise HTTPException(422, "Every edge must be an object")
        source, target = edge.get("source"), edge.get("target")
        if source not in node_ids or target not in node_ids:
            raise HTTPException(422, "Edge references an unknown node")

    document = {
        "owner_id": current_user["id"],
        "cluster_id": snapshot.cluster_id,
        "scan_id": snapshot.scan_id,
        "graph": graph,
        "created_at": datetime.now(timezone.utc),
    }

    result = await graph_snapshots().insert_one(document)

    return {
        "id": str(result.inserted_id),
        "cluster_id": document["cluster_id"],
        "scan_id": document["scan_id"],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "created_at": document["created_at"].isoformat(),
    }


@app.get("/snapshots")
async def list_snapshots(
    cluster_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(cluster_id):
        raise HTTPException(400, "Invalid cluster ID")

    cluster = await clusters().find_one({
        "_id": ObjectId(cluster_id),
        "owner_id": current_user["id"],
    })
    if not cluster:
        raise HTTPException(404, "Cluster not found")

    cursor = graph_snapshots().find({
        "owner_id": current_user["id"],
        "cluster_id": cluster_id,
    }).sort("created_at", -1)

    results = []
    async for item in cursor:
        results.append({
            "id": str(item["_id"]),
            "cluster_id": item["cluster_id"],
            "scan_id": item["scan_id"],
            "node_count": len(item["graph"]["nodes"]),
            "edge_count": len(item["graph"]["edges"]),
            "created_at": item["created_at"].isoformat(),
        })

    return results


@app.get("/snapshots/{snapshot_id}")
async def get_snapshot(
    snapshot_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(snapshot_id):
        raise HTTPException(400, "Invalid snapshot ID")

    item = await graph_snapshots().find_one({
        "_id": ObjectId(snapshot_id),
        "owner_id": current_user["id"],
    })
    if not item:
        raise HTTPException(404, "Snapshot not found")

    return {
        "id": str(item["_id"]),
        "cluster_id": item["cluster_id"],
        "scan_id": item["scan_id"],
        "graph": item["graph"],
        "created_at": item["created_at"].isoformat(),
    }
def load_snapshot_engine(snapshot):
    engine = GraphEngine()
    engine.load_data(snapshot["graph"])
    return engine


@app.get("/snapshots/{snapshot_id}/analysis")
async def analyze_snapshot(
    snapshot_id: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(snapshot_id):
        raise HTTPException(400, "Invalid snapshot ID")

    snapshot = await graph_snapshots().find_one({
        "_id": ObjectId(snapshot_id),
        "owner_id": current_user["id"],
    })

    if not snapshot:
        raise HTTPException(404, "Snapshot not found")

    try:
        engine = load_snapshot_engine(snapshot)
        return {
            "stats": engine.stats(),
            "cycles": engine.find_cycles(),
            "critical_nodes": engine.critical_node_analysis(),
        }
    except GraphError as exc:
        raise HTTPException(422, str(exc))


@app.get("/snapshots/{snapshot_id}/paths")
async def analyze_path(
    snapshot_id: str,
    source: str,
    target: str,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(snapshot_id):
        raise HTTPException(400, "Invalid snapshot ID")

    snapshot = await graph_snapshots().find_one({
        "_id": ObjectId(snapshot_id),
        "owner_id": current_user["id"],
    })

    if not snapshot:
        raise HTTPException(404, "Snapshot not found")

    try:
        engine = load_snapshot_engine(snapshot)
        return engine.shortest_path(source, target)
    except GraphError as exc:
        raise HTTPException(422, str(exc))


@app.get("/snapshots/{snapshot_id}/blast-radius")
async def analyze_blast_radius(
    snapshot_id: str,
    source: str,
    hops: int = 2,
    current_user: dict = Depends(get_current_user),
):
    if not ObjectId.is_valid(snapshot_id):
        raise HTTPException(400, "Invalid snapshot ID")

    snapshot = await graph_snapshots().find_one({
        "_id": ObjectId(snapshot_id),
        "owner_id": current_user["id"],
    })

    if not snapshot:
        raise HTTPException(404, "Snapshot not found")

    try:
        engine = load_snapshot_engine(snapshot)
        return engine.blast_radius(source, hops)
    except GraphError as exc:
        raise HTTPException(422, str(exc))
@app.post("/agent/jobs/{job_id}/complete")
async def complete_agent_job(
    job_id: str,
    payload: AgentJobComplete,
    agent: dict = Depends(get_current_agent),
):
    if not ObjectId.is_valid(job_id):
        raise HTTPException(400, "Invalid job ID")

    db = get_database()
    jobs = db["scan_jobs"]

    # Confirm the job is assigned to this agent and cluster.
    job = await jobs.find_one({
        "_id": ObjectId(job_id),
        "owner_id": agent["owner_id"],
        "cluster_id": agent["cluster_id"],
        "agent_id": str(agent["_id"]),
        "status": "running",
    })

    if not job:
        raise HTTPException(404, "Active assigned job not found")

    graph = payload.graph
    nodes = graph.get("nodes")
    edges = graph.get("edges")

    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise HTTPException(422, "Graph must contain nodes and edges arrays")

    if len(nodes) > 50000 or len(edges) > 200000:
        raise HTTPException(413, "Graph exceeds allowed size")

    node_ids = set()

    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise HTTPException(422, "Each node must have a string id")
        if node["id"] in node_ids:
            raise HTTPException(422, "Duplicate node id")
        node_ids.add(node["id"])

    for edge in edges:
        if not isinstance(edge, dict):
            raise HTTPException(422, "Each edge must be an object")
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            raise HTTPException(422, "Edge references an unknown node")

    now = datetime.now(timezone.utc)

    # Claim completion atomically to prevent duplicate uploads.
    updated_job = await jobs.find_one_and_update(
        {
            "_id": ObjectId(job_id),
            "agent_id": str(agent["_id"]),
            "status": "running",
        },
        {"$set": {"status": "completed", "completed_at": now}},
        return_document=ReturnDocument.AFTER,
    )

    if not updated_job:
        raise HTTPException(409, "Job is no longer running")

    try:
        snapshot = {
            "owner_id": agent["owner_id"],
            "cluster_id": job["cluster_id"],
            "scan_id": job_id,
            "graph": graph,
            "created_at": now,
        }
        result = await db["graph_snapshots"].insert_one(snapshot)

    except Exception:
        # Do not leave a completed job without a snapshot.
        await jobs.update_one(
            {
                "_id": ObjectId(job_id),
                "agent_id": str(agent["_id"]),
                "status": "completed",
            },
            {"$set": {"status": "failed", "error": "Snapshot persistence failed"}},
        )
        raise HTTPException(500, "Could not save graph snapshot")

    return {
        "job_id": job_id,
        "snapshot_id": str(result.inserted_id),
        "status": "completed",
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


@app.post("/agent/jobs/{job_id}/fail")
async def fail_agent_job(
    job_id: str,
    payload: AgentJobFailure,
    agent: dict = Depends(get_current_agent),
):
    if not ObjectId.is_valid(job_id):
        raise HTTPException(400, "Invalid job ID")

    result = await get_database()["scan_jobs"].update_one(
        {
            "_id": ObjectId(job_id),
            "owner_id": agent["owner_id"],
            "cluster_id": agent["cluster_id"],
            "agent_id": str(agent["_id"]),
            "status": "running",
        },
        {
            "$set": {
                "status": "failed",
                "error": payload.error,
                "completed_at": datetime.now(timezone.utc),
            }
        },
    )

    if result.modified_count == 0:
        raise HTTPException(404, "Active assigned job not found")

    return {"job_id": job_id, "status": "failed"}