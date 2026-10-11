from .database import get_database


def users():
    return get_database()["users"]


def clusters():
    return get_database()["clusters"]


def scan_jobs():
    return get_database()["scan_jobs"]


def graph_snapshots():
    return get_database()["graph_snapshots"]


async def create_indexes():
    db = get_database()

    await db.users.create_index("email", unique=True)
    await db.clusters.create_index([("owner_id", 1), ("name", 1)])
    await db.scan_jobs.create_index([("owner_id", 1), ("created_at", -1)])
    await db.graph_snapshots.create_index(
        [("owner_id", 1), ("cluster_id", 1), ("created_at", -1)]
    )
    await db.graph_snapshots.create_index("scan_id", unique=True)