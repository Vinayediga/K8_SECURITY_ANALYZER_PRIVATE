from pymongo import AsyncMongoClient

from .config import settings


_client = None
_database = None


async def connect_to_database():
    global _client, _database

    if not settings.MONGODB_URI:
        raise RuntimeError("MONGODB_URI is not configured")

    _client = AsyncMongoClient(settings.MONGODB_URI)
    _database = _client[settings.MONGODB_DATABASE]

    await _client.admin.command("ping")


def get_database():
    if _database is None:
        raise RuntimeError("Database is not connected")

    return _database


async def close_database_connection():
    global _client, _database

    if _client is not None:
        await _client.close()

    _client = None
    _database = None