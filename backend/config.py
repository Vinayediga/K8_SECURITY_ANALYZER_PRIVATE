import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    APP_NAME = "Kubernetes Attack Path Visualizer API"
    APP_VERSION = "1.0.0"

    FRONTEND_ORIGINS = [
        origin.strip()
        for origin in os.getenv(
            "FRONTEND_ORIGINS",
            "http://localhost:5173",
        ).split(",")
        if origin.strip()
    ]

    MONGODB_URI = os.getenv("MONGODB_URI", "")
    MONGODB_DATABASE = os.getenv(
        "MONGODB_DATABASE",
        "k8s_attack_path_visualizer",
    )

    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")


settings = Settings()