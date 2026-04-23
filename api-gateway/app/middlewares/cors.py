import logging
from fastapi.middleware.cors import CORSMiddleware
from config import CORS_ORIGINS, ENVIRONMENT

logger = logging.getLogger(__name__)

def setup_cors(app):
    if ENVIRONMENT == "production" and CORS_ORIGINS == ["*"]:
        logger.warning(
            "CORS_ORIGINS is set to '*' in production. "
            "Set the CORS_ORIGINS environment variable to a specific origin list."
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
