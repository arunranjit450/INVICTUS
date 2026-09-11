from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.chat import router as chat_router
from app.api.dashboard import router as dashboard_router
from app.api.health import router as health_router
from app.services.llm_service import get_mock_llm


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm up and initialize the Mock Enterprise LLM instance at startup."""
    get_mock_llm()
    yield


app = FastAPI(title="LLM Tripwire", lifespan=lifespan)

# CORS configuration for frontend
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(chat_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")



