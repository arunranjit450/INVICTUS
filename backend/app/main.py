from contextlib import asynccontextmanager
from fastapi import FastAPI
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

app.include_router(health_router)
app.include_router(chat_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")


