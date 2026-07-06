from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis.api.routes import router
from aegis.config import get_settings
from aegis.database import Base, engine

settings = get_settings()
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SOCloom",
    description="Weave 800+ security skills into AI-powered SOC operations",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
app.include_router(router, prefix="")


@app.get("/")
def root():
    return {
        "name": "SOCloom",
        "tagline": "Weave 800+ Security Skills into AI-Powered SOC Operations",
        "docs": "/docs",
        "health": "/api/v1/health",
    }