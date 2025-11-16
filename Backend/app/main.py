from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.config import settings
from app.database import engine, Base
from app.routers import systems, analysis, osint
from app.services.osint_collector import OSINTCollector

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize scheduler
scheduler = BackgroundScheduler()
osint_collector = OSINTCollector()

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting OSINT Cyber Threat Detection System...")
    
    # Start OSINT collection scheduler
    trigger = IntervalTrigger(seconds=settings.OSINT_UPDATE_INTERVAL)
    scheduler.add_job(
        osint_collector.collect_all_feeds,
        trigger,
        id="osint_collection",
        replace_existing=True
    )
    scheduler.start()
    print("✅ OSINT Collector started")
    
    # Initial OSINT data collection
    osint_collector.collect_all_feeds()
    
    yield
    
    # Shutdown
    print("🛑 Shutting down...")
    scheduler.shutdown()
    print("✅ Scheduler stopped")

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(
    systems.router,
    prefix=f"{settings.API_PREFIX}/systems",
    tags=["Systems"]
)

app.include_router(
    analysis.router,
    prefix=f"{settings.API_PREFIX}/analysis",
    tags=["Analysis"]
)

app.include_router(
    osint.router,
    prefix=f"{settings.API_PREFIX}/osint",
    tags=["OSINT"]
)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "status": "running"
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "connected"
    }
