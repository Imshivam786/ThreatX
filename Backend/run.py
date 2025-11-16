"""
Main entry point to run the FastAPI application
"""
import uvicorn
from app.config import settings

if __name__ == "__main__":
    print(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"📡 Server will be available at: http://localhost:8000")
    print(f"📚 API documentation: http://localhost:8000/docs")
    print(f"🔧 Debug mode: {settings.DEBUG}")
    print()
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )
