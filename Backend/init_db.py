"""
Database initialization script
Run this to create all database tables
"""
from app.database import engine, Base
from app.models import (
    MonitoredSystem,
    Alert,
    LogEntry,
    OSINTThreat,
    AnalysisSession
)

def init_database():
    """
    Initialize database with all tables
    """
    print("🗄️  Creating database tables...")
    
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        
        print("✅ Database tables created successfully!")
        print("\nTables created:")
        print("  - monitored_systems")
        print("  - alerts")
        print("  - log_entries")
        print("  - osint_threats")
        print("  - analysis_sessions")
        
    except Exception as e:
        print(f"❌ Error creating database: {str(e)}")
        raise

if __name__ == "__main__":
    init_database()
