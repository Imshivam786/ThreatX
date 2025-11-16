"""
Add new columns to alerts table
"""
from sqlalchemy import Column, DateTime, String, Boolean
from app.database import engine
from sqlalchemy import text

def update_alerts_table():
    with engine.connect() as conn:
        # Add new columns
        try:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN resolved_at TIMESTAMP"))
            print("✅ Added resolved_at column")
        except:
            print("⚠️ resolved_at column already exists")
        
        try:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN resolved_by VARCHAR(100)"))
            print("✅ Added resolved_by column")
        except:
            print("⚠️ resolved_by column already exists")
        
        try:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN logged_to_system BOOLEAN DEFAULT FALSE"))
            print("✅ Added logged_to_system column")
        except:
            print("⚠️ logged_to_system column already exists")
        
        conn.commit()
    
    print("\n✅ Database updated successfully!")

if __name__ == "__main__":
    update_alerts_table()
