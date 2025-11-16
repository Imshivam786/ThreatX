-- Create database
CREATE DATABASE threat_detection;

-- Connect to database
\c threat_detection;

-- Create extension for UUID support (optional)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE threat_detection TO postgres;

-- Verify tables after running init_db.py
-- \dt
