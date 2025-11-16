# OSINT-Based Cyber Threat Detection System - Backend

FastAPI backend for real-time cyber threat detection using OSINT and Machine Learning.

## Features

- 🔍 OSINT threat intelligence collection
- 🤖 ML-based threat detection
- 📊 Real-time log analysis
- 🚨 Automated alert generation
- 📈 Threat visualization data
- 🔐 SSH-based log collection

## Prerequisites

- Python 3.9+
- PostgreSQL 12+
- 8GB RAM minimum

## Installation

1. Install dependencies:

2. Configure database:

3. Initialize database:

4. Run the application:

## API Endpoints

### Systems
- `POST /api/systems` - Add new monitored system
- `GET /api/systems` - Get all systems
- `GET /api/systems/{id}` - Get system details
- `DELETE /api/systems/{id}` - Remove system

### Analysis
- `POST /api/analysis/start/{system_id}` - Start analysis
- `POST /api/analysis/stop/{system_id}` - Stop analysis
- `GET /api/analysis/threats/{system_id}` - Get threat data
- `GET /api/analysis/alerts/{system_id}` - Get alerts

### OSINT
- `GET /api/osint/threats` - Get OSINT threats
- `POST /api/osint/check-ip` - Check IP reputation
- `POST /api/osint/refresh` - Refresh OSINT data

## API Documentation

Visit http://localhost:8000/docs for interactive API documentation.

## Configuration

Edit `.env` file for configuration:
- Database connection
- API keys (optional)
- Analysis parameters
- OSINT update intervals
