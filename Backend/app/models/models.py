from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class MonitoredSystem(Base):
    __tablename__ = "monitored_systems"

    id = Column(Integer, primary_key=True, index=True)
    local_name = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(50), nullable=False)
    system_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    
    # SSH Connection Details
    ssh_port = Column(Integer, default=22)
    ssh_username = Column(String(100), nullable=False)
    ssh_password = Column(String(255), nullable=False)  # In production, encrypt this!
    log_path = Column(String(500), default="/var/log")
    
    # Status
    is_active = Column(Boolean, default=True)
    date_configured = Column(DateTime(timezone=True), server_default=func.now())
    last_analyzed = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    alerts = relationship("Alert", back_populates="system", cascade="all, delete-orphan")
    logs = relationship("LogEntry", back_populates="system", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("monitored_systems.id"), nullable=False)
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    severity = Column(String(20), nullable=False, index=True)  # High, Medium, Low
    attack_type = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(20), default="active")  # active, acknowledged, resolved
    
    # ML Detection Info
    confidence_score = Column(Float, nullable=True)
    osint_match = Column(Boolean, default=False)

    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    logged_to_system = Column(Boolean, default=False)
    
    # Relationships
    system = relationship("MonitoredSystem", back_populates="alerts")


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey("monitored_systems.id"), nullable=False)
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    log_level = Column(String(20), nullable=True)
    source = Column(String(100), nullable=True)  # auth.log, apache2, etc.
    message = Column(Text, nullable=False)
    raw_log = Column(Text, nullable=False)
    
    # Analysis
    is_analyzed = Column(Boolean, default=False)
    is_threat = Column(Boolean, default=False)
    threat_score = Column(Float, nullable=True)
    
    # Relationships
    system = relationship("MonitoredSystem", back_populates="logs")


class OSINTThreat(Base):
    __tablename__ = "osint_threats"

    id = Column(Integer, primary_key=True, index=True)
    
    indicator_type = Column(String(50), nullable=False)  # IP, Domain, Hash, URL
    indicator_value = Column(String(500), nullable=False, index=True)
    threat_type = Column(String(100), nullable=False)
    source = Column(String(100), nullable=False)  # AlienVault, Abuse.ch, etc.
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    is_active = Column(Boolean, default=True)


class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"

    id = Column(Integer, primary_key=True, index=True)
    system_id = Column(Integer, ForeignKey('monitored_systems.id', ondelete='CASCADE'))
    
    start_time = Column(DateTime(timezone=True), server_default=func.now())
    end_time = Column(DateTime(timezone=True), nullable=True)
    
    is_running = Column(Boolean, default=True)
    total_logs_analyzed = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    
    status = Column(String(50), default="running")  # running, stopped, completed
