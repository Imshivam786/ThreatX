from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Any

# System Schemas
class SystemBase(BaseModel):
    local_name: str = Field(..., alias='localName')
    ip_address: str = Field(..., alias='ipAddress')
    system_type: str = Field(..., alias='systemType')
    description: Optional[str] = None
    ssh_port: int = Field(22, alias='sshPort')
    ssh_username: str = Field(..., alias='sshUsername')
    ssh_password: str = Field(..., alias='sshPassword')
    log_path: str = Field("/var/log", alias='logPath')
    
    class Config:
        populate_by_name = True

class SystemCreate(SystemBase):
    class Config:
        populate_by_name = True

class SystemUpdate(BaseModel):
    local_name: Optional[str] = None
    ip_address: Optional[str] = None
    system_type: Optional[str] = None
    description: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    log_path: Optional[str] = None
    is_active: Optional[bool] = None

class SystemResponse(SystemBase):
    id: int
    is_active: bool
    date_configured: datetime
    last_analyzed: Optional[datetime] = None

    class Config:
        from_attributes = True

# Alert Schemas
class AlertBase(BaseModel):
    severity: str
    attack_type: str
    source_ip: str
    description: str

class AlertCreate(AlertBase):
    system_id: int
    confidence_score: Optional[float] = None
    osint_match: bool = False

class AlertResponse(AlertBase):
    id: int
    system_id: int
    timestamp: datetime
    status: str
    confidence_score: Optional[float] = None
    osint_match: bool

    class Config:
        from_attributes = True

# Threat Data Schemas
class AttackType(BaseModel):
    name: str
    count: int
    severity: str

class TimeSeriesPoint(BaseModel):
    timestamp: str
    request_count: int
    threat_count: int

class ThreatData(BaseModel):
    system_id: int
    system_name: str
    total_requests: int
    threats_detected: int
    high_severity_threats: int
    medium_severity_threats: int
    low_severity_threats: int
    top_attack_types: List[AttackType]
    time_series_data: List[TimeSeriesPoint]
    recent_alerts: List[AlertResponse]
    resolved_threats: Any
    resolution_time_series: Any
    auto_resolved_threats: int = 0

# OSINT Schemas
class OSINTThreatCreate(BaseModel):
    indicator_type: str
    indicator_value: str
    threat_type: str
    source: str
    description: Optional[str] = None
    severity: str

class OSINTThreatResponse(OSINTThreatCreate):
    id: int
    first_seen: datetime
    last_updated: datetime
    is_active: bool

    class Config:
        from_attributes = True

# Analysis Status Schema
class AnalysisStatus(BaseModel):
    is_running: bool
    start_time: Optional[datetime] = None
    total_logs_analyzed: int = 0
    threats_detected: int = 0
