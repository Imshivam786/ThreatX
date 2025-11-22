from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case
from datetime import datetime, timedelta
from typing import List

from app.database import get_db
from app.schemas import ThreatData, AlertResponse, AnalysisStatus, AttackType, TimeSeriesPoint
from app.models import MonitoredSystem, Alert, LogEntry, AnalysisSession
from app.services.log_collector import LogCollector
from app.services.threat_detector import ThreatDetector

router = APIRouter()

# Store active analysis sessions
active_sessions = {}


@router.post("/start/{system_id}")
async def start_analysis(
    system_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start real-time analysis for a system
    """
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    # Check if already running
    if system_id in active_sessions and active_sessions[system_id].get("is_running"):
        return {
            "message": "Analysis already running",
            "system_id": system_id
        }
    
    # Create analysis session
    session = AnalysisSession(
        system_id=system_id,
        is_running=True,
        status="running"
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # Store in active sessions
    active_sessions[system_id] = {
        "is_running": True,
        "session_id": session.id,
        "start_time": datetime.utcnow()
    }
    
    # Start background analysis
    background_tasks.add_task(run_analysis, system_id, session.id, db)
    
    return {
        "message": "Analysis started successfully",
        "system_id": system_id,
        "session_id": session.id
    }


@router.post("/stop/{system_id}")
async def stop_analysis(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Stop analysis for a system
    """
    if system_id not in active_sessions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active analysis session for this system"
        )
    
    # Mark as stopped
    active_sessions[system_id]["is_running"] = False
    
    # Update database session
    session_id = active_sessions[system_id]["session_id"]
    session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
    
    if session:
        session.is_running = False
        session.end_time = datetime.utcnow()
        session.status = "stopped"
        db.commit()
    
    return {
        "message": "Analysis stopped",
        "system_id": system_id
    }


@router.get("/status/{system_id}", response_model=AnalysisStatus)
async def get_analysis_status(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Get current analysis status for a system
    """
    session = db.query(AnalysisSession).filter(
        AnalysisSession.system_id == system_id,
        AnalysisSession.is_running == True
    ).first()
    
    if not session:
        return AnalysisStatus(
            is_running=False,
            total_logs_analyzed=0,
            threats_detected=0
        )
    
    return AnalysisStatus(
        is_running=True,
        start_time=session.start_time,
        total_logs_analyzed=session.total_logs_analyzed,
        threats_detected=session.threats_detected
    )


@router.get("/threats/{system_id}", response_model=ThreatData)
async def get_threat_data(
    system_id: int,
    hours: int = 168,
    db: Session = Depends(get_db)
):
    """
    Get comprehensive threat data for visualization
    """
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    # Calculate time range
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    
    # Get total requests (log entries)
    total_requests = db.query(LogEntry).filter(
        LogEntry.system_id == system_id,
        LogEntry.timestamp >= time_threshold
    ).count()
    
    # Get threats detected
    threats_detected = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.timestamp >= time_threshold
    ).count()
    
    # Get severity breakdown
    high_severity = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.severity == "High",
        Alert.timestamp >= time_threshold
    ).count()
    
    medium_severity = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.severity == "Medium",
        Alert.timestamp >= time_threshold
    ).count()
    
    low_severity = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.severity == "Low",
        Alert.timestamp >= time_threshold
    ).count()
    
    # Get top attack types
    attack_types_raw = db.query(
        Alert.attack_type,
        Alert.severity,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.system_id == system_id,
        Alert.timestamp >= time_threshold
    ).group_by(Alert.attack_type, Alert.severity).order_by(desc('count')).limit(5).all()
    
    top_attack_types = [
        AttackType(name=at.attack_type, count=at.count, severity=at.severity)
        for at in attack_types_raw
    ]
    
    # Get time series data (5-minute buckets for last 30 minutes - better for demo)
    recent_timestamps = db.query(
    func.date_trunc('minute', LogEntry.timestamp).label('minute'),
    func.count(LogEntry.id).label('log_count')
    ).filter(
        LogEntry.system_id == system_id
    ).group_by('minute').order_by(desc('minute')).limit(20).all()

    time_series_data = []
    for ts_data in reversed(recent_timestamps):  # Oldest to newest for chart
        minute_timestamp = ts_data.minute
        log_count = ts_data.log_count
        
        # Count alerts in that minute
        alert_count = db.query(Alert).filter(
            Alert.system_id == system_id,
            func.date_trunc('minute', Alert.timestamp) == minute_timestamp
        ).count()
        
        time_series_data.append(TimeSeriesPoint(
            timestamp=minute_timestamp.isoformat(),
            request_count=log_count,
            threat_count=alert_count
        ))

    # If no data, provide empty list
    if not time_series_data:
        time_series_data = []

    
    # Get recent alerts
    recent_alerts_raw = db.query(Alert).filter(
        Alert.system_id == system_id
    ).order_by(desc(Alert.timestamp)).limit(10).all()
    
    recent_alerts = [AlertResponse.from_orm(alert) for alert in recent_alerts_raw]

    resolved_threats = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.status == "resolved"
    ).count()

    auto_resolved_threats = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.status == "resolved",
        Alert.resolved_by == "auto-system"
    ).count()


    resolution_time_series = []
    recent_alerts_query = db.query(
        func.date_trunc('minute', Alert.timestamp).label('minute'),
        func.count(Alert.id).label('total_count'),
        func.count(case((Alert.status == 'resolved', 1))).label('resolved_count')
    ).filter(
        Alert.system_id == system_id
    ).group_by('minute').order_by(desc('minute')).limit(20).all()
    
    for data in reversed(recent_alerts_query):
        resolution_time_series.append({
            'timestamp': data.minute.isoformat(),
            'detected_count': data.total_count,
            'resolved_count': data.resolved_count
        })
    
    return ThreatData(
        system_id=system_id,
        system_name=system.local_name,
        total_requests=total_requests,
        threats_detected=threats_detected,
        high_severity_threats=high_severity,
        medium_severity_threats=medium_severity,
        low_severity_threats=low_severity,
        top_attack_types=top_attack_types,
        time_series_data=time_series_data,
        recent_alerts=recent_alerts,
        resolved_threats = resolved_threats,
        auto_resolved_threats=auto_resolved_threats,
        resolution_time_series = resolution_time_series
    )


@router.get("/alerts/{system_id}", response_model=List[AlertResponse])
async def get_realtime_alerts(
    system_id: int,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Get real-time alerts for a system
    """
    alerts = db.query(Alert).filter(
        Alert.system_id == system_id
    ).order_by(desc(Alert.timestamp)).limit(limit).all()
    
    return alerts


@router.put("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """
    Acknowledge an alert
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    alert.status = "acknowledged"
    db.commit()
    
    return {"message": "Alert acknowledged", "alert_id": alert_id}


@router.get("/trends/{system_id}")
async def get_threat_trends(
    system_id: int,
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Get threat trends over time
    """
    time_threshold = datetime.utcnow() - timedelta(hours=hours)
    
    # Hourly threat counts
    trends = []
    for i in range(hours):
        hour_start = datetime.utcnow() - timedelta(hours=hours-i)
        hour_end = hour_start + timedelta(hours=1)
        
        count = db.query(Alert).filter(
            Alert.system_id == system_id,
            Alert.timestamp >= hour_start,
            Alert.timestamp < hour_end
        ).count()
        
        trends.append({
            "timestamp": hour_start.isoformat(),
            "threat_count": count
        })
    
    return trends


# Background analysis function
def run_analysis(system_id: int, session_id: int, db: Session):
    """
    Background task to continuously analyze logs
    """
    log_collector = LogCollector()
    threat_detector = ThreatDetector(db)
    
    # Get system details
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        return
    
    while active_sessions.get(system_id, {}).get("is_running", False):
        try:
            # Collect logs
            logs = log_collector.collect_logs(
                system.ip_address,
                system.ssh_port,
                system.ssh_username,
                system.ssh_password,
                system.log_path
            )
            
            # Analyze logs
            for log_line in logs:
                # Save log entry
                log_entry = LogEntry(
                    system_id=system_id,
                    message=log_line[:500],
                    raw_log=log_line,
                    is_analyzed=False
                )
                db.add(log_entry)
                db.commit()
                db.refresh(log_entry)
                
                # Detect threats
                threat_result = threat_detector.analyze_log(log_entry, system_id)
                
                if threat_result["is_threat"]:
                    # Create alert
                    alert = Alert(
                        system_id=system_id,
                        severity=threat_result["severity"],
                        attack_type=threat_result["attack_type"],
                        source_ip=threat_result.get("source_ip", "unknown"),
                        description=threat_result["description"],
                        confidence_score=threat_result.get("confidence", 0.0),
                        osint_match=threat_result.get("osint_match", False)
                    )
                    db.add(alert)
                    db.commit()
                    db.refresh(alert)  # Important: get the alert ID
                    
                    # 🔥 AUTO-LOG HIGH SEVERITY THREATS
                    if threat_result["severity"] == "High":
                        try:
                            from app.services.remote_logger import RemoteLogger
                            
                            print(f"🚨 HIGH SEVERITY ALERT {alert.id} - Auto-logging to remote system...")
                            
                            # Prepare threat data
                            threat_data = {
                                'alert_id': alert.id,
                                'severity': alert.severity,
                                'attack_type': alert.attack_type,
                                'source_ip': alert.source_ip,
                                'confidence': alert.confidence_score,
                                'timestamp': alert.timestamp
                            }
                            
                            # Log to remote system
                            remote_logger = RemoteLogger()
                            success = remote_logger.log_high_severity_threat(
                                system.ip_address,
                                system.ssh_port,
                                system.ssh_username,
                                system.ssh_password,
                                threat_data
                            )
                            
                            if success:
                                # Mark as resolved automatically
                                alert.logged_to_system = True
                                alert.status = "resolved"
                                alert.resolved_at = datetime.utcnow()
                                alert.resolved_by = "auto-system"
                                db.commit()
                                
                                print(f"✅ Alert {alert.id} AUTO-LOGGED & RESOLVED: {alert.source_ip}")
                            else:
                                print(f"❌ Failed to log alert {alert.id} to remote system")
                        
                        except Exception as e:
                            print(f"❌ Error in auto-logging: {str(e)}")
                    
                    # Update session stats
                    session = db.query(AnalysisSession).filter(
                        AnalysisSession.id == session_id
                    ).first()

                    if session:
                        session.threats_detected += 1
                        db.commit()
                
                # Mark log as analyzed
                log_entry.is_analyzed = True
                log_entry.is_threat = threat_result["is_threat"]
                log_entry.threat_score = threat_result.get("confidence", 0.0)
                db.commit()
                
                # Update session stats
                session = db.query(AnalysisSession).filter(
                    AnalysisSession.id == session_id
                ).first()
                if session:
                    session.total_logs_analyzed += 1
                    db.commit()
            
            # Update last analyzed time
            system.last_analyzed = datetime.utcnow()
            db.commit()
            
            # Wait before next collection
            import time
            time.sleep(10)  # Collect every 10 seconds during demo
            
        except Exception as e:
            print(f"Error in analysis loop: {str(e)}")
            import time
            time.sleep(5)

    
@router.post("/resolve-alert/{alert_id}")
async def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """
    Mark an alert as resolved
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    alert.status = "resolved"
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = "manual"
    
    db.commit()
    
    return {"message": "Alert resolved successfully", "alert_id": alert_id}


@router.post("/log-to-system/{alert_id}")
async def log_alert_to_system(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """
    Log high severity alert to remote system
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    if alert.severity != "High":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only high severity alerts can be logged to system"
        )
    
    # Get system details
    system = db.query(MonitoredSystem).filter(
        MonitoredSystem.id == alert.system_id
    ).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System not found"
        )
    
    # Log to remote system
    from app.services.threat_detector import ThreatDetector
    detector = ThreatDetector(db)
    
    success = detector.log_threat_to_remote_system(
        alert_id,
        system.ip_address,
        system.ssh_port,
        system.ssh_username,
        system.ssh_password
    )
    
    if success:
        return {
            "message": "Alert logged to remote system successfully",
            "alert_id": alert_id,
            "logged": True
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to log alert to remote system"
        )
