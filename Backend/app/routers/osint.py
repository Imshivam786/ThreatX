from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas import OSINTThreatResponse
from app.models import OSINTThreat
from app.services.osint_collector import OSINTCollector

router = APIRouter()
osint_collector = OSINTCollector()


@router.get("/threats", response_model=List[OSINTThreatResponse])
async def get_osint_threats(
    limit: int = 100,
    indicator_type: str = None,
    db: Session = Depends(get_db)
):
    """
    Get OSINT threat intelligence data
    """
    query = db.query(OSINTThreat).filter(OSINTThreat.is_active == True)
    
    if indicator_type:
        query = query.filter(OSINTThreat.indicator_type == indicator_type)
    
    threats = query.order_by(OSINTThreat.last_updated.desc()).limit(limit).all()
    
    return threats


@router.post("/check-ip")
async def check_ip_reputation(
    ip: str,
    db: Session = Depends(get_db)
):
    """
    Check if an IP address is malicious based on OSINT data
    """
    threat = db.query(OSINTThreat).filter(
        OSINTThreat.indicator_type == "IP",
        OSINTThreat.indicator_value == ip,
        OSINTThreat.is_active == True
    ).first()
    
    if threat:
        return {
            "ip": ip,
            "is_malicious": True,
            "threat_type": threat.threat_type,
            "severity": threat.severity,
            "source": threat.source,
            "description": threat.description
        }
    else:
        return {
            "ip": ip,
            "is_malicious": False,
            "message": "IP not found in threat database"
        }


@router.get("/vulnerabilities/{system_id}")
async def get_vulnerabilities(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Get known vulnerabilities for a system based on OSINT
    """
    from app.models import MonitoredSystem
    
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    # Get CVE-related threats
    vulnerabilities = db.query(OSINTThreat).filter(
        OSINTThreat.threat_type.like("%CVE%"),
        OSINTThreat.is_active == True
    ).limit(50).all()
    
    return {
        "system_id": system_id,
        "system_name": system.local_name,
        "vulnerabilities": [
            {
                "cve_id": vuln.indicator_value,
                "description": vuln.description,
                "severity": vuln.severity,
                "source": vuln.source
            }
            for vuln in vulnerabilities
        ]
    }


@router.post("/refresh")
async def refresh_osint_data(
    db: Session = Depends(get_db)
):
    """
    Manually trigger OSINT data collection
    """
    try:
        osint_collector.collect_all_feeds()
        
        # Count threats
        threat_count = db.query(OSINTThreat).filter(OSINTThreat.is_active == True).count()
        
        return {
            "message": "OSINT data refreshed successfully",
            "total_threats": threat_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to refresh OSINT data: {str(e)}"
        )


@router.get("/stats")
async def get_osint_stats(
    db: Session = Depends(get_db)
):
    """
    Get OSINT database statistics
    """
    from sqlalchemy import func
    
    total_threats = db.query(OSINTThreat).filter(OSINTThreat.is_active == True).count()
    
    # Count by type
    by_type = db.query(
        OSINTThreat.indicator_type,
        func.count(OSINTThreat.id).label('count')
    ).filter(OSINTThreat.is_active == True).group_by(OSINTThreat.indicator_type).all()
    
    # Count by severity
    by_severity = db.query(
        OSINTThreat.severity,
        func.count(OSINTThreat.id).label('count')
    ).filter(OSINTThreat.is_active == True).group_by(OSINTThreat.severity).all()
    
    return {
        "total_threats": total_threats,
        "by_type": {item.indicator_type: item.count for item in by_type},
        "by_severity": {item.severity: item.count for item in by_severity}
    }
