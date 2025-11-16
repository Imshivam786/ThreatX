from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas import SystemCreate, SystemUpdate, SystemResponse
from app.models import MonitoredSystem
from app.services.system_service import SystemService

router = APIRouter()

@router.post("/", response_model=SystemResponse, status_code=status.HTTP_201_CREATED)
async def create_system(
    system: SystemCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new monitored system
    """
    service = SystemService(db)
    
    # Check if system with same IP already exists
    existing = db.query(MonitoredSystem).filter(
                    MonitoredSystem.ip_address == system.ip_address,
                    MonitoredSystem.ssh_port == system.ssh_port
                ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"System with IP {system.ip_address} already exists"
        )
    
    # Test SSH connection before creating
    try:
        print(f"🔍 Testing SSH: {system.ip_address}:{system.ssh_port}")
        connection_test = service.test_ssh_connection(
            system.ip_address,
            system.ssh_port,
            system.ssh_username,
            system.ssh_password
        )
        print(f"📡 SSH Result: {connection_test}")
        
        # Create system even if SSH test fails (for demo purposes)
        if not connection_test["success"]:
            print(f"⚠️ SSH test failed but continuing: {connection_test['message']}")
        
    except Exception as e:
        print(f"❌ SSH test error: {str(e)}")

    # Create the system regardless
    return service.create_system(system)


@router.get("/", response_model=List[SystemResponse])
async def get_all_systems(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Get all monitored systems
    """
    systems = db.query(MonitoredSystem).offset(skip).limit(limit).all()
    return systems


@router.get("/{system_id}", response_model=SystemResponse)
async def get_system(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific system by ID
    """
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    return system


@router.put("/{system_id}", response_model=SystemResponse)
async def update_system(
    system_id: int,
    system_update: SystemUpdate,
    db: Session = Depends(get_db)
):
    """
    Update a system's configuration
    """
    service = SystemService(db)
    
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    return service.update_system(system_id, system_update)


@router.delete("/{system_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_system(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a monitored system and all associated data
    """
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    db.delete(system)
    db.commit()
    
    return None


@router.post("/{system_id}/test")
async def test_connection(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Test SSH connection to a system
    """
    service = SystemService(db)
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    result = service.test_ssh_connection(
        system.ip_address,
        system.ssh_port,
        system.ssh_username,
        system.ssh_password
    )
    
    return result


@router.get("/{system_id}/stats")
async def get_system_stats(
    system_id: int,
    db: Session = Depends(get_db)
):
    """
    Get basic statistics for a system
    """
    from app.models import Alert, LogEntry
    
    system = db.query(MonitoredSystem).filter(MonitoredSystem.id == system_id).first()
    
    if not system:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"System with ID {system_id} not found"
        )
    
    total_alerts = db.query(Alert).filter(Alert.system_id == system_id).count()
    total_logs = db.query(LogEntry).filter(LogEntry.system_id == system_id).count()
    active_alerts = db.query(Alert).filter(
        Alert.system_id == system_id,
        Alert.status == "active"
    ).count()
    
    return {
        "system_id": system_id,
        "system_name": system.local_name,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "total_logs_collected": total_logs,
        "last_analyzed": system.last_analyzed
    }
