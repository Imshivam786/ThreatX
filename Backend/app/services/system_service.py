from sqlalchemy.orm import Session
from typing import Dict, Optional
import paramiko
from datetime import datetime

from app.models import MonitoredSystem
from app.schemas import SystemCreate, SystemUpdate


class SystemService:
    def __init__(self, db: Session):
        self.db = db
    
    def create_system(self, system: SystemCreate) -> MonitoredSystem:
        """
        Create a new monitored system
        """
        db_system = MonitoredSystem(
            local_name=system.local_name,
            ip_address=system.ip_address,
            system_type=system.system_type,
            description=system.description,
            ssh_port=system.ssh_port,
            ssh_username=system.ssh_username,
            ssh_password=system.ssh_password,
            log_path=system.log_path,
            is_active=True,
            date_configured=datetime.utcnow()
        )
        
        self.db.add(db_system)
        self.db.commit()
        self.db.refresh(db_system)
        
        return db_system
    
    def update_system(self, system_id: int, system_update: SystemUpdate) -> MonitoredSystem:
        """
        Update an existing system
        """
        system = self.db.query(MonitoredSystem).filter(
            MonitoredSystem.id == system_id
        ).first()
        
        if not system:
            raise ValueError(f"System with ID {system_id} not found")
        
        # Update only provided fields
        update_data = system_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(system, field, value)
        
        self.db.commit()
        self.db.refresh(system)
        
        return system
    
    def test_ssh_connection(
        self,
        ip_address: str,
        port: int,
        username: str,
        password: str
    ) -> Dict[str, any]:
        """
        Test SSH connection to a remote system
        """
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Attempt connection
            ssh_client.connect(
                hostname=ip_address,
                port=port,
                username=username,
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Test a simple command
            stdin, stdout, stderr = ssh_client.exec_command('echo "Connection test"')
            output = stdout.read().decode('utf-8').strip()
            
            ssh_client.close()
            
            return {
                "success": True,
                "message": "SSH connection successful",
                "test_output": output
            }
            
        except paramiko.AuthenticationException:
            return {
                "success": False,
                "message": "Authentication failed - invalid credentials"
            }
        except paramiko.SSHException as e:
            return {
                "success": False,
                "message": f"SSH error: {str(e)}"
            }
        except TimeoutError:
            return {
                "success": False,
                "message": "Connection timeout - host unreachable"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Connection failed: {str(e)}"
            }
        finally:
            try:
                ssh_client.close()
            except:
                pass
    
    def get_system_info(self, system_id: int) -> Optional[MonitoredSystem]:
        """
        Get system information by ID
        """
        return self.db.query(MonitoredSystem).filter(
            MonitoredSystem.id == system_id
        ).first()
