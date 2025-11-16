"""
Service to write threat alerts to remote system logs
"""
import paramiko
from datetime import datetime
from typing import Dict, Optional
from app.utils.logger import logger


class RemoteLogger:
    """
    Writes threat alerts to remote system log files for IP blocking
    """
    
    def __init__(self):
        self.remote_log_path = "/var/log/threat_detection_alerts.log"
    
    def log_high_severity_threat(
        self,
        ip_address: str,
        port: int,
        username: str,
        password: str,
        threat_data: Dict
    ) -> bool:
        """
        Write high severity threat to remote system log
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                hostname=ip_address,
                port=port,
                username=username,
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            
            log_entry = self._format_log_entry(threat_data)
            
            command = f'echo "{log_entry}" >> {self.remote_log_path}'

            stdin, stdout, stderr = client.exec_command(command)
            
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                logger.info(f"✅ Logged to remote: {threat_data['source_ip']} → {self.remote_log_path}")
                self._create_block_suggestion(client, threat_data)
                self._create_alert_file(client, threat_data)
                client.close()
                return True
            else:
                error = stderr.read().decode()
                logger.error(f"❌ Remote logging failed: {error}")
                client.close()
                return False
            
        except Exception as e:
            logger.error(f"❌ Remote logging error: {str(e)}")
            return False
    
    def _format_log_entry(self, threat_data: Dict) -> str:
        """Format threat data as log entry"""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = (
            f"[{timestamp}] THREAT_DETECTION: "
            f"SEVERITY={threat_data['severity']} "
            f"ATTACK_TYPE={threat_data['attack_type']} "
            f"SOURCE_IP={threat_data['source_ip']} "
            f"ALERT_ID={threat_data['alert_id']} "
            f"CONFIDENCE={threat_data['confidence']:.2f} "
            f"ACTION=BLOCK_RECOMMENDED"
        )
        
        return log_entry.replace('"', '\\"')
    
    def _create_block_suggestion(self, client: paramiko.SSHClient, threat_data: Dict):
        """Create iptables block script"""
        try:
            block_script_path = "/tmp/block_threats.sh"
            block_command = f"iptables -A INPUT -s {threat_data['source_ip']} -j DROP"
            command = f'echo "{block_command}" >> {block_script_path}'
            client.exec_command(command)
            client.exec_command(f'chmod +x {block_script_path}')
            logger.info(f"✅ Block script updated: {block_script_path}")
        except Exception as e:
            logger.error(f"⚠️ Could not create block script: {str(e)}")
    
    def _create_alert_file(self, client: paramiko.SSHClient, threat_data: Dict):
        """Create human-readable alert file"""
        try:
            alert_file = f"/tmp/threat_alert_{threat_data['alert_id']}.txt"
            
            alert_content = f"""
            ========================================
            CRITICAL SECURITY ALERT
            ========================================
            Alert ID: {threat_data['alert_id']}
            Timestamp: {threat_data['timestamp']}
            Severity: {threat_data['severity']}
            Attack Type: {threat_data['attack_type']}
            Source IP: {threat_data['source_ip']}
            Confidence: {threat_data['confidence']:.2%}

            ACTION REQUIRED:
            This IP has been identified as a high-severity threat.
            To block this IP, run:
            sudo iptables -A INPUT -s {threat_data['source_ip']} -j DROP
            
            Or execute the automated block script:
            sudo /tmp/block_threats.sh

            ========================================
            """
            
            command = f"cat > {alert_file} << 'EOF'\n{alert_content}\nEOF"
            client.exec_command(command)
            logger.info(f"📄 Alert file created: {alert_file}")
            
        except Exception as e:
            logger.error(f"⚠️ Could not create alert file: {str(e)}")
