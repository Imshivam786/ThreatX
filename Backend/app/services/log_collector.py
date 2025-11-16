import paramiko
from typing import List, Optional
import re
from datetime import datetime
import io


class LogCollector:
    """
    Collects logs from remote systems via SSH
    """
    
    def __init__(self):
        self.ssh_client = None
    
    def collect_logs(
        self,
        ip_address: str,
        port: int,
        username: str,
        password: str,
        log_path: str,
        max_lines: int = 100
    ) -> List[str]:
        """
        Collect logs from a remote system via SSH
        """
        logs = []
        
        try:
            # Connect via SSH
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.ssh_client.connect(
                hostname=ip_address,
                port=port,
                username=username,
                password=password,
                timeout=15,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Collect from multiple log sources
            log_sources = [
                f"{log_path}/auth.log",
                f"{log_path}/syslog",
                f"{log_path}/apache2/access.log",
                f"{log_path}/apache2/error.log",
                f"{log_path}/nginx/access.log",
                f"{log_path}/nginx/error.log"
            ]
            
            for log_file in log_sources:
                try:
                    # Use tail command to get recent logs
                    command = f"tail -n {max_lines // len(log_sources)} {log_file} 2>/dev/null"
                    stdin, stdout, stderr = self.ssh_client.exec_command(command)
                    
                    file_logs = stdout.read().decode('utf-8', errors='ignore').strip().split('\n')
                    logs.extend([log for log in file_logs if log.strip()])
                    
                except Exception as e:
                    # Log file might not exist, continue to next
                    print(f"Could not read {log_file}: {str(e)}")
                    continue
            
            self.ssh_client.close()
            
            return logs[:max_lines]  # Limit total logs
            
        except Exception as e:
            print(f"Error collecting logs: {str(e)}")
            if self.ssh_client:
                try:
                    self.ssh_client.close()
                except:
                    pass
            return []
    
    def collect_specific_log(
        self,
        ip_address: str,
        port: int,
        username: str,
        password: str,
        log_file_path: str,
        lines: int = 100
    ) -> List[str]:
        """
        Collect logs from a specific log file
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh_client.connect(
                hostname=ip_address,
                port=port,
                username=username,
                password=password,
                timeout=15
            )
            
            command = f"tail -n {lines} {log_file_path}"
            stdin, stdout, stderr = ssh_client.exec_command(command)
            
            logs = stdout.read().decode('utf-8', errors='ignore').strip().split('\n')
            
            ssh_client.close()
            
            return [log for log in logs if log.strip()]
            
        except Exception as e:
            print(f"Error collecting specific log: {str(e)}")
            return []
    
    def parse_log_entry(self, log_line: str) -> dict:
        """
        Parse a log entry and extract relevant information
        """
        result = {
            "timestamp": None,
            "level": None,
            "source": None,
            "message": log_line,
            "ip_address": None
        }
        
        # Extract timestamp (common formats)
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',  # 2024-01-01 12:00:00
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',   # Jan 01 12:00:00
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, log_line)
            if match:
                result["timestamp"] = match.group(1)
                break
        
        # Extract log level
        level_patterns = [
            r'\b(ERROR|WARN|INFO|DEBUG|CRITICAL|FATAL)\b',
            r'\[(\w+)\]'
        ]
        
        for pattern in level_patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                result["level"] = match.group(1).upper()
                break
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, log_line)
        if ip_matches:
            result["ip_address"] = ip_matches[0]
        
        # Detect log source
        if 'auth' in log_line.lower() or 'login' in log_line.lower():
            result["source"] = "auth"
        elif 'apache' in log_line.lower() or 'httpd' in log_line.lower():
            result["source"] = "apache"
        elif 'nginx' in log_line.lower():
            result["source"] = "nginx"
        elif 'ssh' in log_line.lower():
            result["source"] = "ssh"
        else:
            result["source"] = "system"
        
        return result
    
    def filter_relevant_logs(self, logs: List[str]) -> List[str]:
        """
        Filter logs to keep only security-relevant entries
        """
        security_keywords = [
            'failed', 'error', 'denied', 'unauthorized', 'invalid',
            'attack', 'breach', 'intrusion', 'malicious', 'suspicious',
            'authentication', 'login', 'password', 'access', 'permission',
            'refused', 'blocked', 'violation', 'alert', 'warning'
        ]
        
        relevant_logs = []
        
        for log in logs:
            log_lower = log.lower()
            if any(keyword in log_lower for keyword in security_keywords):
                relevant_logs.append(log)
        
        return relevant_logs
