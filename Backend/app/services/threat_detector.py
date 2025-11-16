import re
from typing import Dict, List
from sqlalchemy.orm import Session
from datetime import datetime

from app.models import LogEntry, OSINTThreat
from app.services.ml_model import MLModel
from app.services.osint_collector import OSINTCollector


class ThreatDetector:
    """
    Analyzes logs and detects cyber threats using ML and rule-based detection
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.ml_model = MLModel()
        self.osint_collector = OSINTCollector()
        
        # Attack patterns for rule-based detection
        self.attack_patterns = {
            'SQL Injection': [
                r"(\bUNION\b.*\bSELECT\b)",
                r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
                r"(;.*DROP\s+TABLE)",
                r"('|\")(\s)*(OR|AND)(\s)*('|\")?\d+('|\")?\s*(=|>|<)",
                r"(EXEC(\s|\+)+(s|x)p\w+)"
            ],
            'XSS': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*="
            ],
            'Command Injection': [
                r";\s*(ls|cat|wget|curl|nc|bash|sh)\s+",
                r"\|\s*(ls|cat|wget|curl|nc|bash|sh)\s+",
                r"&&\s*(ls|cat|wget|curl|nc|bash|sh)\s+",
                r"`.*`"
            ],
            'Brute Force': [
                r"Failed password for",
                r"authentication failure",
                r"Invalid user",
                r"Failed login",
                r"Access denied"
            ],
            'Port Scan': [
                r"SYN.*SYN.*SYN",
                r"nmap",
                r"port scan",
                r"connection attempt.*refused"
            ],
            'Directory Traversal': [
                r"\.\./\.\./",
                r"\.\.\\\.\.\\",
                r"%2e%2e%2f",
                r"%252e%252e%252f"
            ],
            'File Inclusion': [
                r"(include|require)(_once)?\s*\(?.*\.(php|asp|jsp)",
                r"(file|path)=.*\.(php|asp|jsp|txt|log)"
            ]
        }
    
    def analyze_log(self, log_entry: LogEntry, system_id: int) -> Dict:
        """
        Analyze a log entry for threats using multiple detection methods
        """
        log_text = log_entry.raw_log
        
        # 1. Rule-based detection
        rule_result = self._rule_based_detection(log_text)
        
        # 2. Extract IP and check OSINT
        ip_address = self._extract_ip(log_text)
        osint_match = False
        
        if ip_address:
            osint_match = self.osint_collector.check_ip_in_osint(ip_address, self.db)
        
        # 3. ML-based detection
        ml_result = self.ml_model.predict_threat(log_text)
        
        # Combine results
        is_threat = rule_result['is_threat'] or osint_match or ml_result['is_threat']
        
        # Determine severity
        severity = self._calculate_severity(rule_result, osint_match, ml_result)
        
        # Determine attack type
        attack_type = rule_result.get('attack_type') or ml_result.get('attack_type', 'Unknown')
        
        # Calculate confidence
        confidence = max(
            rule_result.get('confidence', 0.0),
            ml_result.get('confidence', 0.0),
            1.0 if osint_match else 0.0
        )
        
        # Generate description
        description = self._generate_description(
            attack_type,
            ip_address,
            osint_match,
            rule_result,
            ml_result
        )
        
        return {
            'is_threat': is_threat,
            'severity': severity,
            'attack_type': attack_type,
            'source_ip': ip_address or 'unknown',
            'description': description,
            'confidence': confidence,
            'osint_match': osint_match,
            'detection_method': self._get_detection_method(rule_result, osint_match, ml_result)
        }
    
    def _rule_based_detection(self, log_text: str) -> Dict:
        """
        Detect threats using predefined patterns
        """
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_text, re.IGNORECASE):
                    return {
                        'is_threat': True,
                        'attack_type': attack_type,
                        'confidence': 0.9,
                        'pattern_matched': pattern
                    }
        
        return {
            'is_threat': False,
            'attack_type': None,
            'confidence': 0.0
        }
    
    def _extract_ip(self, log_text: str) -> str:
        """
        Extract IP address from log entry
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, log_text)
        
        if matches:
            # Filter out local IPs
            for ip in matches:
                if not ip.startswith(('127.', '10.', '192.168.', '172.')):
                    return ip
            # If all are local, return the first one
            return matches[0]
        
        return None
    
    def _calculate_severity(
        self,
        rule_result: Dict,
        osint_match: bool,
        ml_result: Dict
    ) -> str:
        """
        Calculate threat severity based on all detection methods
        """
        # High severity attacks
        high_severity_attacks = ['SQL Injection', 'Command Injection', 'File Inclusion']
        
        if rule_result.get('attack_type') in high_severity_attacks:
            return 'High'
        
        if osint_match:
            return 'High'
        
        if ml_result.get('confidence', 0.0) > 0.8:
            return 'High'
        
        # Medium severity
        medium_severity_attacks = ['XSS', 'Directory Traversal', 'Brute Force']
        
        if rule_result.get('attack_type') in medium_severity_attacks:
            return 'Medium'
        
        if ml_result.get('confidence', 0.0) > 0.5:
            return 'Medium'
        
        # Low severity
        return 'Low'
    
    def _generate_description(
        self,
        attack_type: str,
        ip_address: str,
        osint_match: bool,
        rule_result: Dict,
        ml_result: Dict
    ) -> str:
        """
        Generate human-readable description of the threat
        """
        description_parts = []
        
        if attack_type:
            description_parts.append(f"Detected {attack_type} attack")
        
        if ip_address:
            description_parts.append(f"from IP {ip_address}")
        
        if osint_match:
            description_parts.append("(IP found in threat intelligence feeds)")
        
        if rule_result.get('is_threat'):
            description_parts.append(f"- Pattern-based detection")
        
        if ml_result.get('is_threat'):
            description_parts.append(f"- ML model confidence: {ml_result.get('confidence', 0.0):.2f}")
        
        return ' '.join(description_parts) if description_parts else "Potential threat detected"
    
    def _get_detection_method(
        self,
        rule_result: Dict,
        osint_match: bool,
        ml_result: Dict
    ) -> str:
        """
        Determine which detection method identified the threat
        """
        methods = []
        
        if rule_result.get('is_threat'):
            methods.append('Rule-based')
        
        if osint_match:
            methods.append('OSINT')
        
        if ml_result.get('is_threat'):
            methods.append('ML')
        
        return ', '.join(methods) if methods else 'None'
    
    def analyze_batch(self, log_entries: List[LogEntry], system_id: int) -> List[Dict]:
        """
        Analyze multiple log entries in batch
        """
        results = []
        
        for log_entry in log_entries:
            result = self.analyze_log(log_entry, system_id)
            results.append(result)
        
        return results
    
    def detect_brute_force(
        self,
        system_id: int,
        time_window_minutes: int = 5,
        threshold: int = 5
    ) -> bool:
        """
        Detect brute force attacks by counting failed login attempts
        """
        from datetime import timedelta
        
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        # Count failed authentication attempts
        failed_attempts = self.db.query(LogEntry).filter(
            LogEntry.system_id == system_id,
            LogEntry.timestamp >= time_threshold,
            LogEntry.message.ilike('%failed%password%') | 
            LogEntry.message.ilike('%authentication%failure%') |
            LogEntry.message.ilike('%invalid%user%')
        ).count()
        
        return failed_attempts >= threshold
    
    def log_threat_to_remote_system(
            self,
            alert_id: int,
            system_ip: str,
            system_port: int,
            system_username: str,
            system_password: str
        ) -> bool:
        """
        Log high severity threat to remote system
        """
        from app.services.remote_logger import RemoteLogger
        from app.models import Alert
        
        # Get alert details
        alert = self.db.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert or alert.severity != "High":
            return False
        
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
            system_ip,
            system_port,
            system_username,
            system_password,
            threat_data
        )
        
        if success:
            # Update alert
            alert.logged_to_system = True
            self.db.commit()
        
        return success

