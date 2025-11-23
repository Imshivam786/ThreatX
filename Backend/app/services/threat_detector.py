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
        
        # IMPROVED: Comprehensive attack patterns with proper HIGH severity detection
        self.attack_patterns = {
            # ========== HIGH SEVERITY ==========
            'SQL Injection': [
                # Advanced SQL Injection - UNION attacks
                r"union\s+(all\s+)?select",                    # UNION SELECT (case-insensitive)
                r"union.*select.*from",                        # UNION with FROM
                
                # Database enumeration
                r"information_schema",                         # Schema access
                r"sysobjects",                                # MSSQL system objects
                r"syscolumns",                                # MSSQL columns
                
                # Time-based blind SQL injection
                r"sleep\s*\(",                                # MySQL SLEEP
                r"waitfor\s+delay",                           # MSSQL WAITFOR
                r"benchmark\s*\(",                            # MySQL BENCHMARK
                r"pg_sleep",                                  # PostgreSQL sleep
                
                # Boolean-based blind
                r"and\s+1\s*=\s*1\s+union",                  # Advanced UNION
                r"extractvalue\s*\(",                         # XML extraction
                r"updatexml\s*\(",                            # XML update
                
                # Data exfiltration
                r"load_file\s*\(",                            # File reading
                r"into\s+outfile",                            # File writing
                
                # Stacked queries
                r";\s*drop\s+table",                          # DROP TABLE
                r";\s*exec",                                  # Execute command
            ],
            
            'Command Injection': [
                # Critical file access
                r"/etc/shadow",                               # Shadow file (passwords)
                r"/etc/passwd",                               # User accounts
                r"cat\s+/etc/(shadow|passwd)",               # Reading sensitive files
                r"type\s+.*\\system32",                       # Windows system files
                
                # Remote shells
                r"nc\s+-e",                                   # Netcat reverse shell
                r"bash\s+-i",                                 # Interactive bash
                r"/bin/bash\s+-i",                           # Full path bash
                r"/bin/sh\s+-i",                             # Interactive sh
                r"bash\s+-c",                                # Bash command execution
                
                # Downloaders (malware)
                r"wget\s+http",                              # Download via wget
                r"curl.*http.*-o",                           # Curl download
                r"curl.*http.*>",                            # Curl redirect
                
                # Script execution
                r"python\s+-c",                              # Python one-liner
                r"perl\s+-e",                                # Perl one-liner
                r"ruby\s+-e",                                # Ruby one-liner
                r"php\s+-r",                                 # PHP execution
                
                # Destructive commands
                r"rm\s+-rf",                                 # Remove files
                r"dd\s+if=",                                 # Disk operations
                r"mkfs",                                     # Format filesystem
                r"chmod\s+777",                              # Permission changes
                
                # Command chaining
                r";\s*(cat|ls|whoami|id|pwd)",              # Semicolon chaining
                r"\|\s*(cat|ls|whoami|id|pwd)",             # Pipe chaining
                r"&&\s*(cat|ls|whoami|id|pwd)",             # AND chaining
                r"`[^`]+`",                                  # Backtick execution
                r"\$\([^)]+\)",                              # Command substitution
            ],
            
            'Remote Code Execution': [
                r"eval\s*\(",                                # Eval function
                r"exec\s*\(",                                # Exec function
                r"system\s*\(",                              # System function
                r"shell_exec\s*\(",                          # PHP shell_exec
                r"passthru\s*\(",                            # PHP passthru
                r"popen\s*\(",                               # Process open
                r"proc_open\s*\(",                           # Process open
                r"assert\s*\(",                              # PHP assert
            ],
            
            # ========== MEDIUM SEVERITY ==========
            'XSS': [
                r"<script[^>]*>",                            # Script tags
                r"</script>",                                # Closing script
                r"javascript:",                               # JavaScript protocol
                r"onerror\s*=",                              # Error handler
                r"onload\s*=",                               # Load handler
                r"onclick\s*=",                              # Click handler
                r"onmouseover\s*=",                          # Mouse handler
                r"<iframe",                                  # Iframe injection
                r"<svg.*onload",                             # SVG with event
                r"document\.cookie",                         # Cookie theft
                r"document\.write",                          # DOM write
                r"window\.location",                         # Redirection
                r"eval\s*\(.*atob",                         # Encoded eval
            ],
            
            'Directory Traversal': [
                r"\.\./\.\./",                               # Path traversal
                r"\.\.\\\.\.\\",                             # Windows traversal
                r"%2e%2e%2f",                                # URL encoded ../ 
                r"%252e%252e%252f",                          # Double encoded
                r"\.\.;",                                    # IIS traversal
                r"\.\.%2f",                                  # Mixed encoding
                r"\.\.%5c",                                  # Windows encoded
            ],
            
            'LDAP Injection': [
                r"\*\)\(uid=\*",                             # LDAP wildcard
                r"\)\(|\(",                                  # LDAP operators
                r"uid=.*\)",                                 # UID injection
            ],
            
            # ========== LOW SEVERITY ==========
            'SQL Injection (Basic)': [
                r"'\s*or\s*'.*'=",                           # ' OR '1'='1
                r"'\s*or\s*1\s*=\s*1",                       # ' OR 1=1
                r"admin'\s*--",                              # Comment bypass
                r"'\s*and\s*1\s*=\s*1",                      # ' AND 1=1
                r"'\s*or\s*'1",                              # ' OR '1
            ],
            
            'Brute Force': [
                r"failed\s+password",                        # Failed login
                r"authentication\s+failure",                 # Auth failure
                r"invalid\s+user",                           # Invalid user
                r"failed\s+login",                           # Failed login
                r"access\s+denied",                          # Access denied
            ],
            
            'Port Scan': [
                r"syn.*syn.*syn",                            # SYN flood
                r"nmap",                                     # Nmap scan
                r"port\s+scan",                              # Port scan
                r"connection\s+attempt.*refused",            # Connection refused
            ],
            
            'File Inclusion': [
                r"(include|require)(_once)?\s*\(?.*\.(php|asp|jsp)",  # PHP inclusion
                r"(file|path)=.*\.(php|asp|jsp|txt|log)",            # File parameter
            ],
            
            'Suspicious Activity': [
                r"/admin",                                   # Admin access
                r"/phpmyadmin",                              # PhpMyAdmin
                r"\.env",                                    # Environment files
                r"\.git",                                    # Git repository
                r"wp-config",                                # WordPress config
                r"backup\.(zip|sql|tar|gz)",                # Backup files
                r"\.bak$",                                   # Backup extension
                r"database\.sql",                            # Database dump
            ],
        }
        
        # Define severity levels for each attack type
        self.attack_severity_map = {
            'SQL Injection': 'High',
            'Command Injection': 'High',
            'Remote Code Execution': 'High',
            'XSS': 'Medium',
            'Directory Traversal': 'Medium',
            'LDAP Injection': 'Medium',
            'SQL Injection (Basic)': 'Low',
            'Brute Force': 'Low',
            'Port Scan': 'Low',
            'File Inclusion': 'Medium',
            'Suspicious Activity': 'Low',
        }
    
    def analyze_log(self, log_entry: LogEntry, system_id: int) -> Dict:
        """
        Analyze a log entry for threats using multiple detection methods
        """
        log_text = log_entry.raw_log
        
        # 🔥 DECODE URL-ENCODED CHARACTERS
        # Apache logs URLs with %20, %27, etc.
        # Decode them so patterns can match properly
        try:
            log_text_decoded = unquote(log_text)
        except:
            log_text_decoded = log_text  # If decode fails, use original
        
        # DEBUG: Print both versions
        if log_text != log_text_decoded:
            print(f"📝 Original: {log_text[:80]}")
            print(f"📝 Decoded:  {log_text_decoded[:80]}")
        
        # 1. Rule-based detection (use DECODED text)
        rule_result = self._rule_based_detection(log_text_decoded)
        
        # 2. Extract IP (use original text - IPs don't need decoding)
        ip_address = self._extract_ip(log_text)
        osint_match = False
        
        if ip_address:
            osint_match = self.osint_collector.check_ip_in_osint(ip_address, self.db)
        
        # 3. ML-based detection (use decoded text)
        ml_result = self.ml_model.predict_threat(log_text_decoded)
        
        # Combine results
        is_threat = rule_result['is_threat'] or osint_match or ml_result['is_threat']
        
        # Determine severity (FIXED: Pattern-based takes priority!)
        severity = self._calculate_severity(rule_result, osint_match, ml_result)
        
        # Determine attack type
        attack_type = rule_result.get('attack_type') or ml_result.get('attack_type', 'Unknown')
        
        # Calculate confidence (pattern-based gets highest confidence)
        if rule_result.get('is_threat'):
            confidence = 0.95  # Pattern matches are highly reliable
        elif osint_match:
            confidence = 1.0   # OSINT matches are definitive
        else:
            confidence = ml_result.get('confidence', 0.0)
        
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
        # 🔥 ADD DEBUG
        print(f"🔍 Analyzing: {log_text[:100]}")
        
        # Check patterns in order (HIGH → MEDIUM → LOW)
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, log_text, re.IGNORECASE)
                if match:
                    print(f"✅ MATCH FOUND: {attack_type} - {pattern}")
                    print(f"   Matched text: {match.group(0)}")
                    return {
                        'is_threat': True,
                        'attack_type': attack_type,
                        'confidence': 0.95,
                        'pattern_matched': pattern,
                        'matched_text': match.group(0)
                    }
        
        print(f"❌ NO MATCH FOUND")
        
        return {
            'is_threat': False,
            'attack_type': None,
            'confidence': 0.0
        }

    
    def _calculate_severity(
        self,
        rule_result: Dict,
        osint_match: bool,
        ml_result: Dict
    ) -> str:
        """
        Calculate threat severity (FIXED: Pattern-based takes priority!)
        """
        # If pattern matched, use predefined severity
        if rule_result.get('is_threat'):
            attack_type = rule_result.get('attack_type')
            return self.attack_severity_map.get(attack_type, 'Medium')
        
        # OSINT matches are always HIGH
        if osint_match:
            return 'High'
        
        # ML as fallback (less reliable)
        ml_confidence = ml_result.get('confidence', 0.0)
        if ml_confidence > 0.8:
            return 'High'
        elif ml_confidence > 0.5:
            return 'Medium'
        else:
            return 'Low'
    
    # ... (keep all other methods unchanged: _extract_ip, _generate_description, 
    #      _get_detection_method, analyze_batch, detect_brute_force, 
    #      log_threat_to_remote_system)
    
    def _extract_ip(self, log_text: str) -> str:
        """Extract IP address from log entry"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, log_text)
        
        if matches:
            for ip in matches:
                if not ip.startswith(('127.', '10.', '192.168.', '172.')):
                    return ip
            return matches[0]
        
        return None
    
    def _generate_description(
        self,
        attack_type: str,
        ip_address: str,
        osint_match: bool,
        rule_result: Dict,
        ml_result: Dict
    ) -> str:
        """Generate human-readable description of the threat"""
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
        """Determine which detection method identified the threat"""
        methods = []
        
        if rule_result.get('is_threat'):
            methods.append('Rule-based')
        
        if osint_match:
            methods.append('OSINT')
        
        if ml_result.get('is_threat'):
            methods.append('ML')
        
        return ', '.join(methods) if methods else 'None'
    
    def analyze_batch(self, log_entries: List[LogEntry], system_id: int) -> List[Dict]:
        """Analyze multiple log entries in batch"""
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
        """Detect brute force attacks by counting failed login attempts"""
        from datetime import timedelta
        
        time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
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
        """Log high severity threat to remote system"""
        from app.services.remote_logger import RemoteLogger
        from app.models import Alert
        
        alert = self.db.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert or alert.severity != "High":
            return False
        
        threat_data = {
            'alert_id': alert.id,
            'severity': alert.severity,
            'attack_type': alert.attack_type,
            'source_ip': alert.source_ip,
            'confidence': alert.confidence_score,
            'timestamp': alert.timestamp
        }
        
        remote_logger = RemoteLogger()
        success = remote_logger.log_high_severity_threat(
            system_ip,
            system_port,
            system_username,
            system_password,
            threat_data
        )
        
        if success:
            alert.logged_to_system = True
            self.db.commit()
        
        return success
