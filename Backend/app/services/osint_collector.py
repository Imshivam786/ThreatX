import requests
from typing import List, Dict
from datetime import datetime
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import OSINTThreat
from app.config import settings


class OSINTCollector:
    """
    Collects threat intelligence from various OSINT sources
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OSINT-Threat-Detection/1.0'
        })
    
    def collect_all_feeds(self):
        """
        Collect from all available OSINT sources
        """
        print("🔍 Starting OSINT data collection...")
        
        db = SessionLocal()
        
        try:
            # Collect from multiple sources
            self.collect_abuse_ch_feodotracker(db)
            self.collect_abuse_ch_urlhaus(db)
            self.collect_abuse_ch_malware_bazaar(db)
            self.collect_threatfox(db)
            
            # If API keys are available, collect from premium sources
            if settings.ALIENVAULT_OTX_API_KEY:
                self.collect_alienvault_otx(db)
            
            print("✅ OSINT data collection completed")
            
        except Exception as e:
            print(f"❌ Error in OSINT collection: {str(e)}")
        finally:
            db.close()
    
    def collect_abuse_ch_feodotracker(self, db: Session):
        """
        Collect botnet C&C servers from Abuse.ch Feodo Tracker
        """
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data[:100]:  # Limit to 100 entries
                    # Check if already exists
                    existing = db.query(OSINTThreat).filter(
                        OSINTThreat.indicator_type == "IP",
                        OSINTThreat.indicator_value == entry.get('ip_address')
                    ).first()
                    
                    if not existing:
                        threat = OSINTThreat(
                            indicator_type="IP",
                            indicator_value=entry.get('ip_address'),
                            threat_type=f"Botnet C&C - {entry.get('malware', 'Unknown')}",
                            source="Abuse.ch Feodo Tracker",
                            description=f"Botnet C&C server hosting {entry.get('malware', 'malware')}",
                            severity="High",
                            is_active=True
                        )
                        db.add(threat)
                
                db.commit()
                print("✓ Collected Abuse.ch Feodo Tracker data")
                
        except Exception as e:
            print(f"✗ Error collecting Feodo Tracker: {str(e)}")
    
    def collect_abuse_ch_urlhaus(self, db: Session):
        """
        Collect malicious URLs from Abuse.ch URLhaus
        """
        try:
            url = "https://urlhaus.abuse.ch/downloads/json_recent/"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                urls = data.get('urls', [])
                
                for entry in urls[:50]:  # Limit to 50 entries
                    url_value = entry.get('url')
                    
                    # Check if already exists
                    existing = db.query(OSINTThreat).filter(
                        OSINTThreat.indicator_type == "URL",
                        OSINTThreat.indicator_value == url_value
                    ).first()
                    
                    if not existing and url_value:
                        threat = OSINTThreat(
                            indicator_type="URL",
                            indicator_value=url_value[:500],
                            threat_type=entry.get('threat', 'Malicious URL'),
                            source="Abuse.ch URLhaus",
                            description=f"Malicious URL serving {entry.get('threat', 'malware')}",
                            severity="Medium",
                            is_active=True
                        )
                        db.add(threat)
                
                db.commit()
                print("✓ Collected Abuse.ch URLhaus data")
                
        except Exception as e:
            print(f"✗ Error collecting URLhaus: {str(e)}")
    
    def collect_abuse_ch_malware_bazaar(self, db: Session):
        """
        Collect malware hashes from Abuse.ch Malware Bazaar
        """
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {'query': 'get_recent', 'selector': '100'}
            
            response = self.session.post(url, data=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('query_status') == 'ok':
                    entries = result.get('data', [])
                    
                    for entry in entries[:50]:
                        sha256 = entry.get('sha256_hash')
                        
                        if sha256:
                            # Check if already exists
                            existing = db.query(OSINTThreat).filter(
                                OSINTThreat.indicator_type == "Hash",
                                OSINTThreat.indicator_value == sha256
                            ).first()
                            
                            if not existing:
                                threat = OSINTThreat(
                                    indicator_type="Hash",
                                    indicator_value=sha256,
                                    threat_type=f"Malware - {entry.get('signature', 'Unknown')}",
                                    source="Abuse.ch Malware Bazaar",
                                    description=f"Malware hash: {entry.get('file_name', 'unknown')}",
                                    severity="High",
                                    is_active=True
                                )
                                db.add(threat)
                    
                    db.commit()
                    print("✓ Collected Abuse.ch Malware Bazaar data")
                    
        except Exception as e:
            print(f"✗ Error collecting Malware Bazaar: {str(e)}")
    
    def collect_threatfox(self, db: Session):
        """
        Collect IOCs from Abuse.ch ThreatFox
        """
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            data = {'query': 'get_iocs', 'days': 1}
            
            response = self.session.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('query_status') == 'ok':
                    iocs = result.get('data', [])
                    
                    for ioc in iocs[:50]:
                        ioc_value = ioc.get('ioc')
                        ioc_type = ioc.get('ioc_type', 'Unknown')
                        
                        # Map IOC types
                        indicator_type = "IP" if ioc_type in ['ip:port', 'ip'] else "Domain" if ioc_type == 'domain' else "Other"
                        
                        if ioc_value:
                            # Check if already exists
                            existing = db.query(OSINTThreat).filter(
                                OSINTThreat.indicator_value == ioc_value
                            ).first()
                            
                            if not existing:
                                threat = OSINTThreat(
                                    indicator_type=indicator_type,
                                    indicator_value=ioc_value[:500],
                                    threat_type=ioc.get('malware', 'Unknown threat'),
                                    source="Abuse.ch ThreatFox",
                                    description=f"IOC: {ioc.get('threat_type', 'malicious activity')}",
                                    severity="High",
                                    is_active=True
                                )
                                db.add(threat)
                    
                    db.commit()
                    print("✓ Collected ThreatFox data")
                    
        except Exception as e:
            print(f"✗ Error collecting ThreatFox: {str(e)}")
    
    def collect_alienvault_otx(self, db: Session):
        """
        Collect from AlienVault OTX (requires API key)
        """
        try:
            if not settings.ALIENVAULT_OTX_API_KEY:
                return
            
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {'X-OTX-API-KEY': settings.ALIENVAULT_OTX_API_KEY}
            
            response = self.session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                
                for pulse in pulses[:20]:
                    indicators = pulse.get('indicators', [])
                    
                    for indicator in indicators[:10]:
                        indicator_value = indicator.get('indicator')
                        indicator_type = indicator.get('type', 'Unknown')
                        
                        if indicator_value:
                            existing = db.query(OSINTThreat).filter(
                                OSINTThreat.indicator_value == indicator_value
                            ).first()
                            
                            if not existing:
                                threat = OSINTThreat(
                                    indicator_type=indicator_type,
                                    indicator_value=indicator_value[:500],
                                    threat_type=pulse.get('name', 'Threat'),
                                    source="AlienVault OTX",
                                    description=pulse.get('description', '')[:500],
                                    severity="Medium",
                                    is_active=True
                                )
                                db.add(threat)
                
                db.commit()
                print("✓ Collected AlienVault OTX data")
                
        except Exception as e:
            print(f"✗ Error collecting AlienVault OTX: {str(e)}")
    
    def check_ip_in_osint(self, ip_address: str, db: Session) -> bool:
        """
        Check if an IP address exists in OSINT threat database
        """
        threat = db.query(OSINTThreat).filter(
            OSINTThreat.indicator_type == "IP",
            OSINTThreat.indicator_value == ip_address,
            OSINTThreat.is_active == True
        ).first()
        
        return threat is not None
