import re
from typing import Dict, Optional

class DomainAnalyzer:
    C2_PATTERNS = [
        "panel", "c2", "rat", "stealer", "command", 
        "control", "beacon", "payload", "botnet",
        "admin", "server", "cnc", "backdoor"
    ]
    
    MALICIOUS_THRESHOLD = 5
    SUSPICIOUS_THRESHOLD = 10
    
    @classmethod
    def is_c2_domain(cls, domain_info: Dict) -> bool:
        if not domain_info or "data" not in domain_info:
            return False
            
        attributes = domain_info["data"].get("attributes", {})
        tags = attributes.get("tags", [])
        stats = attributes.get("last_analysis_stats", {})
        domain = domain_info["data"].get("id", "")
    
        if any(re.search(p, domain.lower()) for p in cls.C2_PATTERNS):
            return True
            
        if stats.get("malicious", 0) >= cls.MALICIOUS_THRESHOLD:
            return True
            
        if any("c2" in tag.lower() or "command" in tag.lower() for tag in tags):
            return True
            
        return False
        
    @classmethod
    def get_domain_risk(cls, domain_info: Dict) -> Dict:
        if not domain_info or "data" not in domain_info:
            return {"risk": "unknown", "score": 0}
            
        attributes = domain_info["data"].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        score = malicious * 2 + suspicious
        
        if malicious >= 10 or score >= 20:
            risk = "critical"
        elif malicious >= 5 or score >= 10:
            risk = "high"
        elif malicious >= 2 or score >= 5:
            risk = "medium"
        elif malicious > 0 or suspicious > 0:
            risk = "low"
        else:
            risk = "clean"
            
        return {
            "risk": risk,
            "score": score,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }