import requests
from config import Config
from typing import List, Dict, Optional
import time

class VirusTotalFetcher:
    def __init__(self):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _make_request(self, url: str) -> Optional[Dict]:
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return None
        finally:
            time.sleep(0.5)

    def get_related_domains(self, ip: str) -> List[str]:
        url = f"{self.base_url}/ip_addresses/{ip}/resolutions"
        data = self._make_request(url)
        if not data:
            return []
        domains = []
        for item in data.get("data", []):
            if domain := item["attributes"].get("host_name"):
                domains.append(domain)
        return domains[:Config.MAX_DOMAINS]

    def get_domain_info(self, domain: str) -> Optional[Dict]:
        url = f"{self.base_url}/domains/{domain}"
        return self._make_request(url)
