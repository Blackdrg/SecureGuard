import requests
import hashlib
from typing import Optional, Dict

class CloudIntelligence:
    def __init__(self):
        self.api_endpoint = "https://api.threat-intel.example.com"
        self.api_key = "YOUR_API_KEY"
        
    def query_file_reputation(self, file_path: str) -> Optional[Dict]:
        file_hash = self._calculate_hash(file_path)
        if not file_hash:
            return None
        
        try:
            response = requests.post(
                f"{self.api_endpoint}/check",
                json={"hash": file_hash},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=5
            )
            return response.json()
        except:
            return None
    
    def _calculate_hash(self, file_path: str) -> Optional[str]:
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def submit_sample(self, file_path: str, metadata: dict) -> bool:
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                data = {'metadata': str(metadata)}
                response = requests.post(
                    f"{self.api_endpoint}/submit",
                    files=files,
                    data=data,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=30
                )
            return response.status_code == 200
        except:
            return False
    
    def get_threat_intelligence(self, threat_type: str) -> Dict:
        try:
            response = requests.get(
                f"{self.api_endpoint}/intel/{threat_type}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=5
            )
            return response.json()
        except:
            return {}
