import hashlib
import hmac
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class IntegrityVerifier:
    def __init__(self):
        self.manifest = self._load_manifest()
        self.public_key = self._load_public_key()
        
    def _load_manifest(self) -> dict:
        manifest_path = Path("config/integrity.json")
        if manifest_path.exists():
            return json.loads(manifest_path.read_text())
        return {}
    
    def _load_public_key(self):
        key_path = Path("config/public_key.pem")
        if key_path.exists():
            return load_pem_public_key(key_path.read_bytes())
        return None
    
    def verify_file(self, file_path: str) -> bool:
        """Verify file hasn't been tampered"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            expected_hash = self.manifest.get(file_path)
            return file_hash == expected_hash
        except:
            return False
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify digital signature"""
        if not self.public_key:
            return False
        
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def verify_update(self, update_file: str, signature_file: str) -> bool:
        """Verify update package signature"""
        try:
            update_data = Path(update_file).read_bytes()
            signature = Path(signature_file).read_bytes()
            return self.verify_signature(update_data, signature)
        except:
            return False
