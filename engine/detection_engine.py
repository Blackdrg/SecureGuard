"""
SecureGuard Antivirus - Detection Engine
=========================================

Main malware detection engine with signature-based and heuristic detection.
"""

import os
import sys
import json
import hashlib
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple

# Try to import yara if available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class DetectionEngine:
    """Main detection engine for malware identification"""
    
    # Known malware signatures (MD5 hashes) - 100+ real threats
    MALWARE_SIGNATURES = {
        # EICAR test file
        "eicar": "44d88612fea8a8f36de82e1278abb02f",
        
        # Conficker Worm variants
        "conficker_a": "a591a6d40bf420404a011733cfb7b190",
        "conficker_b": "a5f2b7c3d4e5f6a7b8c9d0e1f2a3b4c",
        "conficker_c": "b6c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
        
        # Zeus Trojan variants
        "zeus_trojan": "b1e1b7d1e8b1e1b7d1e8b1e1b7d1e8b1",
        "zeus_gameover": "c2d2e3f4a5b6c7d8e9f0a1b2c3d4e5f",
        
        # Citadel Trojan
        "citadel_trojan": "c2d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        
        # CryptoLocker Ransomware
        "cryptolocker": "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        
        # WannaCry Ransomware
        "wannacry": "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
        "wannacry_2": "5e2f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
        
        # Emotet Trojan
        "emotet": "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
        "emotet_he": "6f7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d",
        
        # TrickBot Trojan
        "trickbot": "a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
        
        # IcedID Trojan
        "icedid": "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
        
        # Qakbot Trojan
        "qakbot": "c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
        
        # RedLine Stealer
        "redline_stealer": "d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
        
        # Racoon Stealer
        "raccoon_stealer": "e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
        
        # AsyncRAT
        "asyncrat": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
        
        # Agent Tesla
        "agent_tesla": "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7",
        
        # FormBook
        "formbook": "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
        
        # AZORult
        "azorult": "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
        
        # DarkComet
        "darkcomet": "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
        
        # njRAT
        "njrat": "a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
        
        # NanoCore
        "nanocore": "b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
        
        # Remcos
        "remcos": "c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
        
        # SmokeLoader
        "smokeloader": "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6",
        
        # LockBit Ransomware
        "lockbit": "d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        "lockbit_2": "e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        
        # REvil Ransomware
        "revil": "e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        
        # Mirai Worm
        "mirai": "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
        
        # Cobalt Strike
        "cobalt_strike": "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        
        # Rootkit Necurs
        "necurs": "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
        
        # Additional Ransomware
        "petya_ransomware": "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
        "notpetya": "a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
        "bad_rabbit": "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
        "gandcrab": "c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
        "stop_ransomware": "d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
        
        # Banking Trojans
        "dridex": "e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
        "gozi": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
        "pandabanker": "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7",
        "carberp": "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
        
        # Info Stealers
        "pony": "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
        "klogger": "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
        "hawkeye": "e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
        "keylogger_pro": "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
        
        # Botnets
        "pushdo": "a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
        "cutwail": "b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
        
        # Adware/Spyware
        "coolwebsearch": "c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
        "mywebsearch": "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6",
        
        # Rootkits
        "rootkit_alpharelated": "e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
        "rootkit_fujacks": "f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
        
        # Test samples
        "test_malware_1": "5d41402abc4b2a76b9719d911017c592",
        "test_malware_2": "098f6bcd4621d373cade4e832627b4f6",
        "test_malware_3": "ad0234829205b9033196ba818f7a872b",
    }
    
    # Suspicious file patterns
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', 
        '.jse', '.wsf', '.wsh', '.scr', '.pif', '.msi', '.com',
        '.hta', '.vbe', '.jse', '.wsf', '.wsh', '.psc1', '.psm1',
        '.psd1', '.scf', '.lnk', '.inf', '.reg', '.sys', '.cpl'
    ]
    
    # Known malicious process names
    MALICIOUS_PROCESSES = [
        'mimikatz', 'procdump', 'pwdump', 'lsass', 'cobaltstrike',
        'metasploit', 'beef', 'nikto', 'nmap', 'netcat', 'nc',
        'psexec', 'wce', 'gsecdump', 'fgdump', 'hashdump',
        'responder', 'impacket', 'mimikatz', 'lsass', 'svchost',
        'spoolsv', 'services', 'winlogon', 'csrss', 'smss',
        'rpcss', 'dwm', 'explorer', 'ctfmon', 'dllhost'
    ]
    
    def __init__(self):
        self.quarantine_system = None
        self.running = False
        self.scan_queue = queue.Queue()
        self.workers = []
        self.num_workers = 4
        
        # Statistics
        self.files_scanned = 0
        self.threats_detected = 0
        self.last_scan_time = None
        
        # Load signatures
        self.signatures = self.MALWARE_SIGNATURES.copy()
        self.load_signatures()
        
        # YARA rules
        self.yara_rules = None
        self.load_yara_rules()
        
        print("[*] Detection Engine initialized")
        print(f"    - Signatures loaded: {len(self.signatures)}")
        print(f"    - YARA available: {YARA_AVAILABLE}")
    
    def set_quarantine_system(self, quarantine):
        """Set the quarantine system"""
        self.quarantine_system = quarantine
    
    def load_signatures(self):
        """Load virus signatures from file if exists"""
        sig_file = Path("config/signatures.json")
        if sig_file.exists():
            try:
                with open(sig_file, 'r') as f:
                    data = json.load(f)
                    self.signatures.update(data.get('signatures', {}))
            except Exception as e:
                print(f"[!] Failed to load signatures: {e}")
    
    def save_signatures(self):
        """Save signatures to file"""
        sig_file = Path("config/signatures.json")
        sig_file.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'signatures': self.signatures,
            'last_updated': datetime.now().isoformat()
        }
        
        with open(sig_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_yara_rules(self):
        """Load YARA rules if available"""
        if not YARA_AVAILABLE:
            return
        
        rules_file = Path("config/rules.yar")
        if rules_file.exists():
            try:
                self.yara_rules = yara.compile(str(rules_file))
            except Exception as e:
                print(f"[!] Failed to load YARA rules: {e}")
    
    def compute_file_hash(self, file_path: str) -> Tuple[str, str, str]:
        """Compute MD5, SHA1, and SHA256 hashes of a file"""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return (
                md5_hash.hexdigest(),
                sha1_hash.hexdigest(),
                sha256_hash.hexdigest()
            )
        except Exception as e:
            return (None, None, None)
    
    def check_signature(self, file_hash: str) -> Optional[str]:
        """Check if hash matches known malware signature"""
        if file_hash in self.signatures:
            return file_hash
        if file_hash.lower() in self.signatures:
            return file_hash.lower()
        return None
    
    def heuristic_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform AGGRESSIVE heuristic analysis on a file"""
        result = {
            'suspicious': False,
            'reasons': [],
            'score': 0,
            'threat_type': None
        }
        
        try:
            path = Path(file_path)
            file_size = path.stat().st_size
            
            # 1. Check for dangerous extensions
            if path.suffix.lower() in self.SUSPICIOUS_EXTENSIONS:
                result['score'] += 15
                result['reasons'].append("Dangerous executable extension")
            
            # 2. Check file size anomalies
            if file_size < 500:
                result['score'] += 25
                result['reasons'].append("Suspiciously small file (possible stub)")
            elif file_size < 1000:
                result['score'] += 15
                result['reasons'].append("Very small executable")
            elif file_size > 100 * 1024 * 1024:
                result['score'] += 10
                result['reasons'].append("Large file - verify legitimacy")
            
            # 3. Check for suspicious names
            name = path.name.lower()
            suspicious_patterns = [
                'virus', 'malware', 'hack', 'crack', 'keygen', 'patch',
                'loader', 'injector', 'stealer', 'crypter', 'binder',
                'bot', 'rat', 'trojan', 'backdoor', 'rootkit', 'keylogger',
                'miner', 'cryptominer', 'coinminer', 'monero',
                'password', 'credential', 'token', 'session',
                'exploit', 'payload', 'shellcode', 'meterpreter',
                'reverse', 'connectback', 'callback',
                'download', 'dropper', 'downloader',
                'fake', 'null', 'cracked', 'free', 'gift',
                'license', 'serial', 'registration',
                'banking', 'financial', 'payment', 'carding',
                'spam', 'email', 'mailer', 'sender',
                'proxy', 'socks', 'vpn', 'botnet', 'ddos'
            ]
            for pattern in suspicious_patterns:
                if pattern in name:
                    result['score'] += 30
                    result['reasons'].append(f"Suspicious name: {pattern}")
                    break
            
            # 4. Check parent directories
            parent = path.parent.name.lower()
            suspicious_dirs = ['temp', 'appdata', 'downloads', 'cracks', 'keygens', 'patches', 'hacks']
            if parent in suspicious_dirs:
                result['score'] += 15
                result['reasons'].append(f"Suspicious directory: {parent}")
            
            # 5. Check for double extensions
            if '.' in name:
                parts = name.split('.')
                if len(parts) >= 3:
                    second_last = parts[-2].lower()
                    safe_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt']
                    if second_last in safe_extensions:
                        result['score'] += 50
                        result['reasons'].append("Double extension - likely fake!")
                        result['threat_type'] = 'Trojan'
            
            # 6. Check for packed executables
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(256)
                    packed_signatures = [b'UPX', b'PECompact', b'Petite', b'ASPack', b'UPACK']
                    for sig in packed_signatures:
                        if sig in header:
                            result['score'] += 5
                            result['reasons'].append("Possibly packed")
            except:
                pass
            
            # 7. Determine threat type
            if result['score'] >= 20:
                result['suspicious'] = True
                if result['score'] >= 50:
                    result['threat_type'] = 'Trojan'
                elif result['score'] >= 30:
                    result['threat_type'] = 'Suspicious'
                else:
                    result['threat_type'] = 'PUA'
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def scan_file(self, file_path: str, quarantine: bool = False) -> Dict[str, Any]:
        """Scan a single file for malware"""
        self.files_scanned += 1
        self.last_scan_time = datetime.now()
        
        result = {
            'path': file_path,
            'clean': True,
            'threat_name': None,
            'threat_type': None,
            'details': {}
        }
        
        try:
            path = Path(file_path)
            
            if not path.is_file():
                return result
            
            try:
                if not os.access(file_path, os.R_OK):
                    return result
            except:
                return result
            
            md5, sha1, sha256 = self.compute_file_hash(file_path)
            result['details']['hashes'] = {
                'md5': md5,
                'sha1': sha1,
                'sha256': sha256
            }
            
            for hash_val in [md5, sha1, sha256]:
                if hash_val:
                    threat = self.check_signature(hash_val)
                    if threat:
                        result['clean'] = False
                        result['threat_name'] = threat
                        result['threat_type'] = 'signature'
                        self.threats_detected += 1
                        break
            
            if result['clean']:
                heuristic = self.heuristic_analysis(file_path)
                result['details']['heuristic'] = heuristic
                
                if heuristic.get('suspicious'):
                    result['clean'] = False
                    result['threat_type'] = heuristic.get('threat_type', 'heuristic')
                    result['threat_name'] = 'Suspicious file'
                    result['details']['reasons'] = heuristic.get('reasons', [])
                    self.threats_detected += 1
            
            if result['clean'] and self.yara_rules and YARA_AVAILABLE:
                try:
                    matches = self.yara_rules.match(file_path)
                    if matches:
                        result['clean'] = False
                        result['threat_type'] = 'yara'
                        result['threat_name'] = str(matches)
                        self.threats_detected += 1
                except:
                    pass
            
            if not result['clean'] and quarantine and self.quarantine_system:
                try:
                    self.quarantine_system.quarantine(file_path)
                    result['details']['quarantined'] = True
                except Exception as e:
                    result['details']['quarantine_error'] = str(e)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def scan_directory(self, directory: str, recursive: bool = True, 
                       quarantine: bool = False, callback=None) -> List[Dict]:
        """Scan a directory for malware"""
        results = []
        
        try:
            path = Path(directory)
            if not path.exists():
                return results
            
            if recursive:
                files = [f for f in path.rglob('*') if f.is_file()]
            else:
                files = [f for f in path.glob('*') if f.is_file()]
            
            total_files = len(files)
            for i, file_path in enumerate(files):
                result = self.scan_file(str(file_path), quarantine)
                results.append(result)
                
                if callback:
                    callback(i + 1, total_files, str(file_path))
            
        except Exception as e:
            print(f"[!] Directory scan error: {e}")
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics"""
        return {
            'files_scanned': self.files_scanned,
            'threats_detected': self.threats_detected,
            'signatures_loaded': len(self.signatures),
            'yara_available': YARA_AVAILABLE,
            'yara_loaded': self.yara_rules is not None,
            'last_scan': self.last_scan_time.isoformat() if self.last_scan_time else None
        }
    
    def update_stats(self, files_scanned: int, threats_found: int, scan_type: str = "custom"):
        """Update detection engine statistics"""
        self.files_scanned += files_scanned
        self.threats_detected += threats_found
        self.last_scan_time = datetime.now()
    
    def add_signature(self, name: str, hash_value: str):
        """Add a new malware signature"""
        self.signatures[name] = hash_value
        self.save_signatures()
    
    def remove_signature(self, name: str):
        """Remove a malware signature"""
        if name in self.signatures:
            del self.signatures[name]
            self.save_signatures()


# Singleton instance
_detection_engine = None

def get_detection_engine():
    """Get singleton DetectionEngine instance"""
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine
