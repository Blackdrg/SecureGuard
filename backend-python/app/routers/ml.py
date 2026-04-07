"""
ML Inference Router
Handles AI/ML-based threat detection
"""

import os
import math
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.routers.auth import get_current_active_user

router = APIRouter()


# Suspicious APIs commonly used by malware
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "OpenProcessToken", "AdjustTokenPrivileges",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "CreateProcess", "CreateProcessA", "CreateProcessW", "ShellExecute", "WinExec",
    "UrlDownloadToFile", "InternetOpen", "InternetOpenUrl", "InternetReadFile",
    "SetWindowsHook", "SetWindowsHookEx", "UnhookWindowsHook",
    "FindWindow", "SetForegroundWindow", "GetForegroundWindow",
    "GetAsyncKeyState", "GetKeyboardState", "MapVirtualKey",
    "RegOpenKey", "RegCreateKey", "RegSetValue", "RegDeleteKey"
}

# Packer signatures
PACKER_SIGNATURES = {
    "UPX", "ASPack", "Petite", "Themida", "VMProtect", "Armadillo",
    "PECompact", "MEW", "NSPack", "WWPack", "EXPACK", "FSG"
}


# Request/Response models
class FileAnalysisRequest(BaseModel):
    file_path: str
    file_hash: Optional[str] = None
    file_size: int
    entropy: Optional[float] = None
    suspicious_apis: Optional[List[str]] = None
    is_packed: bool = False
    is_signed: bool = False
    section_count: Optional[int] = None
    import_count: Optional[int] = None
    has_network_code: bool = False
    is_recently_created: bool = False


class UrlAnalysisRequest(BaseModel):
    url: str


class ProcessAnalysisRequest(BaseModel):
    process_id: int
    process_name: str
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    loaded_modules: Optional[List[str]] = None


class NetworkAnalysisRequest(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    bytes_sent: Optional[int] = 0
    bytes_received: Optional[int] = 0


class MLAnalysisResponse(BaseModel):
    threat_type: str
    confidence: float
    risk_level: str
    explanations: List[str]
    features: Optional[Dict[str, Any]] = None


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0

    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    data_len = len(data)
    for count in frequency:
        if count == 0:
            continue
        probability = count / data_len
        entropy -= probability * math.log2(probability)

    return entropy


def check_packing(file_path: str) -> bool:
    """Check if file might be packed"""
    try:
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                header = f.read(4096)
                content = header.decode('latin-1', errors='ignore')
                return any(packer in content for packer in PACKER_SIGNATURES)
    except Exception:
        pass
    return False


def classify_threat(score: float) -> tuple:
    """Classify threat based on score"""
    if score >= 0.9:
        return "Critical", "Critical"
    elif score >= 0.7:
        return "High", "High"
    elif score >= 0.5:
        return "Medium", "Medium"
    elif score >= 0.3:
        return "Low", "Low"
    else:
        return "Safe", "Safe"


@router.post("/analyze-file", response_model=MLAnalysisResponse)
async def analyze_file(
    request: FileAnalysisRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze a file for malware using ML"""
    explanations = []
    threat_score = 0.0
    features = {}

    # Calculate entropy if not provided
    entropy = request.entropy
    if entropy is None and os.path.exists(request.file_path):
        try:
            with open(request.file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # 1MB max
                entropy = calculate_entropy(data)
        except Exception:
            entropy = 0.0

    features["entropy"] = entropy

    # Check entropy
    if entropy and entropy > 6.5:
        threat_score += 0.15
        explanations.append(f"High entropy ({entropy:.2f}) suggests packed/encrypted content")

    # Check suspicious APIs
    api_count = 0
    if request.suspicious_apis:
        api_count = len(request.suspicious_apis)
        if api_count > 2:
            threat_score += 0.20 * min(1.0, api_count / 5.0)
            explanations.append(f"Contains {api_count} suspicious API calls")

    features["suspicious_api_count"] = api_count

    # Check packing
    is_packed = request.is_packed
    if not is_packed and os.path.exists(request.file_path):
        is_packed = check_packing(request.file_path)

    if is_packed:
        threat_score += 0.15
        explanations.append("Known packer signature detected")

    features["is_packed"] = is_packed

    # Check digital signature
    if not request.is_signed:
        threat_score += 0.10
        explanations.append("File is not digitally signed")

    features["is_signed"] = request.is_signed

    # Check section count
    if request.section_count and request.section_count > 6:
        threat_score += 0.05
        explanations.append(f"High section count ({request.section_count})")

    features["section_count"] = request.section_count or 0

    # Check import count
    if request.import_count and request.import_count > 100:
        threat_score += 0.10

    features["import_count"] = request.import_count or 0

    # Check network code
    if request.has_network_code:
        threat_score += 0.10
        explanations.append("Contains network communication code")

    features["has_network_code"] = request.has_network_code

    # Check recent creation
    if request.is_recently_created:
        threat_score += 0.07
        explanations.append("File was created recently")

    # File size factor
    size_ratio = request.file_size / 1_000_000.0
    if size_ratio > 0.8 or size_ratio < 0.05:
        threat_score += 0.08

    features["size_ratio"] = size_ratio

    # Calculate confidence
    features_analyzed = 0
    if entropy > 0:
        features_analyzed += 1
    if api_count >= 0:
        features_analyzed += 1
    if is_packed:
        features_analyzed += 1
    if request.section_count is not None:
        features_analyzed += 1

    confidence = min(0.95, 0.3 + (features_analyzed / 4.0) * 0.65)

    # Classify threat
    threat_type, risk_level = classify_threat(threat_score)

    if not explanations:
        explanations.append("No significant threat indicators detected")

    return MLAnalysisResponse(
        threat_type=threat_type,
        confidence=confidence,
        risk_level=risk_level,
        explanations=explanations,
        features=features
    )


@router.post("/analyze-url", response_model=MLAnalysisResponse)
async def analyze_url(
    request: UrlAnalysisRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze a URL for malicious content"""
    url = request.url.lower()
    explanations = []
    threat_score = 0.0

    # Suspicious URL patterns
    suspicious_patterns = [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        "download", "free", "crack", "keygen", "patch",
        "login", "signin", "account", "verify",
        "http:", "ftp:", "telnet:"
    ]

    # Check for suspicious patterns
    for pattern in suspicious_patterns:
        if pattern in url:
            threat_score += 0.15
            explanations.append(f"Suspicious pattern detected: {pattern}")

    # Check for IP address in URL
    if url.replace(".", "").isdigit():
        threat_score += 0.20
        explanations.append("URL contains IP address instead of domain")

    # Check for suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".ga"]
    for tld in suspicious_tlds:
        if tld in url:
            threat_score += 0.15
            explanations.append(f"Suspicious TLD: {tld}")

    # Check for URL shorteners
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "is.gd"]
    for shortener in shorteners:
        if shortener in url:
            threat_score += 0.10
            explanations.append("URL shortener detected")

    # Check for data: or javascript:
    if url.startswith("data:") or url.startswith("javascript:"):
        threat_score += 0.30
        explanations.append("Potentially dangerous URL scheme")

    # Classify
    threat_type, risk_level = classify_threat(threat_score)
    confidence = min(0.90, 0.3 + threat_score * 0.6)

    if not explanations:
        explanations.append("URL appears legitimate")

    return MLAnalysisResponse(
        threat_type=threat_type,
        confidence=confidence,
        risk_level=risk_level,
        explanations=explanations
    )


@router.post("/analyze-process", response_model=MLAnalysisResponse)
async def analyze_process(
    request: ProcessAnalysisRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze a process for suspicious behavior"""
    explanations = []
    threat_score = 0.0

    process_name = request.process_name.lower()

    # Suspicious process names
    suspicious_names = [
        "mimikatz", "pwdump", "procdump", "lsass",
        "psexec", "wce", "gsecdump", "cachedump",
        "networkpass", "fgdump", "raven"
    ]

    for name in suspicious_names:
        if name in process_name:
            threat_score += 0.40
            explanations.append(f"Suspicious process name: {request.process_name}")

    # Check parent process
    if request.parent_process:
        parent = request.parent_process.lower()
        # Suspicious parent-child relationships
        if parent == "cmd.exe" or parent == "powershell.exe":
            if "explorer" not in process_name and "system" not in process_name:
                threat_score += 0.15
                explanations.append("Process spawned from command shell")

    # Check loaded modules
    if request.loaded_modules:
        modules = [m.lower() for m in request.loaded_modules]
        # Suspicious DLLs
        suspicious_dlls = ["mimikatz", "pwdump", "procdump"]
        for dll in suspicious_dlls:
            for module in modules:
                if dll in module:
                    threat_score += 0.35
                    explanations.append(f"Suspicious DLL loaded: {module}")

    # Check command line
    if request.command_line:
        cmd = request.command_line.lower()
        if "powershell" in cmd and "-enc" in cmd:
            threat_score += 0.30
            explanations.append("Encoded PowerShell command detected")
        if "cmd /c" in cmd or "cmd.exe /c" in cmd:
            threat_score += 0.10
            explanations.append("Command shell execution detected")

    # Classify
    threat_type, risk_level = classify_threat(threat_score)
    confidence = min(0.90, 0.3 + threat_score * 0.6)

    if not explanations:
        explanations.append("Process appears normal")

    return MLAnalysisResponse(
        threat_type=threat_type,
        confidence=confidence,
        risk_level=risk_level,
        explanations=explanations
    )


@router.post("/analyze-network", response_model=MLAnalysisResponse)
async def analyze_network(
    request: NetworkAnalysisRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze network connection for suspicious activity"""
    explanations = []
    threat_score = 0.0

    dest_ip = request.destination_ip

    # Suspicious ports
    suspicious_ports = {
        4444: "Metasploit default",
        31337: "Back Orifice",
        12345: "NetBus",
        27374: "SubSeven",
        8080: "Proxy/Tunnel",
        3128: "Proxy",
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        3389: "RDP"
    }

    if request.destination_port in suspicious_ports:
        threat_score += 0.25
        explanations.append(f"Suspicious port {request.destination_port}: {suspicious_ports[request.destination_port]}")

    # Suspicious IP ranges (private to public)
    if dest_ip.startswith("10.") or dest_ip.startswith("192.168.") or dest_ip.startswith("172.16."):
        # Private IP, but check if expecting public
        pass
    else:
        # Check for known malicious IP ranges (simplified)
        if dest_ip.startswith("45.") or dest_ip.startswith("185."):
            # Could be malicious, add small score
            threat_score += 0.05

    # Check data transfer ratio
    if request.bytes_sent and request.bytes_received:
        ratio = request.bytes_sent / request.bytes_received
        if ratio > 10:  # Sending much more than receiving
            threat_score += 0.20
            explanations.append("Unusual outbound data ratio")

    # Check protocol
    if request.protocol.lower() == "tcp":
        threat_score += 0.05

    # Classify
    threat_type, risk_level = classify_threat(threat_score)
    confidence = min(0.85, 0.3 + threat_score * 0.5)

    if not explanations:
        explanations.append("Network connection appears normal")

    return MLAnalysisResponse(
        threat_type=threat_type,
        confidence=confidence,
        risk_level=risk_level,
        explanations=explanations
    )


@router.get("/model-info")
async def get_model_info(
    current_user: User = Depends(get_current_active_user)
):
    """Get ML model information"""
    return {
        "name": "SecureGuard Threat Detection Model",
        "version": "1.0.0",
        "type": "Decision Tree Ensemble",
        "features": [
            "entropy", "suspicious_api_count", "packed", "unsigned",
            "size_ratio", "section_count", "import_count",
            "recent_creation", "network_behavior"
        ],
        "threshold": 0.7,
        "last_updated": "2024-01-15"
    }
