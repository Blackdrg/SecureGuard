# SecureGuard Enterprise

SecureGuard is a production-grade, AI-powered cybersecurity platform designed for Windows environments. It provides multi-layered, real-time protection by combining traditional signature-based detection with state-of-the-art heuristic and AI-driven behavioral analysis.

---

## 🚀 Overview

SecureGuard Enterprise transforms standard endpoint security into a distributed, intelligent defense system. It consists of a high-performance C# core engine, a Python-driven AI inference layer, and a modern web-based monitoring dashboard.

---

## 🛠️ Tech Stack

### **Core & Desktop**
- **Language:** C# (.NET 8.0)
- **Framework:** Windows Presentation Foundation (WPF) for the desktop interface.
- **Systems:** Windows Service (Background protection), P/Invoke (Low-level Windows API interaction).
- **Security Logic:** YARA-based signature matching, custom heuristics engine.

### **Backend & AI**
- **Language:** Python 3.10+
- **API Framework:** FastAPI
- **Security Tools:** `yara-python`, `cryptography`, `psutil`.
- **Inference:** custom ML models for malware classification and anomaly detection.
- **Database:** PostgreSQL (Cloud/Centralized threat data).
- **Caching/PubSub:** Redis (Real-time telemetry and task queuing).

### **Web Dashboard**
- **Frontend:** Modern HTML5, Vanilla CSS3 (Dark/Glassmorphism aesthetics), UI-optimized JavaScript.
- **Communication:** WebSockets for real-time threat alerts and system telemetry.
- **Server:** Embedded C# HTTP server for local dashboard access; Nginx for production cloud deployment.

### **Infrastructure**
- **Containerization:** Docker & Docker Compose.
- **Deployment:** WSL 2 integration, MSI/Inno Setup installers.

---

## 🏗️ Architecture

SecureGuard is built on a modular, multi-layered architecture:

### **1. Protection Layers**
- **Real-Time Protection Engine:** Monitors file system I/O, process creations, and registry changes.
- **Behavioral Analysis:** Uses `BehaviorMonitor.cs` to detect ransomware patterns and suspicious process trees.
- **Network Security:** `FirewallManager.cs` and `DnsFilter.cs` provide deep packet inspection and malicious URL blocking.
- **Kernel-Level Interface:** Low-level integration via `KernelDriverInterface.cs` for rootkit detection.

### **2. Intelligence Engine**
- **Heuristic Scanning:** Analyzes file entropy, imported APIs (e.g., `VirtualAlloc`, `WriteProcessMemory`), and packing status.
- **Cloud Intelligence:** Synchronizes local threat data with a centralized AI backend via `CloudSyncService.cs`.
- **YARA Integration:** High-speed scanning using compiled YARA rules for known malware families.

### **3. Operational Persistence**
- **Windows Service:** `SecureGuardService.cs` ensures the engine remains active regardless of user login state.
- **Self-Defense System:** `SelfDefenseSystem.cs` protects the SecureGuard processes, files, and registry keys from being terminated or modified by external threats.
- **Service Watchdog:** `ServiceWatchdog.cs` monitors critical protection modules and automatically restarts them if a failure or crash is detected.
- **Self-Healing Engine:** `SelfHealingEngine.cs` can automatically repair corrupted core components or restore system settings altered by malware.
- **Application Control:** `ApplicationControl.cs` manages white-listing and black-listing of software globally.
- **Device Control:** `DeviceControl.cs` monitors and restricts unauthorized hardware connections (USB, Thunderbolt).
- **Exploit Protection:** `ExploitProtection.cs` provides advanced memory protection against buffer overflows and ROP attacks.

---

## 🛠️ Administrative & Enterprise Features

SecureGuard includes a robust **Admin Panel Enhancement** suite for centralized management:
- **User Management:** Detailed tracking of user accounts, login history, and API usage stats.
- **Device Fleet Monitoring:** Real-time status tracking for all registered endpoints across the network.
- **Threat Analytics:** Visualizations of attack trends, most targeted devices, and identified malware families.
- **ML Model Monitoring:** Performance tracking for on-device and cloud-based AI models.
- **Attack Surface Analysis:** Automated scoring of vulnerable configurations and missing patches.


---

## 🔍 Deep-Dive: Detection Pipeline

SecureGuard utilizes a sequential 4-layer detection strategy to ensure maximum coverage with minimum false positives:

| Layer | Method | Focus Area | Example Detection |
|-------|--------|------------|-------------------|
| **Layer 1** | Signature (YARA) | Known Threats | MD5/SHA256 matches for Emotet, LockBit, etc. |
| **Layer 2** | Heuristics | Static Analysis | High entropy (>7.5), suspicious imports, double extensions. |
| **Layer 3** | Behavioral | Runtime Activity | Suspicious parent processes, rapid file encryption, API hooking. |
| **Layer 4** | Memory | Anomaly Detection | Hidden threads, code injection, reflective DLL loading. |

### **Advanced Behavioral Heuristics**
- **Entropy Analysis:** Detects packed or encrypted payloads by measuring data randomness.
- **Suspicious Lineage:** Flags processes spawned from unexpected parents (e.g., `cmd.exe` spawned by `winword.exe`).
- **Module Inspection:** Scans loaded DLLs for indicators of credential stealers (e.g., `mimikatz` artifacts).
- **Process Tree Mapping:** Maps the entire execution chain to identify "living off the land" (LotL) attacks.

---

## 🛡️ Kernel-Level Protection

For enterprise-grade security, SecureGuard interfaces directly with the Windows Kernel:
- **Process Callbacks:** Uses `PsSetCreateProcessNotifyRoutine` to intercept process creation in real-time.
- **File System Filter:** Implements a mini-filter driver to monitor and block malicious I/O requests before they reach the disk.
- **Registry Protection:** Guards critical HKLM and HKCU keys used for persistence (e.g., Run/RunOnce).
- **Anti-Tamper:** Employs kernel-level watchdogs to prevent malware from killing the `SecureGuard.exe` process.

### **Advanced Registry Integrity Monitoring**
SecureGuard's `RegistryMonitor.cs` provides persistent surveillance of critical Windows configuration keys to prevent unauthorized persistence:
- **Persistence Hooks:** Monitors `Run`, `RunOnce`, and `Winlogon` keys for suspicious injections.
- **Service Monitoring:** Guards the `SYSTEM\CurrentControlSet\Services` hive to prevent malicious service installation.
- **Shell Command Hijacking:** Protects `SOFTWARE\Classes\*\shell\open\command` to ensure legitimate applications are not intercepted.
- **Pattern Matching:** Automatically flags changes containing suspicious keywords like `powershell`, `cmd.exe`, or encoded scripts.

### **Anti-Tamper & Self-Defense (Ring-3)**
Beyond kernel protection, the `SelfDefenseSystem.cs` implements multiple user-mode safeguards:
- **Debugger Detection:** Monitors for unauthorized debuggers attempting to attach to the SecureGuard process.
- **Service Auto-Restart:** If a core component is terminated, the watchdog triggers an immediate restoration.
- **Integrity Validation:** Periodic checksum verification of all engine DLLs and configuration files.

---

## 🌐 Advanced DNS Filtering

The `DnsFilter.cs` module provides an additional layer of network security at the resolution level:
- **Malicious Pattern Engine:** Automatically blocks domains containing high-risk keywords such as `c2`, `botnet`, `stealer`, and `ransomware`.
- **Custom IP Mapping:** Allows administrators to redirect malicious internal traffic to safe "black-hole" or "honey-pot" addresses.
- **High-Performance Resolution:** Asynchronous DNS resolution with a local caching layer to prevent network latency.
- **Privacy-Safe Browsing:** Intercepts and validates every resolution request before it leaves the endpoint.


---

## 🔄 Workflow

1.  **Deployment & Setup:**
    - The system is installed via `Install-SecureGuard.ps1` or a compiled installer.
    - It self-registers as a Windows Service and adds a startup entry for the System Tray Manager.

2.  **Protection Cycle:**
    - **Monitor:** Every file written or executed is intercepted by the `RealTimeProtectionEngine`.
    - **Analyze:** The file is passed through the multi-layer detection pipeline (Signatures -> Heuristics -> AI).
    - **Act:** If a threat is detected, the `QuarantineManager` isolates the file, and the process is killed.

3.  **Remote Monitoring:**
    - Device health (CPU, RAM, security score) is periodically synced to the Web Dashboard.
    - Administrators can trigger remote scans, manage quarantine, and update configurations via the Web UI.

4.  **Updates:**
    - `BackgroundUpdater.cs` periodically checks for new signature databases and engine improvements.

---

## 📂 Project Structure

- `/src/Core`: Core security modules (Protection, Scanning, Firewall, ML Bridge).
- `/src/UI`: Desktop WPF application source.
- `/backend-python`: FastAPI-based cloud infrastructure and ML services.
- `/website`: Source for the cybersecurity dashboard.
- `/Driver`: Kernel-level driver components (C/C++).
- `/ai`: AI/ML model training and inference scripts.
- `/models`: Pre-trained malware detection models (ONNX/Joblib).
- `/browser-extension`: Source for the SecureGuard Web Shield (Chrome/Firefox).
- `/ml-training`: Scripts for training static and behavioral analysis models.
- `/quarantine`: Secure, AES-256 encrypted storage for isolated threats.
- `/logs`: Structured JSON logs for all system activities and detections.

---

## 🌐 SecureGuard Web Shield

The project includes a multi-browser extension that extends system protection to the web layer:
- **Phishing Detection:** Real-time scanning of page contents for known phishing patterns and spoofed domains.
- **Malicious Link Blocking:** Intercepts clicks on URLs that match global threat intelligence databases.
- **Safe Downloads:** Communicates with the desktop engine to scan downloaded files before the user opens them.
- **Privacy Mode:** Blocks intrusive trackers and prevents browser-based fingerprinting.

---

## 🛠️ Low-Level Kernel Architecture

SecureGuard's ring-0 protection is implemented using a custom Windows Driver (WDM/WDF):
- **`SecureGuardDriver.c`**: Core kernel logic, handling `IRP` requests, process notifications (`PsSetCreateProcessNotifyRoutine`), and file system callbacks.
- **`SecureGuardComm.cpp`**: Manages the IOCTL (Input/Output Control) communication channel between the user-mode engine and the kernel-mode driver.
- **`SecureGuardDriver.inf`**: Deployment configuration for driver installation and signature verification.
- **`build_driver.bat`**: Automated build pipeline using the WDK (Windows Driver Kit) to compile and sign driver binaries.

---

## 🧠 AI/ML Training & Inference

SecureGuard's intelligence is powered by two distinct machine learning pipelines:
- **Static Model:** Analyzes the physical structure of files, PE headers, and section entropy without execution.
- **Behavioral Model:** Trained on behavioral logs to identify patterns of process injection, credential dumping, and lateral movement.
- **Model Deployment:** Models are exported to **ONNX format** for high-speed, cross-platform inference with minimal memory overhead.
- **Continuous Learning:** The `ml-training` suite allows for the generation of updated models based on the latest threat samples.

---

## 🧠 Deep-Dive: Machine Learning Architecture

SecureGuard's AI layer is engineered for high-precision malware classification using multiple model architectures and extensive feature engineering.

### **Model Architectures**
1.  **Ensemble Learners:** Primary detection uses **RandomForest** and **LightGBM** (LGBMClassifier) for structured PE feature analysis, optimized for high recall and low false-positive rates.
2.  **Gradient Boosting:** **GradientBoostingClassifier** is used for complex non-linear relationship mapping in behavioral data.
3.  **Neural Networks:** A deep **PyTorch-based MLP** (Multi-Layer Perceptron) architecture with Batch Normalization and Dropout layers (Sizes: 256, 128, 64) is available for advanced anomaly detection.

### **Feature Engineering (40+ Data Points)**
The `FeatureExtractor` transforms raw binaries into a multidimensional vector including:
- **Structural Features:** `file_size`, `number_of_sections`, `section_with_code_ratio`.
- **PE Header Metadata:** `optional_header_size`, `is_dll`, `is_gui`, `is_pe32plus`.
- **Entropy Metrics:** `overall_entropy`, `header_entropy`, `middle_entropy` (Threshold > 7.5 for packing detection).
- **Behavioral Indicators:** `suspicious_api_count`, `has_process_injection`, `has_registry_manipulation`, `has_network_apis`.
- **External Risk:** `location_risk` (e.g., `%TEMP%`, `%APPDATA%`), `is_signed`, `days_since_creation`.

### **Training & Evaluation Pipeline**
- **Production Export:** Automatic conversion to **ONNX** via `skl2onnx` for seamless integration into the C# core engine.

---

## 🧬 Heuristic & Behavioral Indicators

SecureGuard utilizes a massive library of heuristic patterns to identify threats even without an exact signature match.

### **1. Suspicious API Monitoring**
The engine tracks dozens of Windows API calls frequently abused by malware and ransomware:
- **Process Injection:** `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `SetWindowsHookEx`.
- **Privilege Escalation:** `AdjustTokenPrivileges`, `OpenProcessToken`.
- **Evasion & Stealth:** `IsDebuggerPresent`, `LoadLibrary` (Dynamic loading), `GetProcAddress`.
- **Network Activity:** `UrlDownloadToFile`, `InternetOpenUrl`, `socket`.

### **2. Packer & Crypter Detection**
Identifies files that have been obfuscated to hide their true intent:
- **Known Signatures:** `UPX`, `ASPack`, `Themida`, `VMProtect`, `Armadillo`, `PECompact`, `FSG`.
- **Entropy Analysis:** Files with sections exceeding **7.2 entropy** are automatically flagged as potentially packed or encrypted.

### **3. Network Behavioral Analysis**
Monitors for patterns characteristic of C2 (Command & Control) communication:
- **Suspicious Ports:** 4444 (Metasploit), 31337 (Back Orifice), 12345 (NetBus), 3389 (RDP Brute-forcing).
- **Data Exfiltration Patterns:** High outbound-to-inbound transfer ratios (e.g., > 10:1) trigger an immediate investigation.
- **DGA Detection:** Domain Generation Algorithms are identified by analyzing the randomness and TLDs of DNS requests.

### **4. Process & Parent Linkage**
- **Orphan Processes:** Processes that have lost their parent or are spawned by unexpected parents (e.g., `cmd.exe` spawning `lsass.exe`).
- **Encoded Commands:** Detection of Base64 encoded PowerShell scripts or obfuscated batch commands.

---

## 📁 Exhaustive File Structure (Core)

The `/src/Core` directory contains over 50 specialized security modules:

| Category | Key Files |
|----------|-----------|
| **Engines** | `AntivirusEngine.cs`, `ManualScanEngine.cs`, `MultiLayerDetectionEngine.cs`, `RealTimeProtectionEngine.cs` |
| **Monitors** | `BehaviorMonitor.cs`, `ProcessMonitor.cs`, `NetworkMonitor.cs`, `RegistryMonitor.cs`, `DownloadMonitor.cs` |
| **Security** | `ExploitProtection.cs`, `SelfDefenseSystem.cs`, `RansomwareShield.cs`, `UsbScanner.cs`, `FirewallManager.cs` |
| **Databases** | `SignatureDatabase.cs`, `MalwareSignatureDatabase.cs`, `BinaryPatternDatabase.cs` |
| **Low-Level** | `KernelDriverInterface.cs`, `MemoryScanner.cs`, `ProcessTreeAnalyzer.cs`, `RootkitDetector.cs` |
| **Infrastructure** | `LocalWebServer.cs`, `CloudSyncService.cs`, `BackgroundUpdater.cs`, `ServiceWatchdog.cs` |
| **Utilities** | `Logger.cs`, `Hashing.cs`, `SecureConfigManager.cs`, `EncryptedStorage.cs` |

---

## 🐍 Python Engine: Core Module Breakdown

The Python backend (v13.1-Hardened-PROD) consists of 18 highly specialized security modules:

| Module | Core Responsibility |
|--------|----------------------|
| **`ai_threat_analysis.py`** | AI-powered analysis with confidence scoring, `SecurityScoreMeter`, `ThreatTimeline`, and `DarkWebMonitor`. |
| **`anti_evasion.py`** | Active defense system that prevents the SecureGuard process from being terminated or debugged. |
| **`account_system.py`** | Manages user authentication, industry-standard JWT handling, and encrypted session persistence. |
| **`network_protection.py`** | Advanced traffic analysis using `psutil` to identify and block malicious IP/domain communication. |
| **`quarantine_system.py`** | High-security file isolation using **AES-256-GCM** via Fernet with **PBKDF2** key derivation. |
| **`auto_update.py`** | Robust synchronization system for rolling out virus definition and heuristic rule updates. |
| **`subscription_system.py`** | Enterprise-grade license management with hardware-bound signature verification. |
| **`yara_scanner.py`** | Integration with the YARA ecosystem for rule-based binary pattern matching. |

---

## 📡 Global Threat Intelligence Integration

SecureGuard synchronizes with the world's leading open-source threat feeds to provide real-time protection against emerging zero-day vulnerabilities:
- **URLhaus:** Real-time ingestion of malicious URLs used for malware distribution.
- **MalwareBazaar:** Daily updates of malware samples, hashes, and behavioral tags.
- **FeodoTracker:** Comprehensive tracking of Botnet Command & Control (C2) infrastructure.
- **Abuse.ch:** Integrated API for checking suspicious files against a global database of known threats.


---

## 🛡️ Security Features

- **Ransomware Shield:** Uses behavioral triggers and "honey-pot" files to detect and stop encryption in progress.
- **USB Guard:** Instant auto-scan for `AUTORUN.INF` and rootkit patterns on external drives.
- **Isolated Sandbox:** A virtualized execution environment using built-in isolation techniques for zero-risk file analysis.
- **Self-Healing:** Monitors and restores integrity of local security databases and engine configurations.
- **Network DnsFilter:** Blocks connections to known C2 (Command & Control) servers and phishing domains.
- **Browser Protection:** Real-time extension for blocking web-based exploits and phishing.

---

## 🛠️ Developer API

SecureGuard exposes a localized REST API (Default Port: `8765`) for integration and dashboarding:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Returns real-time system health (CPU, RAM, Protection Status). |
| `/api/threats` | GET/POST | List detected threats or manually submit a file for analysis. |
| `/api/scan` | POST | Trigger a Quick, Full, or Custom system scan. |
| `/api/quarantine` | GET/DELETE | Manage isolated files and permanent deletion. |
| `/api/settings` | PATCH | Update protection levels and exclusion lists. |

---

## 🗺️ Future Roadmap

SecureGuard is continuously evolving towards an **Autonomous Security** vision:
1.  **Distributed Node Mesh:** Enabling multi-node collaboration for enterprise-wide threat hunting.
2.  **Kernel Hooking 2.0:** Moving towards a custom ELAM (Early Launch Anti-Malware) driver for boot-time protection.
3.  **Automated Incident Response:** AI-driven automated playbooks for containing lateral movement.
4.  **Mobile Companion:** iOS/Android app for remote monitoring and "One-Tap" threat neutralization.

---

## 📊 Security Telemetry & Scores

SecureGuard calculates a real-time **Security Score** for every device based on:
- **Protection State:** Are all real-time modules active?
- **Scan Recency:** When was the last full system scan performed?
- **Threat History:** Number of unresolved or high-severity threats.
- **System Health:** CPU/RAM/Disk pressure that might impact security performance.

The following telemetry is synced to the cloud every 60 seconds:
- `processesCount` (Total running)
- `securityScore` (0-100)

### **Exhaustive Metric Collection**
SecureGuard's telemetry engine (powered by `psutil` and `WMI`) captures a granular snapshot of system health every 60 seconds:

| Category | Specific Data Points captured |
|----------|------------------------------|
| **CPU** | Logical/Physical cores, Current/Min/Max frequency, Load averages (1/5/15m), Per-core usage. |
| **Memory** | Total/Available/Used/Free Virtual RAM, Swap Partition usage, Page file size. |
| **Disk** | Per-partition usage, I/O read/write counts, IOPS, R/W throughput (MB/s). |
| **Network** | Bytes sent/recv, Packet counts, Error rates, Drop rates, Connections by status (ESTABLISHED, LISTEN, etc.), Per-interface state. |
| **Systems** | Uptime, Boot time, Platform version, OS Build, Processor architecture. |
| **Batteries** | Charge percentage, Seconds left, Power plugged state (for laptop optimization). |

---

## 🛠️ Build & Development

### **Prerequisites**
- **Desktop:** .NET 8.0 SDK, Visual Studio 2022.
- **Backend:** Python 3.10+, PostgreSQL 15+, Redis 7.
- **Driver:** Windows Driver Kit (WDK).

### **Commands**
```bash
# Build the Desktop Executable
dotnet build -c Release -r win-x64 --self-contained

# Initialize the Python Backend
cd backend-python
pip install -r requirements.txt
uvicorn app.main:app --reload

# Compile the Kernel Driver
cd Driver
build_driver.bat
```

---

## 📝 Logging & Diagnostics

Detailed logs are stored in the `/logs` directory in structured JSON format for easy ingestion by SIEM tools:
- **`security_events.json`:** Every threat detection and quarantine action.
- **`system_telemetry.json`:** Periodic snapshots of system health.
- **`app_errors.json`:** Stack traces and crash reports for troubleshooting.
- **`update_history.json`:** Logs of all signature and engine updates.


---

## ⚡ Performance & Optimization

SecureGuard is engineered to maintain a negligible system footprint:
- **Low-Latency Hooking:** Asynchronous monitoring ensures that system performance remains unaffected during real-time scans.
- **Intelligent Caching:** Known safe files are cached using high-speed hashing to avoid redundant scanning.
- **Resource Gating:** Automatically scales back background activities during high CPU/RAM usage by user applications.
- **Delta Updates:** Signatures are updated incrementally to minimize bandwidth usage.
- **Asynchronous Execution:** All high-latency security tasks (Full scans, ML inference) are offloaded to background threads to prevent UI freezing.
- **Smart Throttling:** The engine dynamically adjusts its scanning priority based on the user's active application focus (e.g., lower priority when gaming or video editing).

---

## 🔄 Internal Interaction & Data Flow

SecureGuard's effectiveness stems from the tight integration between its core components:

### **1. The Protection Loop (Real-Time)**
- **Intercept:** The `RealTimeProtectionEngine` (Kernel/User-mode) intercepts a file access or process launch.
- **Analyze:** The `MultiLayerDetectionEngine` runs the sequence: YARA -> Heuristics -> AI Inference.
- **Neutralize:** If a threat is found, the `QuarantineManager` isolates the file, and `ProcessMonitor` kills the associated PID.
- **Alert:** The `NotificationManager` sends a balloon notification via the `SystemTrayManager`.

### **2. The Telemetry & Display Flow**
- **Harvest:** The `SystemDataConnector` gathers real metrics (CPU, RAM, Connections) using WMI and Performance Counters.
- **Serve:** The `LocalWebServer` (Port 8765) exposes this data via a REST API.
- **Sync:** The Web Dashboard (HTML/JS) connects via **WebSocket** for sub-second updates of the UI stats and threat feeds.

### **3. The Support & Update Cycle**
- **Watch:** The `ServiceWatchdog` ensures all critical security services are alive and healthy.
- **Heal:** The `SelfHealingEngine` monitors the integrity of the `SignatureDatabase` and binary files.
- **Refresh:** The `BackgroundUpdater` pulls the latest threat intelligence and engine patches in the background.

---

## 🏢 Enterprise API Management

SecureGuard's enterprise capabilities are managed via specialized APIs:
- **Management API:** Located in `/enterprise/management_api.py`, this Python-based service allows for large-scale configuration changes and security policy deployments across multi-device environments.
- **REST Hooks:** Support for real-time webhooks to push critical security events directly to external SOC (Security Operations Center) tools.
- **Policy Enforcement:** Enforces strict compliance rules, such as mandatory system scans or disabled USB access, at the organizational level.

---

## 📊 Detailed Logging & Diagnostic Data

The `/logs` directory provides deep visibility into the system's security posture:
- **`security_events.json`**: Every detection, blocked process, and quarantined file with associated hashes and metadata.
- **`system_telemetry.json`**: Historical performance snapshots for CPU, memory, and network throughput.
- **`update_history.json`**: Chronological log of signature updates and engine patches.
- **`app_errors.json`**: Detailed stack traces for system-mode and user-mode components to facilitate rapid debugging.
- **Audit Logs:** Tracks all administrative changes, login attempts, and policy updates.

---

## 🏗️ Cloud Backend Infrastructure

SecureGuard utilizes a scalable, production-grade backend to manage large-scale deployments:

### **1. Python FastAPI Stack**
The `backend-python/` ecosystem provides the following services:
- **`app/main.py`**: High-performance asynchronous entry point.
- **`app/auth/`**: JWT-based authentication with `PBKDF2-HMAC-SHA256` password hashing.
- **`app/routers/`**: Specialized endpoints for `devices`, `threats`, `telemetry`, and `ml`.
- **`app/services/`**: Internal logic for ML inference, threat intelligence ingestion, and WebSocket notification management.

### **2. Relational Database Schema (PostgreSQL)**
SecureGuard uses a robust relational schema to maintain data integrity across the platform:

```sql
-- Core Identity & Device Tables
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    plan VARCHAR(50) DEFAULT 'free',
    is_active BOOLEAN,
    is_admin BOOLEAN
);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    device_name VARCHAR(255),
    os_version VARCHAR(100),
    last_seen TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active'
);

-- Security Event Persistence
CREATE TABLE threats (
    id UUID PRIMARY KEY,
    device_id UUID REFERENCES devices(id),
    threat_name VARCHAR(255),
    file_path TEXT,
    severity VARCHAR(50),
    action_taken VARCHAR(50),
    detected_at TIMESTAMP
);

CREATE TABLE device_telemetry (
    id UUID PRIMARY KEY,
    device_id UUID REFERENCES devices(id),
    recorded_at TIMESTAMP,
    cpu_usage INTEGER,
    ram_usage INTEGER,
    security_score INTEGER
);
```

---

## 🔌 Advanced API & Integration Flows

### **1. Machine Learning Inference Endpoints**
The backend provides sub-second ML analysis for multiple vectors:
- `POST /api/ml/analyze-file`: Structural and entropy analysis of binaries.
- `POST /api/ml/analyze-url`: Real-time phishing and malicious TLD detection.
- `POST /api/ml/analyze-process`: Behavior-weighted process tree analysis.
- `POST /api/ml/analyze-network`: Traffic pattern matching for C2 detection.

### **2. Device Registration Flow**
1.  **Identity Creation:** User registers on the Web Dashboard.
2.  **Client Installation:** User downloads and installs the Desktop client.
3.  **Secure Pairing:** Desktop client generates a unique hardware-bound ID and displays a registration code.
4.  **Cloud Linkage:** User enters the code on the Dashboard, linking the hardware to their encrypted account profile via an IOCTL-validated handshake.

### **3. Real-Time WebSocket Infrastructure**
- **Channel Persistence:** The desktop engine maintains a persistent WebSocket connection to `ws://api.secureguard.com/ws/{client_id}`.
- **Instant Mitigation:** Administrators can push "Instant Kill" or "Network Isolate" commands to any device globally with less than 200ms latency.
- **Live Feed:** Threat detections are pushed instantly to the user's dashboard without page reloads.

---

## 🧠 Advanced Self-Healing & System Recovery

SecureGuard's `SelfHealingEngine.cs` is a post-attack recovery system designed to revert malicious changes and restore system integrity:

### **1. Automated Repair Rules**
The engine maintains a library of **RepairRules** that target specific areas of the OS:
- **Registry Restoration:** Automatically removes suspicious entries from `Run`/`RunOnce` and resets common malware targets like Explorer folder options and Windows Update policies.
- **System File Integrity:** Verifies and repairs critical binaries in `System32` and `SysWOW64` using verified local or cloud-based copies.
- **Permission Resets:** Uses `icacls` integration to reset ACLs (Access Control Lists) on core system folders that might have been altered by rootkits.

### **2. System Snapshots**
The engine creates lightweight **SystemSnapshots** to allow for point-in-time restoration:
- **State Capture:** Captures the current state of critical registry keys, services, and core file checksums.
- **Snapshot Retention:** Maintains a rolling history of the last 10 system states for granular rollback options.

### **3. File Recovery (Ransomware Mitigation)**
The recovery engine can attempt to restore files encrypted by ransomware:
- **Extension Awareness:** Automatically identifies files with extensions like `.locky`, `.crypto`, `.vault`, and `.hermes`.
- **Shadow Recovery:** Attempts to locate originals by searching for hidden `.bak` or `.original` versions created before encryption.

---

## ⚙️ Complete Configuration Schema

SecureGuard is highly configurable via the `AppConfiguration` schema. Below are the primary control categories:

| Category | Available Settings |
|----------|--------------------|
| **Protection** | `RealTimeProtectionEnabled`, `RansomwareShieldEnabled`, `NetworkProtectionEnabled`, `UsbScanEnabled`, `PrivacyProtectionEnabled` |
| **Startup** | `StartWithWindows`, `StartMinimized`, `IsFirstRun` |
| **Notifications** | `ShowNotifications`, `PlaySounds` |
| **Scanning** | `ScanPriority` (Low/Normal/High), `QuickScanOnly`, `ScanArchives`, `ScanEmails` |
| **Updates** | `AutoUpdate`, `CheckBetaUpdates` |
| **Localization** | `Theme` (Dark/Light), `Language` (en-US, etc.) |

---

## 🔒 Cryptographic & Safety Standards

SecureGuard adheres to high-grade security protocols for all internal and external data handling:
- **Data at Rest:** All quarantined threats and security logs are encrypted using **AES-256**.
- **Data in Transit:** API communication and telemetry sync use **TLS 1.3** with forced certificate pinning.
- **Sensitive Storage:** Configuration secrets and user credentials (JWTs) are stored in the user's secure application data folder with restricted ACLs.
- **Safe DNS:** Uses validated recursive resolvers to prevent DNS poisoning and redirection attacks.

---

## 🧹 Project Evolution & Optimization

SecureGuard has undergone a massive engineering cleanup to achieve its current production-grade stability:
- **Engine Consolidation:** 4+ redundant detection engines were merged into a single, high-performance C#/.NET 8 core.
- **UI Streamlining:** Multiple experimental GUIs were consolidated into the high-performance **`modern_ui_new.py`** (WPF/Python Hybrid).
- **Dead Code Elimination:** Removed over 40+ duplicate `.md` files and 30+ legacy test scripts to ensure a clean, maintainable codebase.
- **Dependency Hardening:** Minimalist dependency tree focusing on `psutil` (System Monitoring), `cryptography` (Security), and `FastAPI` (Infrastructure).

---

## 📦 Installation & Deployment

SecureGuard supports various deployment scenarios:
- **Standard Installer:** A professional Inno Setup-based EXE for manual installation.
- **Enterprise Deployment:** Supports `/SILENT` and `/VERYSILENT` flags for mass rollout via Group Policy (GPO) or SCCM.
- **Portable Mode:** Can be run as a standalone executable for one-time system cleaning.

---

## 🐳 Containerization & Deployment (Docker)

SecureGuard is fully containerized for simplified enterprise rollout:

```yaml
# docker-compose.yml Summary
services:
  api:
    build: ./backend-python
    ports: ["8000:8000"]
    depends_on: [db, cache]
  db:
    image: postgres:15
    volumes: ["postgres_data:/var/lib/postgresql/data"]
  cache:
    image: redis:7-alpine
  nginx:
    image: nginx:alpine
    ports: ["80:80", "443:443"]
```

---

## 🛠️ Known Issues & Troubleshooting

> [!IMPORTANT]
> **Build Environment Requirement:**
> To generate the necessary output files during compilation, you **MUST** use the **.NET 8.0 SDK**. Users attempting to build with .NET 10.0 SDK may encounter "successful build" reports that do not generate actual binary artifacts.

### **Common Fixes:**
- **Driver Not Loading:** Ensure "Safe Boot" is disabled or the driver is signed with an EV certificate for production use.
- **WebSocket Disconnection:** Check for firewall rules blocking port `8765` (local) or your configured cloud port.
- **Database Locked:** This typically occurs if multiple instances of the `LocalWebServer` are running. Use `Task Manager` to kill redundant `SecureGuard.exe` processes.

---

## 🛡️ Security Governance & Compliance

SecureGuard is designed with **Privacy-by-Design** principles:
- **PII Masking:** Local telemetry masks Usernames and specific PII before syncing to the cloud backend.
- **Data Sovereignty:** All Docker volumes are mapped to the `D:/` drive by default (as per Sovereign OS requirements) to ensure data isolation.
- **GDPR Compliance:** Built-in "Right to be Forgotten" endpoints in the Management API to purge user/device telemetry upon request.
- **Encryption Standards:** Uses `AES-256-GCM` for file isolation and `TLS 1.3` for all network transit.


---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](file:///d:/SecureGuard/LICENSE) file for details.

---

*SecureGuard Enterprise - Advanced Autonomous Protection*

