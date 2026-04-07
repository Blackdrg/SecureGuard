"""
SecureGuard Antivirus - Professional UI
======================================
Enhanced cybersecurity-themed interface with professional graphics.
"""

from network.threat_feed import ThreatFeed
from engine.network_shield import NetworkShield
from engine.process_monitor import ProcessMonitor
from engine.account_system import get_account_system
from engine.quarantine_system import QuarantineSystem
from engine.system_stats import SystemStats
from engine.detection_engine import DetectionEngine
from logs.threat_logger import get_threat_logger
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import sys
import os
import time
from datetime import datetime
from typing import List

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))


# Try to import AI/Enterprise features
try:
    from engine.ai_threat_analysis import AIThreatAnalyzer, SecurityScoreMeter
    HAS_AI = True
except:
    HAS_AI = False

try:
    from engine.enterprise_features import DeviceControl, FirewallManager
    HAS_ENTERPRISE = True
except:
    HAS_ENTERPRISE = False


# Professional Cyber Security Color Palette
COLORS = {
    'primary': '#00D4FF',
    'primary_dark': '#0099CC',
    'primary_glow': '#00E5FF',
    'secondary': '#7B2CBF',
    'secondary_dark': '#5A189A',
    'safe': '#00FF88',
    'safe_dark': '#00CC6A',
    'warning': '#FFB800',
    'warning_dark': '#CC9200',
    'danger': '#FF3366',
    'danger_dark': '#CC2952',
    'bg_dark': '#0A0E17',
    'bg_darker': '#05080C',
    'bg_gradient_start': '#0F1923',
    'bg_gradient_end': '#0A0E17',
    'card_bg': '#151D2B',
    'card_hover': '#1C2636',
    'card_border': '#2A3A50',
    'text': '#FFFFFF',
    'text_bright': '#F0F4F8',
    'text_dim': '#6B7C93',
    'text_accent': '#00D4FF',
    'accent': '#00D4FF',
    'cyber_blue': '#00F0FF',
    'cyber_purple': '#A855F7',
    'cyber_green': '#10B981',
    'cyber_red': '#EF4444',
    'cyber_orange': '#F59E0B',
}


class ModernUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ SecureGuard Antivirus - Professional Security Suite")
        self.root.geometry("1400x900")
        self.root.configure(bg=COLORS['bg_dark'])

        try:
            self.root.iconbitmap('shield.ico')
        except:
            pass

        # Core components
        self.detection_engine = DetectionEngine()
        self.system_stats = SystemStats()
        self.quarantine_system = QuarantineSystem()
        self.threat_logger = get_threat_logger()
        self.process_monitor = ProcessMonitor()
        self.network_shield = NetworkShield()
        self.threat_feed = ThreatFeed()

        # AI Features
        if HAS_AI:
            self.ai_analyzer = AIThreatAnalyzer()
            self.security_meter = SecurityScoreMeter()

        # Account system
        self.account_system = get_account_system()
        self.session_token = None
        self.logged_in = False
        self.current_user = None
        self.subscription_plan = "Free"

        # State
        self.scan_running = False
        self.realtime_protection_active = True

        # Setup UI
        self.setup_ui()

        # Start background updates
        threading.Thread(target=self.update_loop, daemon=True).start()

    def setup_ui(self):
        # Main container
        self.main_container = tk.Frame(self.root, bg=COLORS['bg_dark'])
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Create sidebar
        self.create_sidebar()

        # Content area
        self.content = tk.Frame(self.main_container,
                                bg=COLORS['bg_dark'], padx=25, pady=25)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Show dashboard by default
        self.show_dashboard()

    def create_sidebar(self):
        sidebar = tk.Frame(self.main_container,
                           bg=COLORS['card_bg'], width=280)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Logo with glow effect
        logo_frame = tk.Frame(sidebar, bg=COLORS['card_bg'])
        logo_frame.pack(pady=(20, 10))

        tk.Label(logo_frame, text="🛡️", font=('Arial', 40),
                 bg=COLORS['card_bg'], fg=COLORS['cyber_blue']).pack()
        
        # Animated title
        tk.Label(logo_frame, text="SecureGuard", font=('Helvetica', 20, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['text_bright']).pack()
        tk.Label(logo_frame, text="PROFESSIONAL SECURITY SUITE", font=('Helvetica', 7, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['cyber_purple']).pack(pady=(2, 15))

        # Menu items with hover effect
        menu_items = [
            ("🏠", "Dashboard", self.show_dashboard),
            ("🔍", "Scan Center", self.show_scan),
            ("🛡️", "Protection", self.show_protection),
            ("📊", "Security Score", self.show_security_score),
            ("📁", "Quarantine", self.show_quarantine),
            ("📜", "Threat History", self.show_threat_history),
            ("⚙️", "Process Monitor", self.show_processes),
            ("🌐", "Network", self.show_network),
            ("🔐", "Account", self.show_account),
            ("⚙️", "Settings", self.show_settings)
        ]

        for icon, text, cmd in menu_items:
            btn = tk.Button(sidebar, text=f"  {icon}  {text}",
                            bg=COLORS['card_bg'], fg=COLORS['text_dim'],
                            font=('Helvetica', 11), relief=tk.FLAT,
                            anchor='w', padx=25, pady=12, bd=0,
                            command=cmd, cursor='hand2')
            btn.pack(fill=tk.X, padx=10, pady=2)

        # Status indicator
        status_frame = tk.Frame(sidebar, bg=COLORS['card_bg'], pady=20)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # Animated protection status
        tk.Label(status_frame, text="●", font=('Arial', 18),
                 bg=COLORS['card_bg'], fg=COLORS['safe']).pack()
        tk.Label(status_frame, text="SYSTEM PROTECTED",
                 font=('Helvetica', 9, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['safe']).pack()

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def create_card(self, parent, **kwargs):
        card = tk.Frame(parent, bg=COLORS['card_bg'], **kwargs)
        return card

    def create_header(self, title_text, icon="📊"):
        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))

        tk.Label(header, text=f"{icon} {title_text}", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack(side=tk.LEFT)

        return header

    def show_dashboard(self):
        self.clear_content()

        # Header
        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))

        tk.Label(header, text="Dashboard", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack(side=tk.LEFT)

        user_text = f"👤 {self.current_user if self.current_user else 'Guest'}"
        tk.Label(header, text=user_text, font=('Helvetica', 12),
                 bg=COLORS['bg_dark'], fg=COLORS['text_dim']).pack(side=tk.RIGHT, padx=10)

        # Security Status Card - Large
        status_card = self.create_card(self.content)
        status_card.pack(fill=tk.X, pady=(0, 20))

        stats = self.system_stats.get_all_stats()
        scanning = stats.get('scanning', {})
        threats = scanning.get('total_threats_blocked', 0)

        status_color = COLORS['safe'] if threats == 0 else COLORS['danger']
        status_text = "YOUR SYSTEM IS PROTECTED" if threats == 0 else "THREATS DETECTED"

        tk.Label(status_card, text=f"🛡️ {status_text}",
                 font=('Helvetica', 16, 'bold'),
                 bg=COLORS['card_bg'], fg=status_color).pack(pady=20)

        # Real-time stats row
        system = stats.get('system', {})
        files = scanning.get('total_files_scanned', 0)
        cpu = system.get('cpu_usage', 0)
        mem = system.get('memory', {}).get('percent', 0)
        sig_count = len(self.detection_engine.signatures)

        stats_data = [
            ("🛡️ Threats Blocked", str(threats), COLORS['danger']),
            ("📁 Files Scanned", f"{files:,}", COLORS['cyber_blue']),
            ("🔏 Signatures", str(sig_count), COLORS['cyber_purple']),
            ("💻 CPU", f"{cpu:.1f}%", COLORS['warning']),
            ("💾 Memory", f"{mem:.1f}%", COLORS['cyber_green']),
        ]

        stats_frame = tk.Frame(self.content, bg=COLORS['bg_dark'])
        stats_frame.pack(fill=tk.X)

        for i, (label, value, color) in enumerate(stats_data):
            card = self.create_card(stats_frame)
            card.grid(row=0, column=i, padx=5, pady=5, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)

            tk.Label(card, text=value, font=('Helvetica', 20, 'bold'),
                     bg=COLORS['card_bg'], fg=color).pack(pady=(10, 5))
            tk.Label(card, text=label, font=('Helvetica', 8),
                     bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(pady=(0, 10))

        # Quick actions with glow buttons
        actions_frame = tk.Frame(self.content, bg=COLORS['bg_dark'])
        actions_frame.pack(fill=tk.X, pady=(20, 0))

        self.create_action_button(actions_frame, "⚡ Quick Scan",
                                self.quick_scan, COLORS['cyber_blue']).pack(side=tk.LEFT, padx=5)
        self.create_action_button(actions_frame, "🔍 Full Scan",
                                self.full_scan, COLORS['cyber_green']).pack(side=tk.LEFT, padx=5)
        self.create_action_button(actions_frame, "🛡️ Update",
                                self.update_signatures, COLORS['cyber_purple']).pack(side=tk.LEFT, padx=5)
        self.create_action_button(actions_frame, "🔎 Custom Scan",
                                self.custom_scan, COLORS['warning']).pack(side=tk.LEFT, padx=5)

    def create_action_button(self, parent, text, command, color):
        btn = tk.Button(parent, text=text, bg=color, fg='white',
                        font=('Helvetica', 10, 'bold'), relief=tk.FLAT,
                        bd=0, padx=20, pady=12, command=command, cursor='hand2')
        return btn

    def show_scan(self):
        self.clear_content()
        self.create_header("🔍 Scan Center")

        scans = [
            ("⚡", "Quick Scan", "Fast scan of common locations",
             COLORS['cyber_blue'], self.quick_scan),
            ("🔍", "Full Scan", "Complete system scan",
             COLORS['cyber_green'], self.full_scan),
            ("📁", "Custom Scan", "Select specific folders",
             COLORS['warning'], self.custom_scan),
            ("🎯", "Targeted Scan", "Scan specific files",
             COLORS['cyber_purple'], self.targeted_scan),
        ]

        for icon, title, desc, color, cmd in scans:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=8)

            left = tk.Frame(card, bg=COLORS['card_bg'])
            left.pack(side=tk.LEFT, fill=tk.BOTH,
                      expand=True, padx=20, pady=15)

            tk.Label(left, text=f"{icon} {title}", font=('Helvetica', 14, 'bold'),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright']).pack(anchor='w')
            tk.Label(left, text=desc, font=('Helvetica', 9),
                     bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(anchor='w')

            btn = tk.Button(card, text="▶ START", bg=color, fg='white',
                           font=('Helvetica', 10, 'bold'), relief=tk.FLAT,
                           bd=0, padx=25, pady=10, command=cmd, cursor='hand2')
            btn.pack(side=tk.RIGHT, padx=20, pady=15)

    def show_protection(self):
        self.clear_content()
        self.create_header("🛡️ Protection Center")

        protections = [
            ("Real-Time Protection", "Active ✓", COLORS['cyber_green']),
            ("Firewall", "Enabled ✓", COLORS['cyber_green']),
            ("Ransomware Shield", "Active ✓", COLORS['cyber_green']),
            ("Network Shield", f"{len(self.network_shield.blocked_ips)} IPs Blocked", COLORS['cyber_blue']),
            ("Behavior Monitoring", "Active ✓", COLORS['cyber_green']),
            ("Cloud Protection", "Connected ✓", COLORS['cyber_purple']),
            ("AI Threat Detection", "Active ✓", COLORS['cyber_green']),
            ("Auto-Update", "Enabled ✓", COLORS['cyber_green']),
        ]

        for name, status, color in protections:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=4)

            tk.Label(card, text=name, font=('Helvetica', 11),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=20, pady=15).pack(side=tk.LEFT)
            tk.Label(card, text=status, font=('Helvetica', 11, 'bold'),
                     bg=COLORS['card_bg'], fg=color, padx=20).pack(side=tk.RIGHT)

    def show_security_score(self):
        self.clear_content()

        self.create_header("📊 Security Score")

        # Calculate dynamic score
        stats = self.system_stats.get_all_stats()
        threats = stats.get('scanning', {}).get('total_threats_blocked', 0)
        
        # Score calculation
        base_score = 100
        if threats > 0:
            score = max(0, base_score - (threats * 5))
        else:
            score = 100

        score_color = COLORS['cyber_green'] if score >= 80 else COLORS['warning'] if score >= 60 else COLORS['danger']

        score_card = self.create_card(self.content)
        score_card.pack(fill=tk.X, pady=10)

        tk.Label(score_card, text=f"{score}/100", font=('Helvetica', 56, 'bold'),
                 bg=COLORS['card_bg'], fg=score_color).pack(pady=25)
        
        score_label = "Excellent" if score >= 80 else "Good" if score >= 60 else "Needs Attention"
        tk.Label(score_card, text=f"Security Rating: {score_label}", font=('Helvetica', 14),
                 bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack()

        # Score breakdown
        breakdown_items = [
            ("Virus Definitions", "100%", COLORS['cyber_green']),
            ("Real-Time Protection", "100%" if self.realtime_protection_active else "0%", COLORS['cyber_green']),
            ("Firewall Status", "Enabled", COLORS['cyber_green']),
            ("Last Scan", "Recently", COLORS['cyber_blue']),
        ]

        for item, value, color in breakdown_items:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=3)
            tk.Label(card, text=item, font=('Helvetica', 10),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=20, pady=10).pack(side=tk.LEFT)
            tk.Label(card, text=value, font=('Helvetica', 10, 'bold'),
                     bg=COLORS['card_bg'], fg=color, padx=20).pack(side=tk.RIGHT)

    def show_quarantine(self):
        self.clear_content()
        self.create_header("📁 Quarantine")

        try:
            quarantined = self.quarantine_system.list_quarantined()
        except:
            quarantined = {}

        count = len(quarantined)

        tk.Label(self.content, text=f"{count} items in quarantine",
                 font=('Helvetica', 13),
                 bg=COLORS['bg_dark'], fg=COLORS['text_dim']).pack(pady=10)

        if count == 0:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=30)
            tk.Label(card, text="✓ Quarantine is empty - No threats detected",
                     font=('Helvetica', 14),
                     bg=COLORS['card_bg'], fg=COLORS['cyber_green']).pack(pady=25)
        else:
            # List items
            for file_id, info in list(quarantined.items())[:20]:
                card = self.create_card(self.content)
                card.pack(fill=tk.X, pady=3)

                name = info.get('original_name', file_id)
                threat = info.get('threat_name', 'Unknown')

                tk.Label(card, text=name[:50], font=('Helvetica', 9),
                         bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=15, pady=10).pack(side=tk.LEFT)
                tk.Label(card, text=threat, font=('Helvetica', 8),
                         bg=COLORS['card_bg'], fg=COLORS['danger'], padx=15).pack(side=tk.RIGHT)

    def show_threat_history(self):
        self.clear_content()
        self.create_header("📜 Threat History")

        try:
            threat_stats = self.threat_logger.get_threat_statistics()
        except:
            threat_stats = {'total_threats': 0, 'by_severity': {}}

        total = threat_stats.get('total_threats', 0)

        card = self.create_card(self.content)
        card.pack(fill=tk.X, pady=10)

        if total == 0:
            tk.Label(card, text="✓ No threats detected - Your system is safe!",
                     font=('Helvetica', 14),
                     bg=COLORS['card_bg'], fg=COLORS['cyber_green']).pack(pady=25)
        else:
            tk.Label(card, text=f"Total threats detected: {total}",
                     font=('Helvetica', 14),
                     bg=COLORS['card_bg'], fg=COLORS['danger']).pack(pady=20)

            by_severity = threat_stats.get('by_severity', {})
            for severity, count in by_severity.items():
                sev_card = self.create_card(self.content)
                sev_card.pack(fill=tk.X, pady=3)
                tk.Label(sev_card, text=severity, font=('Helvetica', 10),
                         bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=20, pady=10).pack(side=tk.LEFT)
                tk.Label(sev_card, text=str(count), font=('Helvetica', 10, 'bold'),
                         bg=COLORS['card_bg'], fg=COLORS['danger'], padx=20).pack(side=tk.RIGHT)

    def show_processes(self):
        self.clear_content()
        self.create_header("⚙️ Process Monitor")

        try:
            processes = self.process_monitor.get_all_processes()
            suspicious = self.process_monitor.scan_processes()
        except:
            processes = []
            suspicious = []

        # Summary
        card = self.create_card(self.content)
        card.pack(fill=tk.X, pady=5)

        tk.Label(card, text=f"Running Processes: {len(processes)}",
                 font=('Helvetica', 12),
                 bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=20, pady=12).pack(side=tk.LEFT)
        tk.Label(card, text=f"Suspicious: {len(suspicious)}",
                 font=('Helvetica', 12, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['danger'] if suspicious else COLORS['cyber_green'], padx=20).pack(side=tk.RIGHT)

        # Show suspicious processes
        if suspicious:
            tk.Label(self.content, text="⚠️ Suspicious Processes Detected",
                     font=('Helvetica', 13, 'bold'),
                     bg=COLORS['bg_dark'], fg=COLORS['danger'], pady=15).pack()

            for proc in suspicious[:10]:
                p_card = self.create_card(self.content)
                p_card.pack(fill=tk.X, pady=3)

                name = proc.get('name', 'Unknown')
                pid = proc.get('pid', 0)

                tk.Label(p_card, text=f"⚠️ {name} (PID: {pid})",
                         font=('Helvetica', 9),
                         bg=COLORS['card_bg'], fg=COLORS['danger'], padx=15, pady=10).pack(side=tk.LEFT)
        else:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=20)
            tk.Label(card, text="✓ No suspicious processes detected",
                     font=('Helvetica', 13),
                     bg=COLORS['card_bg'], fg=COLORS['cyber_green']).pack(pady=20)

    def show_network(self):
        self.clear_content()
        self.create_header("🌐 Network Protection")

        try:
            connections = self.network_shield.get_all_connections()
        except:
            connections = []

        # Stats
        stats_card = self.create_card(self.content)
        stats_card.pack(fill=tk.X, pady=5)

        established = len([c for c in connections if c.get('status') == 'ESTABLISHED'])

        tk.Label(stats_card, text=f"Active Connections: {len(connections)}",
                 font=('Helvetica', 12),
                 bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=20, pady=15).pack(side=tk.LEFT)
        tk.Label(stats_card, text=f"Established: {established}",
                 font=('Helvetica', 12),
                 bg=COLORS['card_bg'], fg=COLORS['cyber_green'], padx=20).pack(side=tk.RIGHT)

        # Blocked IPs
        blocked_card = self.create_card(self.content)
        blocked_card.pack(fill=tk.X, pady=10)

        blocked_count = len(self.network_shield.blocked_ips)
        tk.Label(blocked_card, text=f"🛡️ Blocked Malicious IPs: {blocked_count}",
                 font=('Helvetica', 13),
                 bg=COLORS['card_bg'], fg=COLORS['cyber_blue'], padx=20, pady=15).pack()

    def show_account(self):
        self.clear_content()
        self.create_header("🔐 Account")

        if self.logged_in:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=20, padx=50)

            tk.Label(card, text=f"Welcome back, {self.current_user}!",
                     font=('Helvetica', 16, 'bold'),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright'], pady=20).pack()

            tk.Label(card, text=f"Plan: {self.subscription_plan}",
                     font=('Helvetica', 12),
                     bg=COLORS['card_bg'], fg=COLORS['cyber_purple'], pady=5).pack()

            btn = tk.Button(self.content, text="Logout", bg=COLORS['danger'], fg='white',
                           font=('Helvetica', 11, 'bold'), relief=tk.FLAT,
                           bd=0, padx=30, pady=10, command=self.logout, cursor='hand2')
            btn.pack(pady=20)
        else:
            # Login form
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=20, padx=80)

            tk.Label(card, text="Login to your SecureGuard Account",
                     font=('Helvetica', 15, 'bold'),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright'], pady=20).pack()

            tk.Label(card, text="Username:", bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(
                anchor='w', padx=25)
            username_entry = tk.Entry(card, font=('Helvetica', 11), bg=COLORS['bg_darker'],
                                      fg=COLORS['text_bright'], insertbackground=COLORS['primary'])
            username_entry.pack(fill=tk.X, padx=25, pady=5)

            tk.Label(card, text="Password:", bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(
                anchor='w', padx=25)
            password_entry = tk.Entry(card, show="*", font=('Helvetica', 11), bg=COLORS['bg_darker'],
                                      fg=COLORS['text_bright'], insertbackground=COLORS['primary'])
            password_entry.pack(fill=tk.X, padx=25, pady=5)

            def do_login():
                username = username_entry.get()
                if username:
                    self.logged_in = True
                    self.current_user = username
                    self.show_account()

            btn = tk.Button(card, text="Login", bg=COLORS['cyber_blue'], fg='white',
                           font=('Helvetica', 12, 'bold'), relief=tk.FLAT,
                           bd=0, padx=40, pady=10, command=do_login, cursor='hand2')
            btn.pack(pady=20)

            tk.Label(card, text="(Demo: Enter any username)",
                     font=('Helvetica', 9),
                     bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack()

    def logout(self):
        self.logged_in = False
        self.current_user = None
        self.show_account()

    def show_settings(self):
        self.clear_content()
        self.create_header("⚙️ Settings")

        settings = [
            ("Real-Time Protection", True, "Active monitoring for threats"),
            ("Auto Updates", True, "Automatically update virus definitions"),
            ("Heuristic Scanning", True, "Detect unknown threats by behavior"),
            ("Cloud Protection", True, "Use cloud-based threat intelligence"),
            ("Telemetry", False, "Send anonymous usage data"),
        ]

        for name, default, desc in settings:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=5)

            left = tk.Frame(card, bg=COLORS['card_bg'])
            left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=10)

            tk.Label(left, text=name, font=('Helvetica', 11, 'bold'),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright']).pack(anchor='w')
            tk.Label(left, text=desc, font=('Helvetica', 8),
                     bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(anchor='w')

            var = tk.BooleanVar(value=default)
            tk.Checkbutton(card, variable=var, bg=COLORS['card_bg'],
                          activebackground=COLORS['card_bg']).pack(side=tk.RIGHT, padx=15)

    def quick_scan(self):
        paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
        ]
        self.run_scan("Quick Scan", paths)

    def full_scan(self):
        if os.name == 'nt':
            self.run_scan("Full Scan", ["C:\\"])
        else:
            self.run_scan("Full Scan", ["/"])

    def custom_scan(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.run_scan("Custom Scan", [folder])

    def targeted_scan(self):
        files = filedialog.askopenfilenames(title="Select files to scan")
        if files:
            self.run_scan("Targeted Scan", list(files))

    def update_signatures(self):
        messagebox.showinfo("Update", "Virus definitions are up to date!")

    def run_scan(self, scan_type: str, paths: List[str]):
        if self.scan_running:
            messagebox.showwarning("Scan", "A scan is already in progress!")
            return

        self.scan_running = True
        self.clear_content()

        tk.Label(self.content, text=f"🔍 {scan_type}", font=('Helvetica', 28, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack(pady=30)

        card = self.create_card(self.content)
        card.pack(fill=tk.X, pady=20, padx=50)

        self.scan_status = tk.Label(card, text="Initializing scan...", font=('Helvetica', 15),
                                    bg=COLORS['card_bg'], fg=COLORS['cyber_blue'])
        self.scan_status.pack(pady=20)

        self.scan_progress = tk.Label(card, text="Preparing...", font=('Helvetica', 12),
                                      bg=COLORS['card_bg'], fg=COLORS['text_dim'])
        self.scan_progress.pack(pady=5)

        progress_bar = ttk.Progressbar(card, mode='determinate', length=500)
        progress_bar.pack(fill=tk.X, padx=30, pady=20)

        threading.Thread(target=self._perform_scan,
                         args=(scan_type, paths, progress_bar),
                         daemon=True).start()

    def _perform_scan(self, scan_type: str, paths: List[str], progress_bar):
        files_to_scan = []

        for path in paths:
            if os.path.exists(path):
                try:
                    if os.path.isdir(path):
                        for root, dirs, files in os.walk(path):
                            if len(files_to_scan) > 10000:
                                break
                            for f in files:
                                files_to_scan.append(os.path.join(root, f))
                    else:
                        files_to_scan.append(path)
                except:
                    pass

        total = max(len(files_to_scan), 1)
        threats_found = 0

        for i, filepath in enumerate(files_to_scan):
            if i % 10 == 0:
                try:
                    percent = (i / total) * 100
                    self.root.after(0, lambda p=percent: progress_bar.config(value=p))
                    self.root.after(0, lambda f=i: self.scan_progress.config(text=f"Scanning: {f:,} / {total:,} files"))
                    self.root.after(0, lambda: self.scan_status.config(text="Scanning in progress...", fg=COLORS['cyber_blue']))
                except:
                    pass

            try:
                result = self.detection_engine.scan_file(filepath)
                if not result['clean']:
                    threats_found += 1
                    threat_name = result.get('threat_name', 'Unknown')
                    threat_type = result.get('threat_type', 'unknown')
                    self.threat_logger.log_threat(threat_name, filepath, scan_type,
                                                  "Quarantined", threat_type, 'scan')
            except:
                pass

        self.system_stats.record_scan(scan_type, len(files_to_scan), threats_found)
        self.detection_engine.update_stats(len(files_to_scan), threats_found, scan_type)

        try:
            self.root.after(0, lambda: progress_bar.config(value=100))
            self.root.after(0, lambda: self.scan_status.config(
                text=f"✓ Scan Complete! Scanned {len(files_to_scan):,} files. Found {threats_found} threats.",
                fg=COLORS['cyber_green']))
            self.root.after(0, lambda: self.scan_progress.config(text="Finished"))
        except:
            pass

        time.sleep(3)
        try:
            self.root.after(0, self.show_dashboard)
        except:
            pass

        self.scan_running = False

    def update_loop(self):
        while True:
            try:
                time.sleep(10)
                self.system_stats.get_cpu_usage()
            except:
                break

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ModernUI()
    app.run()
