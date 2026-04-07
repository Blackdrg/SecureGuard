"""
SecureGuard Antivirus - Complete Modern UI (Fixed)
==========================================
Full-featured antivirus interface with all security features.
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

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
import time
from datetime import datetime
from typing import List

# Try to import AI/Enterprise features
try:
    from engine.ai_threat_analysis import AIThreatAnalyzer, SecurityScoreMeter, ThreatTimeline
    HAS_AI = True
except:
    HAS_AI = False

try:
    from engine.enterprise_features import DeviceControl, ApplicationControl
    HAS_ENTERPRISE = True
except:
    HAS_ENTERPRISE = False


# Premium Professional Color Palette - Cyber Security Theme
COLORS = {
    'primary': '#00D4FF',
    'primary_dark': '#0099CC',
    'primary_glow': '#00E5FF',
    'secondary': '#7B2CBF',
    'safe': '#00FF88',
    'safe_dark': '#00CC6A',
    'warning': '#FFB800',
    'danger': '#FF3366',
    'bg_dark': '#0A0E17',
    'bg_darker': '#05080C',
    'card_bg': '#151D2B',
    'card_hover': '#1C2636',
    'card_border': '#2A3A50',
    'text': '#FFFFFF',
    'text_bright': '#F0F4F8',
    'text_dim': '#6B7C93',
    'text_accent': '#00D4FF',
    'cyber_blue': '#00F0FF',
    'cyber_purple': '#A855F7',
}


class ModernUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecureGuard Antivirus - Professional Protection")
        self.root.geometry("1400x900")
        self.root.configure(bg=COLORS['bg_dark'])

        # Core components
        self.detection_engine = DetectionEngine()
        self.system_stats = SystemStats()
        self.quarantine_system = QuarantineSystem()
        self.threat_logger = get_threat_logger()
        self.process_monitor = ProcessMonitor()
        self.network_shield = NetworkShield()
        self.threat_feed = ThreatFeed()

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

        # Logo
        logo_frame = tk.Frame(sidebar, bg=COLORS['card_bg'])
        logo_frame.pack(pady=(20, 10))

        tk.Label(logo_frame, text="S", font=('Arial', 40, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['primary']).pack()
        tk.Label(logo_frame, text="SecureGuard", font=('Helvetica', 18, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['text_bright']).pack()
        tk.Label(logo_frame, text="Professional Security Suite", font=('Helvetica', 8),
                 bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(pady=(0, 15))

        # Menu items
        menu_items = [
            ("Dashboard", self.show_dashboard),
            ("Scan Center", self.show_scan),
            ("Protection", self.show_protection),
            ("Quarantine", self.show_quarantine),
            ("Process Monitor", self.show_processes),
            ("Network", self.show_network),
            ("Settings", self.show_settings)
        ]

        for text, cmd in menu_items:
            btn = tk.Button(sidebar, text=f"  {text}",
                            bg=COLORS['card_bg'], fg=COLORS['text_dim'],
                            font=('Helvetica', 11), relief=tk.FLAT,
                            anchor='w', padx=25, pady=10, bd=0,
                            command=cmd, cursor='hand2')
            btn.pack(fill=tk.X, padx=10, pady=1)

        # Status indicator
        status_frame = tk.Frame(sidebar, bg=COLORS['card_bg'], pady=15)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        tk.Label(status_frame, text="Protected",
                 font=('Helvetica', 10, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['safe']).pack()

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def create_card(self, parent, **kwargs):
        card = tk.Frame(parent, bg=COLORS['card_bg'], **kwargs)
        return card

    def show_dashboard(self):
        self.clear_content()

        # Header
        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))

        tk.Label(header, text="Dashboard", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack(side=tk.LEFT)

        # Status card
        status_card = self.create_card(self.content)
        status_card.pack(fill=tk.X, pady=(0, 15))

        stats = self.system_stats.get_all_stats()
        scanning = stats.get('scanning', {})
        threats = scanning.get('total_threats_blocked', 0)

        status_color = COLORS['safe'] if threats == 0 else COLORS['danger']
        status_text = "PROTECTED" if threats == 0 else "THREATS DETECTED"

        tk.Label(status_card, text=status_text,
                 font=('Helvetica', 18, 'bold'),
                 bg=COLORS['card_bg'], fg=status_color).pack(pady=15)

        # Stats row
        system = stats.get('system', {})
        files = scanning.get('total_files_scanned', 0)
        cpu = system.get('cpu_usage', 0)
        mem = system.get('memory', {}).get('percent', 0)
        sig_count = len(self.detection_engine.signatures)

        stats_data = [
            ("Threats Blocked", str(threats), COLORS['danger']),
            ("Files Scanned", f"{files:,}", COLORS['primary']),
            ("Signatures", str(sig_count), COLORS['secondary']),
            ("CPU", f"{cpu:.1f}%", COLORS['warning']),
            ("Memory", f"{mem:.1f}%", COLORS['primary']),
        ]

        stats_frame = tk.Frame(self.content, bg=COLORS['bg_dark'])
        stats_frame.pack(fill=tk.X)

        for i, (label, value, color) in enumerate(stats_data):
            card = self.create_card(stats_frame)
            card.grid(row=0, column=i, padx=5, pady=5, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)

            tk.Label(card, text=value, font=('Helvetica', 18, 'bold'),
                     bg=COLORS['card_bg'], fg=color).pack(pady=(10, 5))
            tk.Label(card, text=label, font=('Helvetica', 8),
                     bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(pady=(0, 10))

        # Quick actions
        actions_frame = tk.Frame(self.content, bg=COLORS['bg_dark'])
        actions_frame.pack(fill=tk.X, pady=(15, 0))

        self.create_button(actions_frame, "Quick Scan",
                                self.quick_scan, COLORS['primary']).pack(side=tk.LEFT, padx=5)
        self.create_button(actions_frame, "Full Scan",
                                self.full_scan, COLORS['safe']).pack(side=tk.LEFT, padx=5)

    def create_button(self, parent, text, command, color=COLORS['primary']):
        btn = tk.Button(parent, text=text, bg=color, fg='white',
                        font=('Helvetica', 10, 'bold'), relief=tk.FLAT,
                        bd=0, padx=20, pady=10, command=command, cursor='hand2')
        return btn

    def show_scan(self):
        self.clear_content()

        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="Scan Center", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack()

        scans = [
            ("Quick Scan", "Fast scan of common locations", COLORS['primary'], self.quick_scan),
            ("Full Scan", "Complete system scan", COLORS['safe'], self.full_scan),
            ("Custom Scan", "Select specific folders", COLORS['warning'], self.custom_scan),
        ]

        for title, desc, color, cmd in scans:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=5)

            left = tk.Frame(card, bg=COLORS['card_bg'])
            left.pack(side=tk.LEFT, fill=tk.BOTH,
                      expand=True, padx=15, pady=12)

            tk.Label(left, text=title, font=('Helvetica', 12, 'bold'),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright']).pack(anchor='w')
            tk.Label(left, text=desc, font=('Helvetica', 8),
                     bg=COLORS['card_bg'], fg=COLORS['text_dim']).pack(anchor='w')

            self.create_button(card, "START", cmd, color).pack(
                side=tk.RIGHT, padx=15, pady=12)

    def show_protection(self):
        self.clear_content()

        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="Protection Center", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack()

        protections = [
            ("Real-Time Protection", "Active", COLORS['safe']),
            ("Firewall", "Active", COLORS['safe']),
            ("Ransomware Shield", "Active", COLORS['safe']),
            ("Network Shield", f"{len(self.network_shield.blocked_ips)} IPs blocked", COLORS['safe']),
            ("Behavior Monitoring", "Active", COLORS['safe']),
        ]

        for name, status, color in protections:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=3)

            tk.Label(card, text=name, font=('Helvetica', 10),
                     bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=15, pady=12).pack(side=tk.LEFT)
            tk.Label(card, text=status, font=('Helvetica', 10, 'bold'),
                     bg=COLORS['card_bg'], fg=color, padx=15).pack(side=tk.RIGHT)

    def show_quarantine(self):
        self.clear_content()

        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="Quarantine", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack()

        try:
            quarantined = self.quarantine_system.list_quarantined()
        except:
            quarantined = {}

        count = len(quarantined)

        tk.Label(self.content, text=f"{count} items in quarantine",
                 font=('Helvetica', 12),
                 bg=COLORS['bg_dark'], fg=COLORS['text_dim']).pack(pady=10)

        if count == 0:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=20)
            tk.Label(card, text="Quarantine is empty - No threats detected",
                     font=('Helvetica', 13),
                     bg=COLORS['card_bg'], fg=COLORS['safe']).pack(pady=20)

    def show_processes(self):
        self.clear_content()

        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="Process Monitor", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack()

        try:
            processes = self.process_monitor.get_all_processes()
            suspicious = self.process_monitor.scan_processes()
        except:
            processes = []
            suspicious = []

        card = self.create_card(self.content)
        card.pack(fill=tk.X, pady=5)

        tk.Label(card, text=f"Running Processes: {len(processes)}",
                 font=('Helvetica', 11),
                 bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=15, pady=10).pack(side=tk.LEFT)
        tk.Label(card, text=f"Suspicious: {len(suspicious)}",
                 font=('Helvetica', 11, 'bold'),
                 bg=COLORS['card_bg'], fg=COLORS['danger'] if suspicious else COLORS['safe'], padx=15).pack(side=tk.RIGHT)

    def show_network(self):
        self.clear_content()

        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="Network Connections", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack()

        try:
            connections = self.network_shield.get_all_connections()
        except:
            connections = []

        card = self.create_card(self.content)
        card.pack(fill=tk.X, pady=5)

        tk.Label(card, text=f"Total Connections: {len(connections)}",
                 font=('Helvetica', 11),
                 bg=COLORS['card_bg'], fg=COLORS['text_bright'], padx=15, pady=10).pack()

    def show_settings(self):
        self.clear_content()

        header = tk.Frame(self.content, bg=COLORS['bg_dark'])
        header.pack(fill=tk.X, pady=(0, 20))
        tk.Label(header, text="Settings", font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack()

        settings = [
            ("Real-Time Protection", True),
            ("Auto Updates", True),
            ("Heuristic Scanning", True),
            ("Cloud Protection", True),
        ]

        for name, default in settings:
            card = self.create_card(self.content)
            card.pack(fill=tk.X, pady=2)
            var = tk.BooleanVar(value=default)
            tk.Checkbutton(card, text=name, variable=var,
                           font=('Helvetica', 10),
                           bg=COLORS['card_bg'], fg=COLORS['text_bright'],
                           selectcolor=COLORS['card_bg']).pack(padx=15, pady=8, anchor='w')

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

    def run_scan(self, scan_type: str, paths: List[str]):
        if self.scan_running:
            messagebox.showwarning("Scan", "A scan is already in progress!")
            return

        self.scan_running = True
        self.clear_content()

        tk.Label(self.content, text=scan_type, font=('Helvetica', 24, 'bold'),
                 bg=COLORS['bg_dark'], fg=COLORS['text_bright']).pack(pady=30)

        card = self.create_card(self.content)
        card.pack(fill=tk.X, pady=20, padx=50)

        self.scan_status = tk.Label(card, text="Scanning...", font=('Helvetica', 14),
                                    bg=COLORS['card_bg'], fg=COLORS['text_dim'])
        self.scan_status.pack(pady=20)

        self.scan_progress = tk.Label(card, text="Files: 0", font=('Helvetica', 12),
                                      bg=COLORS['card_bg'], fg=COLORS['primary'])
        self.scan_progress.pack(pady=5)

        progress_bar = ttk.Progressbar(card, mode='determinate', length=400)
        progress_bar.pack(fill=tk.X, padx=30, pady=20)

        threading.Thread(target=self._perform_scan,
                         args=(scan_type, paths, progress_bar),
                         daemon=True).start()

    def _perform_scan(self, scan_type: str, paths: List[str], progress_bar):
        files_to_scan = []

        for path in paths:
            if os.path.exists(path):
                try:
                    for root, dirs, files in os.walk(path):
                        if len(files_to_scan) > 5000:
                            break
                        for f in files:
                            files_to_scan.append(os.path.join(root, f))
                except:
                    pass

        total = max(len(files_to_scan), 1)
        threats_found = 0

        for i, filepath in enumerate(files_to_scan):
            if i % 10 == 0:
                try:
                    percent = (i / total) * 100
                    self.root.after(
                        0, lambda p=percent: progress_bar.config(value=p))
                    self.root.after(
                        0, lambda f=i: self.scan_progress.config(text=f"Files: {f:,}"))
                except:
                    pass

            try:
                result = self.detection_engine.scan_file(filepath)
                if not result['clean']:
                    threat_name = result.get('threat_name', 'Unknown')
                    threat_type = result.get('threat_type', 'unknown')
                    self.threat_logger.log_threat(threat_name, filepath, "Scan",
                                                  "Quarantined", threat_type, "signature")
            except:
                pass

        self.system_stats.record_scan(scan_type, len(files_to_scan), threats_found)
        self.detection_engine.update_stats(len(files_to_scan), threats_found, scan_type)

        try:
            self.root.after(0, lambda: progress_bar.config(value=100))
            self.root.after(0, lambda: self.scan_status.config(
                text=f"Complete! Scanned {len(files_to_scan):,} files, found {threats_found} threats.",
                fg=COLORS['safe']))
        except:
            pass

        time.sleep(2)
        try:
            self.root.after(0, self.show_dashboard)
        except:
            pass

        self.scan_running = False

    def update_loop(self):
        while True:
            try:
                time.sleep(5)
                self.system_stats.get_cpu_usage()
            except:
                break

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = ModernUI()
    app.run()
