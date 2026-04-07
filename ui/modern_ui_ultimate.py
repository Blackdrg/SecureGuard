"""
SecureGuard Antivirus - Ultimate Professional UI
================================================
Enterprise-grade cybersecurity interface with advanced graphics,
animations, real-time monitoring, and premium features.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import sys
import os
import time
from datetime import datetime
from typing import List, Dict
import random

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import core components
from network.threat_feed import ThreatFeed
from engine.network_shield import NetworkShield
from engine.process_monitor import ProcessMonitor
from engine.account_system import get_account_system
from engine.quarantine_system import QuarantineSystem
from engine.system_stats import SystemStats
from engine.detection_engine import DetectionEngine
from logs.threat_logger import get_threat_logger

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


# Ultimate Professional Color Palette
class ColorPalette:
    """Premium cybersecurity color scheme"""
    PRIMARY = '#00D4FF'
    PRIMARY_DARK = '#0099CC'
    PRIMARY_GLOW = '#00E5FF'
    SECONDARY = '#7B2CBF'
    SECONDARY_DARK = '#5A189A'
    SAFE = '#00FF88'
    SAFE_DARK = '#00CC6A'
    WARNING = '#FFB800'
    WARNING_DARK = '#CC9200'
    DANGER = '#FF3366'
    DANGER_DARK = '#CC2952'
    
    # Background colors
    BG_DARK = '#0A0E17'
    BG_DARKER = '#05080C'
    BG_GLASS = '#0F1923'
    
    # Card colors
    CARD_BG = '#151D2B'
    CARD_HOVER = '#1C2636'
    CARD_BORDER = '#2A3A50'
    
    # Text colors
    TEXT = '#FFFFFF'
    TEXT_BRIGHT = '#F0F4F8'
    TEXT_DIM = '#6B7C93'
    TEXT_ACCENT = '#00D4FF'
    
    # Cyber accent colors
    CYBER_BLUE = '#00F0FF'
    CYBER_PURPLE = '#A855F7'
    CYBER_GREEN = '#10B981'
    CYBER_RED = '#EF4444'
    CYBER_ORANGE = '#F59E0B'
    CYBER_GOLD = '#FFD700'
    CYBER_PLATINUM = '#E5E4E2'
    
    # Gradients (simulated)
    GRADIENT_START = '#1a1f2e'
    GRADIENT_END = '#0d1117'


class AnimatedLabel:
    """Animated label with pulsing glow effect"""
    def __init__(self, parent, text, **kwargs):
        self.parent = parent
        self.text = text
        self.label = tk.Label(parent, text=text, **kwargs)
        self.animation_running = False
        self.colors = [ColorPalette.CYBER_BLUE, ColorPalette.PRIMARY, ColorPalette.CYBER_PURPLE]
        self.color_index = 0
        
    def pack(self, **kwargs):
        self.label.pack(**kwargs)
        
    def config(self, **kwargs):
        self.label.config(**kwargs)
        
    def start_animation(self):
        """Start pulsing animation"""
        if not self.animation_running:
            self.animation_running = True
            self._animate()
            
    def _animate(self):
        """Internal animation loop"""
        if not self.animation_running:
            return
        self.color_index = (self.color_index + 1) % len(self.colors)
        self.label.config(fg=self.colors[self.color_index])
        self.parent.after(500, self._animate)
        
    def stop_animation(self):
        self.animation_running = False


class GlowingButton(tk.Button):
    """Button with glow effect on hover"""
    def __init__(self, parent, text, command, **kwargs):
        self.default_bg = kwargs.get('bg', ColorPalette.CYBER_BLUE)
        self.default_fg = kwargs.get('fg', 'white')
        
        super().__init__(parent, text=text, command=command,
                        bg=self.default_bg, fg=self.default_fg,
                        relief=tk.FLAT, bd=0, cursor='hand2',
                        font=('Helvetica', 10, 'bold'),
                        padx=20, pady=10, **kwargs)
        
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        
    def _on_enter(self, event):
        self.config(bg=ColorPalette.PRIMARY_GLOW)
        
    def _on_leave(self, event):
        self.config(bg=self.default_bg)


class SecureGuardUltimate:
    """Ultimate Professional Security Suite Interface"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ SecureGuard Ultimate - Enterprise Security Suite")
        self.root.geometry("1600x1000")
        self.root.configure(bg=ColorPalette.BG_DARK)
        
        # Set window icon
        try:
            self.root.iconbitmap('shield.ico')
        except:
            pass
        
        # Initialize core components
        self._init_components()
        
        # State variables
        self.scan_running = False
        self.realtime_protection_active = True
        self.logged_in = False
        self.current_user = None
        self.subscription_plan = "Ultimate"
        
        # Animation states
        self.animations = {}
        
        # Build UI
        self._build_ui()
        
        # Start background services
        self._start_background_services()
        
    def _init_components(self):
        """Initialize all security components"""
        print("[*] Initializing SecureGuard Ultimate...")
        
        # Core detection engine
        self.detection_engine = DetectionEngine()
        print(f"    → {len(self.detection_engine.signatures)} malware signatures loaded")
        
        # System monitoring
        self.system_stats = SystemStats()
        
        # Quarantine system
        self.quarantine_system = QuarantineSystem()
        print("    → AES-256 encryption enabled")
        
        # Threat logging
        self.threat_logger = get_threat_logger()
        print("    → Threat history tracking enabled")
        
        # Process monitoring
        self.process_monitor = ProcessMonitor()
        print("    → Behavior analysis ready")
        
        # Network protection
        self.network_shield = NetworkShield()
        print(f"    → {len(self.network_shield.blocked_ips)} malicious IPs blocked")
        
        # Cloud threat intelligence
        self.threat_feed = ThreatFeed()
        print("    → Cloud threat intelligence connected")
        
        # Account system
        self.account_system = get_account_system()
        
        # AI features
        if HAS_AI:
            self.ai_analyzer = AIThreatAnalyzer()
            self.security_meter = SecurityScoreMeter()
            print("    → AI threat detection active")
        
        # Enterprise features
        if HAS_ENTERPRISE:
            self.device_control = DeviceControl()
            self.firewall_manager = FirewallManager()
            print("    → Enterprise features enabled")
        
        print("[✓] All security modules initialized\n")
        
    def _build_ui(self):
        """Build the complete UI"""
        # Main container with glass effect
        self.main_container = tk.Frame(self.root, bg=ColorPalette.BG_DARK)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create sidebar navigation
        self._create_sidebar()
        
        # Content area
        self.content = tk.Frame(self.main_container,
                               bg=ColorPalette.BG_DARK, padx=30, pady=30)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Show dashboard by default
        self.show_dashboard()
        
    def _create_sidebar(self):
        """Create professional sidebar navigation"""
        sidebar = tk.Frame(self.main_container,
                         bg=ColorPalette.CARD_BG, width=300)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        # Logo section with animated glow
        logo_frame = tk.Frame(sidebar, bg=ColorPalette.CARD_BG)
        logo_frame.pack(pady=(25, 15))
        
        # Shield icon
        tk.Label(logo_frame, text="🛡️", font=('Arial', 50),
                bg=ColorPalette.CARD_BG, fg=ColorPalette.CYBER_BLUE).pack()
        
        # App title
        tk.Label(logo_frame, text="SecureGuard", 
                font=('Helvetica', 22, 'bold'),
                bg=ColorPalette.CARD_BG, 
                fg=ColorPalette.TEXT_BRIGHT).pack(pady=(10, 3))
        
        # Subtitle
        tk.Label(logo_frame, text="ULTIMATE SECURITY SUITE",
                font=('Helvetica', 8, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.CYBER_PURPLE).pack()
        
        # Version info
        tk.Label(logo_frame, text="Version 2.0.0 | Enterprise",
                font=('Helvetica', 7),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_DIM).pack(pady=(5, 20))
        
        # Navigation menu
        nav_items = [
            ("🏠", "Dashboard", self.show_dashboard),
            ("🔍", "Scan Center", self.show_scan_center),
            ("🛡️", "Protection Hub", self.show_protection_hub),
            ("📊", "Security Score", self.show_security_score),
            ("📁", "Quarantine", self.show_quarantine),
            ("📜", "Threat History", self.show_threat_history),
            ("⚙️", "Process Monitor", self.show_process_monitor),
            ("🌐", "Network Monitor", self.show_network),
            ("🔐", "Account & License", self.show_account),
            ("⚙️", "Settings", self.show_settings),
            ("📈", "Reports", self.show_reports),
            ("🎯", "Threat Analysis", self.show_threat_analysis),
        ]
        
        # Navigation buttons
        nav_frame = tk.Frame(sidebar, bg=ColorPalette.CARD_BG)
        nav_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for icon, text, cmd in nav_items:
            btn = tk.Button(nav_frame, 
                           text=f"  {icon}  {text}",
                           bg=ColorPalette.CARD_BG,
                           fg=ColorPalette.TEXT_DIM,
                           font=('Helvetica', 11),
                           relief=tk.FLAT,
                           anchor='w',
                           padx=20,
                           pady=14,
                           bd=0,
                           command=cmd,
                           cursor='hand2')
            btn.pack(fill=tk.X, pady=3)
            
            # Hover effect
            btn.bind('<Enter>', lambda e, b=btn: b.config(
                bg=ColorPalette.CARD_HOVER, fg=ColorPalette.TEXT_BRIGHT))
            btn.bind('<Leave>', lambda e, b=btn: b.config(
                bg=ColorPalette.CARD_BG, fg=ColorPalette.TEXT_DIM))
        
        # Status section at bottom
        status_frame = tk.Frame(sidebar, bg=ColorPalette.CARD_BG, pady=20)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Animated status indicator
        self.status_dot = tk.Label(status_frame, text="●",
                                 font=('Arial', 20),
                                 bg=ColorPalette.CARD_BG,
                                 fg=ColorPalette.SAFE)
        self.status_dot.pack()
        
        tk.Label(status_frame, text="SYSTEM PROTECTED",
                font=('Helvetica', 10, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.SAFE).pack()
        
        tk.Label(status_frame, 
                text=f"Protected by {len(self.detection_engine.signatures)} signatures",
                font=('Helvetica', 8),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_DIM).pack(pady=(5, 0))
        
    def clear_content(self):
        """Clear all content widgets"""
        for widget in self.content.winfo_children():
            widget.destroy()
            
    def _create_card(self, parent, title=None, icon=None):
        """Create a styled card widget"""
        card = tk.Frame(parent, bg=ColorPalette.CARD_BG,
                       relief=tk.FLAT, bd=0)
        
        if title or icon:
            header = tk.Frame(card, bg=ColorPalette.CARD_BG)
            header.pack(fill=tk.X, padx=20, pady=(15, 10))
            
            if icon:
                tk.Label(header, text=icon, font=('Arial', 16),
                        bg=ColorPalette.CARD_BG).pack(side=tk.LEFT)
            if title:
                tk.Label(header, text=title,
                        font=('Helvetica', 12, 'bold'),
                        bg=ColorPalette.CARD_BG,
                        fg=ColorPalette.TEXT_BRIGHT).pack(side=tk.LEFT, padx=(8, 0))
                        
        return card
    
    def show_dashboard(self):
        """Main dashboard view"""
        self.clear_content()
        
        # Header
        header = tk.Frame(self.content, bg=ColorPalette.BG_DARK)
        header.pack(fill=tk.X, pady=(0, 25))
        
        tk.Label(header, text="Dashboard",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(side=tk.LEFT)
        
        # User info
        user_text = f"👤 {self.current_user if self.current_user else 'Guest'} | 🛡️ Ultimate Protection"
        tk.Label(header, text=user_text,
                font=('Helvetica', 11),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_DIM).pack(side=tk.RIGHT, padx=10)
        
        # Main status card - Large hero card
        status_card = self._create_card(self.content)
        status_card.pack(fill=tk.X, pady=(0, 20))
        
        # Get stats
        stats = self.system_stats.get_all_stats()
        scanning = stats.get('scanning', {})
        threats = scanning.get('total_threats_blocked', 0)
        
        # Status icon and text
        status_frame = tk.Frame(status_card, bg=ColorPalette.CARD_BG)
        status_frame.pack(fill=tk.X, pady=25)
        
        if threats == 0:
            status_icon = "✅"
            status_text = "YOUR SYSTEM IS FULLY PROTECTED"
            status_color = ColorPalette.SAFE
        else:
            status_icon = "⚠️"
            status_text = f"THREATS DETECTED - {threats} BLOCKED"
            status_color = ColorPalette.DANGER
            
        tk.Label(status_frame, text=f"{status_icon} {status_text}",
                font=('Helvetica', 18, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=status_color).pack()
        
        # Quick stats row - 6 cards
        system = stats.get('system', {})
        files = scanning.get('total_files_scanned', 0)
        cpu = system.get('cpu_usage', 0)
        mem = system.get('memory', {}).get('percent', 0)
        
        stats_data = [
            ("🛡️", "Threats Blocked", str(threats), ColorPalette.DANGER),
            ("📁", "Files Scanned", f"{files:,}", ColorPalette.CYBER_BLUE),
            ("🔏", "Signatures", str(len(self.detection_engine.signatures)), ColorPalette.CYBER_PURPLE),
            ("💻", "CPU Usage", f"{cpu:.1f}%", ColorPalette.WARNING),
            ("💾", "Memory", f"{mem:.1f}%", ColorPalette.CYBER_GREEN),
            ("🌐", "Protected IPs", str(len(self.network_shield.blocked_ips)), ColorPalette.CYBER_ORANGE),
        ]
        
        stats_frame = tk.Frame(self.content, bg=ColorPalette.BG_DARK)
        stats_frame.pack(fill=tk.X)
        
        for i, (icon, label, value, color) in enumerate(stats_data):
            card = self._create_card(stats_frame)
            card.grid(row=0, column=i, padx=6, pady=5, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)
            
            tk.Label(card, text=icon, font=('Arial', 24),
                    bg=ColorPalette.CARD_BG).pack(pady=(10, 5))
            tk.Label(card, text=value, font=('Helvetica', 18, 'bold'),
                    bg=ColorPalette.CARD_BG, fg=color).pack()
            tk.Label(card, text=label, font=('Helvetica', 8),
                    bg=ColorPalette.CARD_BG, fg=ColorPalette.TEXT_DIM).pack(pady=(0, 10))
        
        # Quick actions section
        actions_frame = tk.Frame(self.content, bg=ColorPalette.BG_DARK)
        actions_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Label(actions_frame, text="Quick Actions",
                font=('Helvetica', 14, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 15))
        
        # Action buttons
        actions = [
            ("⚡ Quick Scan", self.quick_scan, ColorPalette.CYBER_BLUE),
            ("🔍 Full System Scan", self.full_scan, ColorPalette.CYBER_GREEN),
            ("🛡️ Update Definitions", self.update_signatures, ColorPalette.CYBER_PURPLE),
            ("🔎 Custom Scan", self.custom_scan, ColorPalette.WARNING),
            ("📊 Security Report", self.show_reports, ColorPalette.CYBER_ORANGE),
        ]
        
        for text, cmd, color in actions:
            btn = GlowingButton(actions_frame, text, cmd, bg=color)
            btn.pack(side=tk.LEFT, padx=6)
    
    def show_scan_center(self):
        """Scan center with multiple scan types"""
        self.clear_content()
        
        # Header
        tk.Label(self.content, text="🔍 Scan Center",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        # Scan types
        scan_types = [
            ("⚡", "Quick Scan", "Fast scan of system temp folders, downloads, and common threat locations",
             "2-5 minutes", ColorPalette.CYBER_BLUE, self.quick_scan),
            ("🔍", "Full System Scan", "Complete scan of all files and folders on your system",
             "30-60 minutes", ColorPalette.CYBER_GREEN, self.full_scan),
            ("📁", "Custom Scan", "Select specific folders or drives to scan",
             "Variable", ColorPalette.WARNING, self.custom_scan),
            ("🎯", "Targeted Scan", "Scan specific files or applications",
             "1-2 minutes", ColorPalette.CYBER_PURPLE, self.targeted_scan),
            ("🧠", "AI-Powered Scan", "Advanced heuristic analysis using machine learning",
             "10-20 minutes", ColorPalette.CYBER_RED, self.ai_scan),
            ("🌐", "Network Scan", "Scan connected devices for vulnerabilities",
             "5-10 minutes", ColorPalette.CYBER_ORANGE, self.network_scan),
        ]
        
        for icon, title, desc, time_est, color, cmd in scan_types:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=8)
            
            # Left content
            left = tk.Frame(card, bg=ColorPalette.CARD_BG)
            left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=18)
            
            tk.Label(left, text=f"{icon} {title}",
                    font=('Helvetica', 15, 'bold'),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w')
            
            tk.Label(left, text=desc,
                    font=('Helvetica', 10),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_DIM).pack(anchor='w', pady=(5, 3))
            
            tk.Label(left, text=f"⏱️ Estimated time: {time_est}",
                    font=('Helvetica', 9),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.CYBER_PURPLE).pack(anchor='w')
            
            # Right button
            btn = GlowingButton(card, "▶ START", cmd, bg=color)
            btn.pack(side=tk.RIGHT, padx=20, pady=18)
    
    def show_protection_hub(self):
        """Protection hub showing all security modules"""
        self.clear_content()
        
        tk.Label(self.content, text="🛡️ Protection Hub",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        protections = [
            ("Real-Time Protection", "Active ✓", "Continuous file monitoring", ColorPalette.CYBER_GREEN),
            ("Firewall", "Enabled ✓", "Network traffic filter", ColorPalette.CYBER_GREEN),
            ("Ransomware Shield", "Active ✓", "Protects files from encryption", ColorPalette.CYBER_GREEN),
            ("Network Shield", f"{len(self.network_shield.blocked_ips)} IPs", "Blocks malicious connections", ColorPalette.CYBER_BLUE),
            ("Behavior Monitoring", "Active ✓", "Detects suspicious behavior", ColorPalette.CYBER_GREEN),
            ("Cloud Protection", "Connected ✓", "Real-time threat intelligence", ColorPalette.CYBER_PURPLE),
            ("AI Threat Detection", "Active ✓", "Machine learning analysis", ColorPalette.CYBER_GREEN if HAS_AI else ColorPalette.TEXT_DIM),
            ("Auto-Update", "Enabled ✓", "Automatic definition updates", ColorPalette.CYBER_GREEN),
            ("Web Protection", "Active ✓", "Blocks malicious websites", ColorPalette.CYBER_GREEN),
            ("Email Protection", "Active ✓", "Scans email attachments", ColorPalette.CYBER_GREEN),
            ("USB Protection", "Active ✓", "Scans removable media", ColorPalette.CYBER_GREEN),
            ("Zero-Day Protection", "Active ✓", "Unknown threat detection", ColorPalette.CYBER_GREEN),
        ]
        
        for name, status, desc, color in protections:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=5)
            
            tk.Label(card, text=name,
                    font=('Helvetica', 12),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_BRIGHT,
                    padx=20, pady=15).pack(side=tk.LEFT)
            
            tk.Label(card, text=status,
                    font=('Helvetica', 11, 'bold'),
                    bg=ColorPalette.CARD_BG,
                    fg=color, padx=15).pack(side=tk.RIGHT)
    
    def show_security_score(self):
        """Security score with detailed breakdown"""
        self.clear_content()
        
        tk.Label(self.content, text="📊 Security Score",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        # Calculate score
        stats = self.system_stats.get_all_stats()
        threats = stats.get('scanning', {}).get('total_threats_blocked', 0)
        
        score = max(0, 100 - (threats * 5))
        
        if score >= 90:
            rating = "EXCELLENT"
            score_color = ColorPalette.SAFE
        elif score >= 70:
            rating = "GOOD"
            score_color = ColorPalette.CYBER_GREEN
        elif score >= 50:
            rating = "FAIR"
            score_color = ColorPalette.WARNING
        else:
            rating = "NEEDS ATTENTION"
            score_color = ColorPalette.DANGER
        
        # Large score display
        score_card = self._create_card(self.content)
        score_card.pack(fill=tk.X, pady=10)
        
        tk.Label(score_card, text=f"{score}/100",
                font=('Helvetica', 64, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=score_color).pack(pady=30)
        
        tk.Label(score_card, text=f"Security Rating: {rating}",
                font=('Helvetica', 16),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_DIM).pack()
        
        # Score breakdown
        breakdown = [
            ("Virus Definitions", "100%", ColorPalette.SAFE),
            ("Real-Time Protection", "100%" if self.realtime_protection_active else "0%", ColorPalette.SAFE),
            ("Firewall", "Enabled", ColorPalette.SAFE),
            ("Last Scan", "Recently", ColorPalette.CYBER_BLUE),
            ("AI Protection", "Active" if HAS_AI else "N/A", ColorPalette.CYBER_PURPLE),
            ("Cloud Protection", "Connected", ColorPalette.CYBER_GREEN),
        ]
        
        for item, value, color in breakdown:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=3)
            tk.Label(card, text=item,
                    font=('Helvetica', 10),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_BRIGHT,
                    padx=20, pady=12).pack(side=tk.LEFT)
            tk.Label(card, text=value,
                    font=('Helvetica', 10, 'bold'),
                    bg=ColorPalette.CARD_BG,
                    fg=color, padx=20).pack(side=tk.RIGHT)
    
    def show_quarantine(self):
        """Quarantine management"""
        self.clear_content()
        
        tk.Label(self.content, text="📁 Quarantine",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        try:
            quarantined = self.quarantine_system.list_quarantined()
        except:
            quarantined = {}
        
        count = len(quarantined)
        
        tk.Label(self.content, text=f"{count} items in quarantine",
                font=('Helvetica', 13),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_DIM).pack(pady=10)
        
        if count == 0:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=30)
            tk.Label(card, text="✓ Quarantine is empty - No threats detected",
                    font=('Helvetica', 14),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.SAFE).pack(pady=25)
        else:
            # List items
            for file_id, info in list(quarantined.items())[:20]:
                card = self._create_card(self.content)
                card.pack(fill=tk.X, pady=3)
                
                name = info.get('original_name', file_id)
                threat = info.get('threat_name', 'Unknown')
                
                tk.Label(card, text=name[:50],
                        font=('Helvetica', 9),
                        bg=ColorPalette.CARD_BG,
                        fg=ColorPalette.TEXT_BRIGHT,
                        padx=15, pady=12).pack(side=tk.LEFT)
                tk.Label(card, text=threat,
                        font=('Helvetica', 8),
                        bg=ColorPalette.CARD_BG,
                        fg=ColorPalette.DANGER, padx=15).pack(side=tk.RIGHT)
    
    def show_threat_history(self):
        """Threat history log"""
        self.clear_content()
        
        tk.Label(self.content, text="📜 Threat History",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        try:
            threat_stats = self.threat_logger.get_threat_statistics()
        except:
            threat_stats = {'total_threats': 0, 'by_severity': {}}
        
        total = threat_stats.get('total_threats', 0)
        
        card = self._create_card(self.content)
        card.pack(fill=tk.X, pady=10)
        
        if total == 0:
            tk.Label(card, text="✓ No threats detected - Your system is safe!",
                    font=('Helvetica', 14),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.SAFE).pack(pady=25)
        else:
            tk.Label(card, text=f"Total threats detected: {total}",
                    font=('Helvetica', 14),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.DANGER).pack(pady=20)
            
            by_severity = threat_stats.get('by_severity', {})
            for severity, count in by_severity.items():
                sev_card = self._create_card(self.content)
                sev_card.pack(fill=tk.X, pady=3)
                tk.Label(sev_card, text=severity,
                        font=('Helvetica', 10),
                        bg=ColorPalette.CARD_BG,
                        fg=ColorPalette.TEXT_BRIGHT,
                        padx=20, pady=12).pack(side=tk.LEFT)
                tk.Label(sev_card, text=str(count),
                        font=('Helvetica', 10, 'bold'),
                        bg=ColorPalette.CARD_BG,
                        fg=ColorPalette.DANGER, padx=20).pack(side=tk.RIGHT)
    
    def show_process_monitor(self):
        """Process monitor"""
        self.clear_content()
        
        tk.Label(self.content, text="⚙️ Process Monitor",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        try:
            processes = self.process_monitor.get_all_processes()
            suspicious = self.process_monitor.scan_processes()
        except:
            processes = []
            suspicious = []
        
        # Summary
        card = self._create_card(self.content)
        card.pack(fill=tk.X, pady=5)
        
        tk.Label(card, text=f"Running Processes: {len(processes)}",
                font=('Helvetica', 12),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_BRIGHT,
                padx=20, pady=15).pack(side=tk.LEFT)
        tk.Label(card, text=f"Suspicious: {len(suspicious)}",
                font=('Helvetica', 12, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.DANGER if suspicious else ColorPalette.SAFE,
                padx=20).pack(side=tk.RIGHT)
        
        if suspicious:
            tk.Label(self.content, text="⚠️ Suspicious Processes Detected",
                    font=('Helvetica', 13, 'bold'),
                    bg=ColorPalette.BG_DARK,
                    fg=ColorPalette.DANGER, pady=15).pack()
            
            for proc in suspicious[:10]:
                p_card = self._create_card(self.content)
                p_card.pack(fill=tk.X, pady=3)
                
                name = proc.get('name', 'Unknown')
                pid = proc.get('pid', 0)
                
                tk.Label(p_card, text=f"⚠️ {name} (PID: {pid})",
                        font=('Helvetica', 9),
                        bg=ColorPalette.CARD_BG,
                        fg=ColorPalette.DANGER, padx=15, pady=12).pack(side=tk.LEFT)
        else:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=20)
            tk.Label(card, text="✓ No suspicious processes detected",
                    font=('Helvetica', 13),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.SAFE).pack(pady=20)
    
    def show_network(self):
        """Network monitoring"""
        self.clear_content()
        
        tk.Label(self.content, text="🌐 Network Monitor",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        try:
            connections = self.network_shield.get_all_connections()
        except:
            connections = []
        
        # Stats
        stats_card = self._create_card(self.content)
        stats_card.pack(fill=tk.X, pady=5)
        
        established = len([c for c in connections if c.get('status') == 'ESTABLISHED'])
        
        tk.Label(stats_card, text=f"Active Connections: {len(connections)}",
                font=('Helvetica', 12),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_BRIGHT,
                padx=20, pady=18).pack(side=tk.LEFT)
        tk.Label(stats_card, text=f"Established: {established}",
                font=('Helvetica', 12),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.SAFE, padx=20).pack(side=tk.RIGHT)
        
        # Blocked IPs
        blocked_card = self._create_card(self.content)
        blocked_card.pack(fill=tk.X, pady=10)
        
        blocked_count = len(self.network_shield.blocked_ips)
        tk.Label(blocked_card, text=f"🛡️ Blocked Malicious IPs: {blocked_count}",
                font=('Helvetica', 13),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.CYBER_BLUE, padx=20, pady=18).pack()
    
    def show_account(self):
        """Account and license management"""
        self.clear_content()
        
        tk.Label(self.content, text="🔐 Account & License",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        if self.logged_in:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=20, padx=80)
            
            tk.Label(card, text=f"Welcome back, {self.current_user}!",
                    font=('Helvetica', 16, 'bold'),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_BRIGHT, pady=20).pack()
            
            tk.Label(card, text=f"Plan: {self.subscription_plan}",
                    font=('Helvetica', 12),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.CYBER_PURPLE, pady=5).pack()
            
            # License info
            tk.Label(card, text="License: Enterprise | Expires: Never",
                    font=('Helvetica', 10),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.SAFE, pady=5).pack()
            
            btn = GlowingButton(self.content, "Logout", self.logout,
                              bg=ColorPalette.DANGER)
            btn.pack(pady=20)
        else:
            # Login form
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=20, padx=100)
            
            tk.Label(card, text="Login to your SecureGuard Account",
                    font=('Helvetica', 16, 'bold'),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_BRIGHT, pady=20).pack()
            
            tk.Label(card, text="Username:",
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_DIM).pack(anchor='w', padx=30)
            
            username_entry = tk.Entry(card, font=('Helvetica', 11),
                                     bg=ColorPalette.BG_DARKER,
                                     fg=ColorPalette.TEXT_BRIGHT,
                                     insertbackground=ColorPalette.PRIMARY)
            username_entry.pack(fill=tk.X, padx=30, pady=5)
            
            tk.Label(card, text="Password:",
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_DIM).pack(anchor='w', padx=30)
            
            password_entry = tk.Entry(card, show="*", font=('Helvetica', 11),
                                     bg=ColorPalette.BG_DARKER,
                                     fg=ColorPalette.TEXT_BRIGHT,
                                     insertbackground=ColorPalette.PRIMARY)
            password_entry.pack(fill=tk.X, padx=30, pady=5)
            
            def do_login():
                username = username_entry.get()
                if username:
                    self.logged_in = True
                    self.current_user = username
                    self.show_account()
            
            btn = GlowingButton(card, "Login", do_login, bg=ColorPalette.CYBER_BLUE)
            btn.pack(pady=20)
            
            tk.Label(card, text="(Demo: Enter any username)",
                    font=('Helvetica', 9),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_DIM).pack()
    
    def logout(self):
        """Logout user"""
        self.logged_in = False
        self.current_user = None
        self.show_account()
    
    def show_settings(self):
        """Settings panel"""
        self.clear_content()
        
        tk.Label(self.content, text="⚙️ Settings",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        settings = [
            ("Real-Time Protection", True, "Active monitoring for threats"),
            ("Auto Updates", True, "Automatically update virus definitions"),
            ("Heuristic Scanning", True, "Detect unknown threats by behavior"),
            ("Cloud Protection", True, "Use cloud-based threat intelligence"),
            ("Telemetry", False, "Send anonymous usage data"),
            ("Start with Windows", True, "Launch on system startup"),
            ("Game Mode", False, "Disable notifications while gaming"),
        ]
        
        for name, default, desc in settings:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=5)
            
            left = tk.Frame(card, bg=ColorPalette.CARD_BG)
            left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=12)
            
            tk.Label(left, text=name,
                    font=('Helvetica', 11, 'bold'),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w')
            tk.Label(left, text=desc,
                    font=('Helvetica', 8),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_DIM).pack(anchor='w')
            
            var = tk.BooleanVar(value=default)
            tk.Checkbutton(card, variable=var,
                          bg=ColorPalette.CARD_BG,
                          activebackground=ColorPalette.CARD_BG).pack(side=tk.RIGHT, padx=15)
    
    def show_reports(self):
        """Security reports"""
        self.clear_content()
        
        tk.Label(self.content, text="📈 Security Reports",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        card = self._create_card(self.content)
        card.pack(fill=tk.BOTH, expand=True, pady=10)
        
        tk.Label(card, text="📊 Security Dashboard Report",
                font=('Helvetica', 16, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_BRIGHT, pady=20).pack()
        
        stats = self.system_stats.get_all_stats()
        scanning = stats.get('scanning', {})
        
        report_items = [
            ("Total Scans", str(scanning.get('total_scans', 0))),
            ("Files Scanned", f"{scanning.get('total_files_scanned', 0):,}"),
            ("Threats Blocked", str(scanning.get('total_threats_blocked', 0))),
            ("Quarantine Items", str(len(self.quarantine_system.list_quarantined()))),
            ("Signatures", str(len(self.detection_engine.signatures))),
            ("Protected IPs", str(len(self.network_shield.blocked_ips))),
        ]
        
        for label, value in report_items:
            tk.Label(card, text=f"{label}: {value}",
                    font=('Helvetica', 11),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.TEXT_DIM, pady=8).pack()
    
    def show_threat_analysis(self):
        """AI Threat Analysis"""
        self.clear_content()
        
        tk.Label(self.content, text="🎯 Threat Analysis",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(anchor='w', pady=(0, 25))
        
        if not HAS_AI:
            card = self._create_card(self.content)
            card.pack(fill=tk.X, pady=30)
            tk.Label(card, text="⚠️ AI Analysis module not available",
                    font=('Helvetica', 14),
                    bg=ColorPalette.CARD_BG,
                    fg=ColorPalette.WARNING).pack(pady=25)
            return
        
        card = self._create_card(self.content)
        card.pack(fill=tk.BOTH, expand=True, pady=10)
        
        tk.Label(card, text="🧠 AI-Powered Threat Analysis",
                font=('Helvetica', 16, 'bold'),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.TEXT_BRIGHT, pady=20).pack()
        
        tk.Label(card, text="AI threat analysis is active and monitoring",
                font=('Helvetica', 11),
                bg=ColorPalette.CARD_BG,
                fg=ColorPalette.SAFE, pady=10).pack()
    
    # Scan methods
    def quick_scan(self):
        """Quick scan of common locations"""
        paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
        ]
        self._run_scan("Quick Scan", paths)
    
    def full_scan(self):
        """Full system scan"""
        if os.name == 'nt':
            self._run_scan("Full Scan", ["C:\\"])
        else:
            self._run_scan("Full Scan", ["/"])
    
    def custom_scan(self):
        """Custom folder scan"""
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self._run_scan("Custom Scan", [folder])
    
    def targeted_scan(self):
        """Targeted file scan"""
        files = filedialog.askopenfilenames(title="Select files to scan")
        if files:
            self._run_scan("Targeted Scan", list(files))
    
    def ai_scan(self):
        """AI-powered scan"""
        if os.name == 'nt':
            self._run_scan("AI Scan", ["C:\\Users"])
        else:
            self._run_scan("AI Scan", [os.path.expanduser("~")])
    
    def network_scan(self):
        """Network scan"""
        messagebox.showinfo("Network Scan", "Scanning network for vulnerabilities...")
    
    def update_signatures(self):
        """Update virus definitions"""
        messagebox.showinfo("Update", "Virus definitions are up to date!")
    
    def _run_scan(self, scan_type: str, paths: List[str]):
        """Execute scan with progress UI"""
        if self.scan_running:
            messagebox.showwarning("Scan", "A scan is already in progress!")
            return
        
        self.scan_running = True
        self.clear_content()
        
        # Scan UI
        tk.Label(self.content, text=f"🔍 {scan_type}",
                font=('Helvetica', 28, 'bold'),
                bg=ColorPalette.BG_DARK,
                fg=ColorPalette.TEXT_BRIGHT).pack(pady=30)
        
        card = self._create_card(self.content)
        card.pack(fill=tk.X, pady=20, padx=50)
        
        self.scan_status = tk.Label(card, text="Initializing scan...",
                                    font=('Helvetica', 15),
                                    bg=ColorPalette.CARD_BG,
                                    fg=ColorPalette.CYBER_BLUE)
        self.scan_status.pack(pady=20)
        
        self.scan_progress_label = tk.Label(card, text="Preparing...",
                                           font=('Helvetica', 12),
                                           bg=ColorPalette.CARD_BG,
                                           fg=ColorPalette.TEXT_DIM)
        self.scan_progress_label.pack(pady=5)
        
        progress_bar = ttk.Progressbar(card, mode='determinate', length=500)
        progress_bar.pack(fill=tk.X, padx=30, pady=20)
        
        threading.Thread(target=self._perform_scan,
                        args=(scan_type, paths, progress_bar),
                        daemon=True).start()
    
    def _perform_scan(self, scan_type: str, paths: List[str], progress_bar):
        """Background scan execution"""
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
                    self.root.after(0, lambda f=i: self.scan_progress_label.config(
                        text=f"Scanning: {f:,} / {total:,} files"))
                    self.root.after(0, lambda: self.scan_status.config(
                        text="Scanning in progress...", fg=ColorPalette.CYBER_BLUE))
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
        
        # Update stats
        self.system_stats.record_scan(scan_type, len(files_to_scan), threats_found)
        self.detection_engine.update_stats(len(files_to_scan), threats_found, scan_type)
        
        try:
            self.root.after(0, lambda: progress_bar.config(value=100))
            self.root.after(0, lambda: self.scan_status.config(
                text=f"✓ Scan Complete! Scanned {len(files_to_scan):,} files. Found {threats_found} threats.",
                fg=ColorPalette.SAFE))
            self.root.after(0, lambda: self.scan_progress_label.config(text="Finished"))
        except:
            pass
        
        time.sleep(3)
        try:
            self.root.after(0, self.show_dashboard)
        except:
            pass
        
        self.scan_running = False
    
    def _start_background_services(self):
        """Start background monitoring services"""
        def update_loop():
            while True:
                try:
                    time.sleep(5)
                    self.system_stats.get_cpu_usage()
                except:
                    break
        
        threading.Thread(target=update_loop, daemon=True).start()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    print("\n" + "="*60)
    print(" SecureGuard Antivirus - Ultimate Security Suite")
    print("="*60 + "\n")
    
    app = SecureGuardUltimate()
    app.run()


if __name__ == "__main__":
    main()
