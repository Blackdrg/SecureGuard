"""
SecureGuard Antivirus - Enterprise Futuristic Dashboard
=====================================================
Advanced visual elements:
- Threat Radar animation
- Live protection shield animation
- Security pulse meter
- Risk heat map
- Threat timeline chart
- Global Threat Map
- Threat DNA Visualization
- Animated Protection Stats
- Security Shield Animation
- Interactive Scan Visualizer
- Premium UI Effects (glassmorphism, glowing borders, etc.)
"""

import tkinter as tk
from tkinter import ttk
import math
import random
import time
import threading
import os
import sys
from datetime import datetime
from collections import deque

# Try to import PIL for advanced graphics
try:
    from PIL import Image, ImageDraw, ImageTk
    PIL_AVAILABLE = True
except:
    PIL_AVAILABLE = False


class ThreatRadarCanvas(tk.Canvas):
    """Animated Threat Radar Display"""
    
    def __init__(self, parent, width=300, height=300):
        super().__init__(parent, width=width, height=height, bg='#0a0e17', highlightthickness=0)
        self.width = width
        self.height = height
        self.center_x = width // 2
        self.center_y = height // 2
        self.radius = min(width, height) // 2 - 20
        
        self.blips = []
        self.radar_angle = 0
        self.is_animating = False
        
        self.draw_radar()
        self.start_animation()
        
    def draw_radar(self):
        """Draw radar circles and lines"""
        # Background circles
        for i in range(4):
            r = self.radius * (i + 1) // 4
            self.create_oval(
                self.center_x - r, self.center_y - r,
                self.center_x + r, self.center_y + r,
                outline='#1a3a5c', width=1
            )
        
        # Cross lines
        self.create_line(self.center_x, 20, self.center_x, self.height - 20, fill='#1a3a5c', width=1)
        self.create_line(20, self.center_y, self.width - 20, self.center_y, fill='#1a3a5c', width=1)
        
        # Diagonal lines
        self.create_line(
            self.center_x + self.radius * 0.707, self.center_y - self.radius * 0.707,
            self.center_x - self.radius * 0.707, self.center_y + self.radius * 0.707,
            fill='#1a3a5c', width=1
        )
        self.create_line(
            self.center_x - self.radius * 0.707, self.center_y - self.radius * 0.707,
            self.center_x + self.radius * 0.707, self.center_y + self.radius * 0.707,
            fill='#1a3a5c', width=1
        )
        
    def add_blip(self, x, y, threat_type='normal'):
        """Add a threat blip on radar"""
        color = {'normal': '#00ff88', 'warning': '#ffaa00', 'critical': '#ff3366'}.get(threat_type, '#00ff88')
        
        blip = self.create_oval(x-4, y-4, x+4, y+4, fill=color, outline='')
        self.blips.append({
            'id': blip,
            'x': x, 'y': y,
            'life': 100,
            'color': color
        })
        
    def animate(self):
        """Radar sweep animation"""
        if not self.is_animating:
            return
            
        # Draw sweep line
        angle_rad = math.radians(self.radar_angle)
        end_x = self.center_x + self.radius * math.cos(angle_rad)
        end_y = self.center_y + self.radius * math.sin(angle_rad)
        
        # Create gradient sweep
        self.create_line(
            self.center_x, self.center_y, end_x, end_y,
            fill='#00ff88', width=2
        )
        
        # Add random blips occasionally
        if random.random() < 0.1:
            blip_angle = random.uniform(0, 360)
            blip_dist = random.uniform(20, self.radius - 10)
            bx = self.center_x + blip_dist * math.cos(math.radians(blip_angle))
            by = self.center_y + blip_dist * math.sin(math.radians(blip_angle))
            threat = random.choice(['normal', 'normal', 'warning', 'critical'])
            self.add_blip(bx, by, threat)
        
        # Update blips
        for blip in self.blips[:]:
            blip['life'] -= 2
            if blip['life'] <= 0:
                self.delete(blip['id'])
                self.blips.remove(blip)
            else:
                alpha = blip['life'] / 100
                self.itemconfig(blip['id'], fill=blip['color'])
        
        self.radar_angle = (self.radar_angle + 3) % 360
        self.after(50, self.animate)
        
    def start_animation(self):
        """Start radar animation"""
        self.is_animating = True
        self.animate()
        
    def stop_animation(self):
        """Stop radar animation"""
        self.is_animating = False


class ShieldAnimation(tk.Canvas):
    """Animated Protection Shield"""
    
    def __init__(self, parent, width=200, height=250):
        super().__init__(parent, width=width, height=height, bg='#0a0e17', highlightthickness=0)
        self.width = width
        self.height = height
        self.state = 'safe'  # safe, warning, danger
        self.pulse_phase = 0
        self.is_animating = False
        
        self.shield_points = [
            (100, 20),   # Top
            (170, 60),   # Right top
            (160, 180),  # Right bottom
            (100, 230),  # Bottom
            (40, 180),   # Left bottom
            (30, 60),    # Left top
        ]
        
        self.draw_shield()
        self.start_pulse()
        
    def draw_shield(self, glow_color=None):
        """Draw shield shape"""
        self.delete('shield')
        
        # Get colors based on state
        colors = {
            'safe': ('#00ff88', '#003322'),
            'warning': ('#ffaa00', '#332200'),
            'danger': ('#ff3366', '#330011')
        }
        main_color, dark_color = colors.get(self.state, colors['safe'])
        
        if glow_color is None:
            glow_color = main_color
            
        # Draw glow effect
        for i in range(5, 0, -1):
            points = []
            for x, y in self.shield_points:
                cx, cy = 100, 125
                dx, dy = x - cx, y - cy
                scale = 1 + i * 0.08
                points.append((cx + dx * scale, cy + dy * scale))
            
            alpha = int(255 * (1 - i/6) * 0.3)
            color = glow_color
            self.create_polygon(points, fill='', outline=color, width=2,
                              tags='shield')
        
        # Draw main shield
        self.create_polygon(self.shield_points, fill=dark_color, 
                          outline=main_color, width=3, tags='shield')
        
        # Draw inner shine
        inner_points = [(100, 35)] + self.shield_points[1:5] + [(100, 210)]
        self.create_line(55, 75, 85, 120, fill=main_color, width=2, tags='shield')
        
    def set_state(self, state):
        """Set shield state"""
        self.state = state
        self.draw_shield()
        
    def animate_pulse(self):
        """Pulse animation"""
        if not self.is_animating:
            return
            
        self.pulse_phase += 0.1
        pulse = math.sin(self.pulse_phase) * 0.3 + 0.7
        
        colors = {'safe': '#00ff88', 'warning': '#ffaa00', 'danger': '#ff3366'}
        color = colors.get(self.state, '#00ff88')
        
        # Redraw with pulse
        self.draw_shield()
        
        # Pulse glow
        if pulse > 0.8:
            self.draw_shield(color)
        
        self.after(50, self.animate_pulse)
        
    def start_pulse(self):
        """Start pulse animation"""
        self.is_animating = True
        self.animate_pulse()


class SecurityPulseMeter(tk.Frame):
    """Security Pulse Meter with animated gauge"""
    
    def __init__(self, parent):
        super().__init__(parent, bg='#0a0e17')
        
        self.value = 85
        self.max_value = 100
        
        # Create canvas
        self.canvas = tk.Canvas(self, width=200, height=120, bg='#0a0e17', highlightthickness=0)
        self.canvas.pack()
        
        self.draw_meter()
        
    def draw_meter(self):
        """Draw pulse meter"""
        # Background arc
        self.canvas.create_arc(20, 20, 180, 100, start=180, extent=180,
                             fill='', outline='#1a3a5c', width=15, style=tk.ARC)
        
        # Value arc
        extent = (self.value / self.max_value) * 180
        color = self.get_color_for_value(self.value)
        
        self.canvas.create_arc(20, 20, 180, 100, start=180, extent=extent,
                             fill='', outline=color, width=15, style=tk.ARC)
        
        # Center text
        self.canvas.create_text(100, 70, text=f"{self.value}%", 
                              fill=color, font=('Segoe UI', 24, 'bold'))
        self.canvas.create_text(100, 90, text="Security Score",
                              fill='#6B7C93', font=('Segoe UI', 10))
        
    def get_color_for_value(self, value):
        """Get color based on value"""
        if value >= 80:
            return '#00ff88'
        elif value >= 60:
            return '#ffaa00'
        else:
            return '#ff3366'
            
    def set_value(self, value):
        """Set meter value"""
        self.value = value
        self.canvas.delete('all')
        self.draw_meter()


class AnimatedStatsCounter(tk.Frame):
    """Animated real-time statistics"""
    
    def __init__(self, parent):
        super().__init__(parent, bg='#0a0e17')
        
        self.stats = {
            'files_scanned': 0,
            'threats_blocked': 0,
            'processes_monitored': 0,
            'connections_secured': 0
        }
        
        self.targets = dict(self.stats)
        
        self.create_widgets()
        self.start_counter()
        
    def create_widgets(self):
        """Create stat displays"""
        self.labels = {}
        
        for i, (stat, value) in enumerate(self.stats.items()):
            frame = tk.Frame(self, bg='#0a0e17')
            frame.pack(fill=tk.X, pady=5)
            
            # Icon
            icons = {'files_scanned': '📁', 'threats_blocked': '🛡️', 
                    'processes_monitored': '⚙️', 'connections_secured': '🌐'}
            icon_label = tk.Label(frame, text=icons.get(stat, '•'), 
                                 bg='#0a0e17', font=('Segoe UI', 16))
            icon_label.pack(side=tk.LEFT, padx=10)
            
            # Value
            value_label = tk.Label(frame, text=f"{value:,}", 
                                  bg='#0a0e17', fg='#00ff88',
                                  font=('Segoe UI', 20, 'bold'))
            value_label.pack(side=tk.LEFT)
            
            # Name
            name = stat.replace('_', ' ').title()
            name_label = tk.Label(frame, text=name, 
                                 bg='#0a0e17', fg='#6B7C93',
                                 font=('Segoe UI', 10))
            name_label.pack(side=tk.LEFT, padx=10)
            
            self.labels[stat] = value_label
            
    def start_counter(self):
        """Start animated counter"""
        def update():
            # Increment counters
            self.targets['files_scanned'] += random.randint(1, 5)
            self.targets['threats_blocked'] += random.randint(0, 2)
            self.targets['processes_monitored'] = random.randint(80, 150)
            self.targets['connections_secured'] = random.randint(500, 2000)
            
            # Smooth animation
            for stat in self.stats:
                diff = self.targets[stat] - self.stats[stat]
                if diff != 0:
                    step = max(1, int(diff / 10))
                    self.stats[stat] += step
                    self.labels[stat].config(text=f"{self.stats[stat]:,}")
                    
            self.after(500, update)
            
        update()


class ThreatTimeline(tk.Frame):
    """Threat Timeline Chart"""
    
    def __init__(self, parent):
        super().__init__(parent, bg='#0a0e17')
        
        self.canvas = tk.Canvas(self, width=500, height=150, bg='#0a0e17', highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        self.data = deque([0] * 20, maxlen=20)
        self.start_chart()
        
    def start_chart(self):
        """Start chart animation"""
        def update():
            # Add new data point
            new_value = random.randint(0, 30)
            self.data.append(new_value)
            
            # Redraw chart
            self.canvas.delete('all')
            
            width = 500
            height = 150
            padding = 30
            
            # Draw grid
            for i in range(5):
                y = padding + (height - 2*padding) * i // 4
                self.canvas.create_line(padding, y, width - padding, y, 
                                       fill='#1a3a5c', width=1)
            
            # Draw line chart
            points = []
            for i, val in enumerate(self.data):
                x = padding + (width - 2*padding) * i // (len(self.data) - 1)
                y = height - padding - (height - 2*padding) * val // 30
                points.append((x, y))
                
            if len(points) > 1:
                for j in range(len(points) - 1):
                    color = '#ff3366' if points[j+1][1] < height * 0.3 else '#00ff88'
                    self.canvas.create_line(points[j], points[j+1], 
                                           fill=color, width=2)
                    
            # Draw dots
            for x, y in points:
                self.canvas.create_oval(x-3, y-3, x+3, y+3, fill='#00ff88', outline='')
                
            self.after(1000, update)
            
        update()


class GlobalThreatMap(tk.Canvas):
    """Global Threat Map showing worldwide attacks"""
    
    def __init__(self, parent, width=600, height=300):
        super().__init__(parent, width=width, height=height, bg='#0a0e17', highlightthickness=0)
        self.width = width
        self.height = height
        
        # Country positions (simplified world map)
        self.countries = {
            'USA': (150, 100), 'China': (500, 100), 'Russia': (480, 70),
            'Brazil': (250, 220), 'India': (520, 130), 'Germany': (400, 80),
            'UK': (370, 75), 'France': (390, 90), 'Japan': (560, 110),
            'Australia': (550, 250), 'South Africa': (450, 280)
        }
        
        self.draw_map()
        self.start_attacks()
        
    def draw_map(self):
        """Draw simplified world map"""
        # Draw country dots
        for country, (x, y) in self.countries.items():
            self.create_oval(x-8, y-8, x+8, y+8, fill='#1a3a5c', outline='#2a4a6c')
            self.create_text(x, y+15, text=country, fill='#6B7C93', font=('Segoe UI', 8))
            
    def start_attacks(self):
        """Simulate global attacks"""
        def attack():
            # Pick random source and target
            sources = list(self.countries.keys())
            source = random.choice(sources)
            target = random.choice([c for c in sources if c != source])
            
            sx, sy = self.countries[source]
            tx, ty = self.countries[target]
            
            # Draw attack line
            line = self.create_line(sx, sy, tx, ty, fill='#ff3366', width=2)
            
            # Wait and delete
            self.after(500)
            self.delete(line)
            
            # Schedule next attack
            self.after(random.randint(500, 2000), attack)
            
        attack()


class ThreatDNAVisualization(tk.Frame):
    """Threat DNA Visualization"""
    
    def __init__(self, parent):
        super().__init__(parent, bg='#0a0e17')
        
        self.canvas = tk.Canvas(self, width=400, height=200, bg='#0a0e17', highlightthickness=0)
        self.canvas.pack()
        
        self.dna_strands = []
        self.phase = 0
        
        self.draw_dna()
        self.animate_dna()
        
    def draw_dna(self):
        """Draw DNA helix"""
        self.canvas.delete('all')
        
        width = 400
        height = 200
        center_x = width // 2
        
        # Draw DNA strands
        for i in range(40):
            x = 20 + i * 9
            offset = math.sin(self.phase + i * 0.3) * 30
            
            # Strand 1
            y1 = height // 2 + offset
            # Strand 2
            y2 = height // 2 - offset
            
            # Draw base pairs
            if i % 4 == 0:
                color = random.choice(['#00ff88', '#00aaff', '#ffaa00', '#ff3366'])
                self.canvas.create_line(x, y1, x, y2, fill=color, width=3)
                
            # Draw backbone dots
            self.canvas.create_oval(x-3, y1-3, x+3, y1+3, fill='#00ff88', outline='')
            self.canvas.create_oval(x-3, y2-3, x+3, y2+3, fill='#00aaff', outline='')
            
        # Labels
        self.canvas.create_text(30, 15, text="Threat DNA", fill='#6B7C93', font=('Segoe UI', 10))
        
    def animate_dna(self):
        """Animate DNA rotation"""
        self.phase += 0.1
        self.draw_dna()
        self.after(50, self.animate_dna)


class ScanVisualizer(tk.Frame):
    """Interactive Scan Visualizer"""
    
    def __init__(self, parent):
        super().__init__(parent, bg='#0a0e17')
        
        self.is_scanning = False
        
        # Progress ring
        self.canvas = tk.Canvas(self, width=150, height=150, bg='#0a0e17', highlightthickness=0)
        self.canvas.pack(pady=10)
        
        # Current file
        self.file_label = tk.Label(self, text="Ready to scan", 
                                   bg='#0a0e17', fg='#6B7C93',
                                   font=('Segoe UI', 10))
        self.file_label.pack()
        
        # Progress text
        self.progress_label = tk.Label(self, text="0%", 
                                       bg='#0a0e17', fg='#00ff88',
                                       font=('Segoe UI', 24, 'bold'))
        self.progress_label.pack()
        
        self.progress = 0
        self.files_scanned = 0
        
        self.draw_ring()
        
    def draw_ring(self):
        """Draw progress ring"""
        self.canvas.delete('all')
        
        cx, cy = 75, 75
        radius = 60
        
        # Background ring
        self.canvas.create_arc(cx-radius, cy-radius, cx+radius, cy+radius,
                             start=0, extent=360, fill='', outline='#1a3a5c', width=10)
        
        # Progress arc
        extent = (self.progress / 100) * 360
        color = '#00ff88' if self.progress < 80 else '#ffaa00' if self.progress < 95 else '#ff3366'
        self.canvas.create_arc(cx-radius, cy-radius, cx+radius, cy+radius,
                             start=-90, extent=extent, fill='', outline=color, width=10)
        
        # Center icon
        icon = '🛡️' if self.progress < 100 else '✓'
        self.canvas.create_text(cx, cy, text=icon, font=('Segoe UI', 30))
        
    def start_scan(self):
        """Start scan visualization"""
        self.is_scanning = True
        self.scan_files = [
            'C:\\Windows\\System32\\*.dll',
            'C:\\Program Files\\*.exe',
            'C:\\Users\\*\\AppData\\*.tmp',
            'C:\\Windows\\SysWOW64\\*.sys'
        ]
        self.current_file_index = 0
        self.scan_file()
        
    def scan_file(self):
        """Simulate scanning a file"""
        if not self.is_scanning or self.progress >= 100:
            return
            
        # Update progress
        self.progress += random.uniform(1, 3)
        self.files_scanned += 1
        
        # Update file being scanned
        if self.current_file_index < len(self.scan_files):
            self.file_label.config(text=self.scan_files[self.current_file_index])
            self.current_file_index += 1
            
        self.progress_label.config(text=f"{int(self.progress)}%")
        self.draw_ring()
        
        if self.progress < 100:
            self.after(100, self.scan_file)
        else:
            self.is_scanning = False
            self.file_label.config(text="Scan Complete!")
            
    def stop_scan(self):
        """Stop scan"""
        self.is_scanning = False


class GlassmorphicPanel(tk.Frame):
    """Glassmorphic styled panel"""
    
    def __init__(self, parent, border_color='#00ff88'):
        super().__init__(parent, bg='#0a0e17')
        
        self.border_color = border_color
        
        # Create glow effect with borders
        for i in range(3):
            self.config(bg=border_color)
            inner = tk.Frame(self, bg='#0a0e17', bd=2, relief=tk.RAISED)
            inner.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)


class FuturisticDashboard(tk.Tk):
    """Main Futuristic Dashboard Window"""
    
    def __init__(self):
        super().__init__()
        
        self.title("SecureGuard Enterprise Dashboard")
        self.geometry("1400x900")
        self.configure(bg='#0a0e17')
        
        # Configure styles
        self.setup_styles()
        
        # Create main layout
        self.create_layout()
        
        # Center window
        self.center_window()
        
    def setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook style
        style.configure('Dark.TNotebook', background='#0a0e17', 
                       tabposition='n', borderwidth=0)
        style.configure('Dark.TNotebook.Tab', background='#1a2a3c', 
                       foreground='#6B7C93', padding=[15, 8], borderwidth=0)
        style.map('Dark.TNotebook.Tab', background=[('selected', '#0a0e17')],
                 foreground=[('selected', '#00ff88')])
        
    def create_layout(self):
        """Create main layout"""
        # Title bar
        title_frame = tk.Frame(self, bg='#0a0e17', height=60)
        title_frame.pack(fill=tk.X, side=tk.TOP)
        title_frame.pack_propagate(False)
        
        # Logo and title
        logo = tk.Label(title_frame, text='🛡️', font=('Segoe UI', 28), 
                       bg='#0a0e17', fg='#00ff88')
        logo.pack(side=tk.LEFT, padx=20)
        
        title = tk.Label(title_frame, text='SecureGuard Enterprise', 
                        font=('Segoe UI', 20, 'bold'), bg='#0a0e17', fg='#ffffff')
        title.pack(side=tk.LEFT)
        
        subtitle = tk.Label(title_frame, text='Advanced Threat Protection', 
                          font=('Segoe UI', 10), bg='#0a0e17', fg='#6B7C93')
        subtitle.pack(side=tk.LEFT, padx=10)
        
        # Time
        self.time_label = tk.Label(title_frame, text='', font=('Segoe UI', 12),
                                   bg='#0a0e17', fg='#00ff88')
        self.time_label.pack(side=tk.RIGHT, padx=20)
        self.update_time()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self, style='Dark.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_radar_tab()
        self.create_threats_tab()
        self.create_scan_tab()
        
    def create_dashboard_tab(self):
        """Create main dashboard tab"""
        frame = tk.Frame(self.notebook, bg='#0a0e17')
        self.notebook.add(frame, text='  Dashboard  ')
        
        # Left panel - Shield and Stats
        left_panel = tk.Frame(frame, bg='#0a0e17')
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10)
        
        # Shield
        shield = ShieldAnimation(left_panel, width=200, height=250)
        shield.pack(pady=10)
        
        # Pulse meter
        pulse = SecurityPulseMeter(left_panel)
        pulse.pack(pady=10)
        
        # Center panel - Main displays
        center_panel = tk.Frame(frame, bg='#0a0e17')
        center_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Threat Timeline
        timeline = ThreatTimeline(center_panel)
        timeline.pack(fill=tk.X, pady=10)
        
        # Animated Stats
        stats = AnimatedStatsCounter(center_panel)
        stats.pack(fill=tk.X, pady=10)
        
        # Right panel - Radar and Map
        right_panel = tk.Frame(frame, bg='#0a0e17')
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)
        
        # Radar
        radar_label = tk.Label(right_panel, text="Threat Radar", 
                              bg='#0a0e17', fg='#6B7C93', font=('Segoe UI', 12))
        radar_label.pack()
        radar = ThreatRadarCanvas(right_panel, width=300, height=300)
        radar.pack(pady=10)
        
    def create_radar_tab(self):
        """Create radar tab"""
        frame = tk.Frame(self.notebook, bg='#0a0e17')
        self.notebook.add(frame, text='  Radar  ')
        
        # Large radar
        radar = ThreatRadarCanvas(frame, width=600, height=600)
        radar.pack(pady=20)
        
    def create_threats_tab(self):
        """Create threats tab"""
        frame = tk.Frame(self.notebook, bg='#0a0e17')
        self.notebook.add(frame, text='  Threats  ')
        
        # Global Threat Map
        map_label = tk.Label(frame, text="Global Threat Activity", 
                            bg='#0a0e17', fg='#6B7C93', font=('Segoe UI', 14))
        map_label.pack(pady=10)
        
        threat_map = GlobalThreatMap(frame, width=800, height=400)
        threat_map.pack(pady=10)
        
        # DNA Visualization
        dna_label = tk.Label(frame, text="Threat DNA Analysis", 
                            bg='#0a0e17', fg='#6B7C93', font=('Segoe UI', 14))
        dna_label.pack(pady=10)
        
        dna = ThreatDNAVisualization(frame)
        dna.pack(pady=10)
        
    def create_scan_tab(self):
        """Create scan tab"""
        frame = tk.Frame(self.notebook, bg='#0a0e17')
        self.notebook.add(frame, text='  Scanner  ')
        
        # Scan Visualizer
        scan_viz = ScanVisualizer(frame)
        scan_viz.pack(pady=50)
        
        # Scan buttons
        btn_frame = tk.Frame(frame, bg='#0a0e17')
        btn_frame.pack(pady=20)
        
        scan_btn = tk.Button(btn_frame, text="🚀 Start Scan", 
                            bg='#00ff88', fg='#0a0e17',
                            font=('Segoe UI', 14, 'bold'),
                            padx=30, pady=10,
                            command=scan_viz.start_scan)
        scan_btn.pack(side=tk.LEFT, padx=10)
        
        stop_btn = tk.Button(btn_frame, text="⏹ Stop", 
                            bg='#ff3366', fg='#ffffff',
                            font=('Segoe UI', 14, 'bold'),
                            padx=30, pady=10,
                            command=scan_viz.stop_scan)
        stop_btn.pack(side=tk.LEFT, padx=10)
        
    def update_time(self):
        """Update time display"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=now)
        self.after(1000, self.update_time)
        
    def center_window(self):
        """Center window on screen"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')


def run_dashboard():
    """Run the futuristic dashboard"""
    app = FuturisticDashboard()
    app.mainloop()


if __name__ == '__main__':
    run_dashboard()
