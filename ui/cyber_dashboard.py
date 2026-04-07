"""
SecureGuard Antivirus - Cyber Dashboard Enhanced
==============================================
Advanced visual elements with enhanced colors and graphics:
- Animated Cyber Shield with particle effects
- Matrix-style threat rain background
- Neon glowing borders
- Real-time CPU/Memory/Network graphs
- Cyberpunk-style status indicators
- Interactive 3D-like effects
- Aurora gradient backgrounds
- Holographic panels
"""

import tkinter as tk
from tkinter import ttk
import math
import random
import time
import threading
from datetime import datetime
from collections import deque

# Color Palette - Cyberpunk Theme
COLORS = {
    'bg_dark': '#0a0a12',
    'bg_medium': '#12121f',
    'bg_light': '#1a1a2e',
    'cyan': '#00fff5',
    'cyan_dark': '#00b8b8',
    'magenta': '#ff00ff',
    'magenta_dark': '#b800b8',
    'purple': '#9d00ff',
    'green': '#00ff88',
    'green_dark': '#00cc66',
    'red': '#ff3366',
    'orange': '#ff9500',
    'yellow': '#ffd500',
    'blue': '#0088ff',
    'white': '#ffffff',
    'gray': '#6B7C93',
    'grid': '#1a2a3c'
}


class ParticleSystem:
    """Particle effects for background"""
    def __init__(self, canvas, count=50):
        self.canvas = canvas
        self.particles = []
        self.count = count
        self.width = 400
        self.height = 300
        
    def create_particles(self):
        """Initialize particles"""
        for _ in range(self.count):
            self.particles.append({
                'x': random.randint(0, self.width),
                'y': random.randint(0, self.height),
                'vx': random.uniform(-0.5, 0.5),
                'vy': random.uniform(-0.5, 0.5),
                'size': random.randint(1, 3),
                'color': random.choice([COLORS['cyan'], COLORS['magenta'], COLORS['purple']])
            })
    
    def update(self):
        """Update particle positions"""
        for p in self.particles:
            p['x'] += p['vx']
            p['y'] += p['vy']
            
            # Wrap around
            if p['x'] < 0: p['x'] = self.width
            if p['x'] > self.width: p['x'] = 0
            if p['y'] < 0: p['y'] = self.height
            if p['y'] > self.height: p['y'] = 0


class CyberShield(tk.Canvas):
    """Enhanced Cyber Shield with glow effects"""
    
    def __init__(self, parent, width=250, height=300):
        super().__init__(parent, width=width, height=height, bg=COLORS['bg_dark'], highlightthickness=0)
        self.width = width
        self.height = height
        self.center_x = width // 2
        self.center_y = height // 2
        self.phase = 0
        self.particles = []
        
        # Initialize particle system
        for _ in range(30):
            self.particles.append({
                'angle': random.uniform(0, 360),
                'dist': random.uniform(40, 100),
                'speed': random.uniform(0.5, 2),
                'size': random.randint(2, 4)
            })
        
        self.draw_shield()
        self.animate()
        
    def draw_shield(self):
        """Draw cyber shield with multiple layers"""
        self.delete('all')
        
        # Background glow
        for i in range(5, 0, -1):
            r = 80 + i * 15
            color = self.hex_to_rgba(COLORS['cyan'], (6-i)/20)
            self.create_oval(
                self.center_x - r, self.center_y - r,
                self.center_x + r, self.center_y + r,
                outline=color, width=3
            )
        
        # Outer ring with rotation
        self.draw_rotating_ring(100, COLORS['cyan'], 3)
        
        # Inner shield shape
        points = self.get_shield_points(80)
        self.create_polygon(points, fill=self.hex_to_rgba(COLORS['cyan'], 0.1),
                          outline=COLORS['cyan'], width=3)
        
        # Inner details
        self.draw_shield_details(60)
        
        # Orbiting particles
        self.draw_particles()
        
        # Center icon
        self.create_text(self.center_x, self.center_y, text='🛡️',
                        font=('Segoe UI', 36), fill=COLORS['cyan'])
        
        # Status text
        status = "PROTECTED" if random.random() > 0.1 else "SCANNING"
        self.create_text(self.center_x, self.center_y + 50,
                        text=status, font=('Consolas', 12, 'bold'),
                        fill=COLORS['green'])
    
    def get_shield_points(self, size):
        """Get shield polygon points"""
        cx, cy = self.center_x, self.center_y
        return [
            (cx, cy - size),           # Top
            (cx + size * 0.8, cy - size * 0.3),  # Right top
            (cx + size * 0.6, cy + size * 0.8),  # Right bottom
            (cx, cy + size),           # Bottom
            (cx - size * 0.6, cy + size * 0.8),  # Left bottom
            (cx - size * 0.8, cy - size * 0.3),  # Left top
        ]
    
    def draw_rotating_ring(self, radius, color, width):
        """Draw rotating dashed ring"""
        segments = 12
        for i in range(segments):
            angle1 = math.radians(self.phase + i * (360/segments))
            angle2 = math.radians(self.phase + (i + 0.5) * (360/segments))
            
            x1 = self.center_x + radius * math.cos(angle1)
            y1 = self.center_y + radius * math.sin(angle1)
            x2 = self.center_x + radius * math.cos(angle2)
            y2 = self.center_y + radius * math.sin(angle2)
            
            self.create_line(x1, y1, x2, y2, fill=color, width=width)
    
    def draw_shield_details(self, radius):
        """Draw inner shield details"""
        # Inner circle
        self.create_oval(
            self.center_x - radius//2, self.center_y - radius//2,
            self.center_x + radius//2, self.center_y + radius//2,
            outline=COLORS['cyan_dark'], width=1
        )
        
        # Cross lines
        self.create_line(self.center_x - radius, self.center_y,
                        self.center_x + radius, self.center_y,
                        fill=COLORS['cyan_dark'], width=1)
        self.create_line(self.center_x, self.center_y - radius,
                        self.center_x, self.center_y + radius,
                        fill=COLORS['cyan_dark'], width=1)
    
    def draw_particles(self):
        """Draw orbiting particles"""
        for p in self.particles:
            angle = math.radians(p['angle'] + self.phase * p['speed'])
            dist = p['dist']
            x = self.center_x + dist * math.cos(angle)
            y = self.center_y + dist * math.sin(angle)
            
            color = random.choice([COLORS['cyan'], COLORS['magenta'], COLORS['purple']])
            self.create_oval(x-p['size'], y-p['size'], x+p['size'], y+p['size'],
                           fill=color, outline='')
    
    def hex_to_rgba(self, hex_color, alpha):
        """Convert hex to rgba"""
        r = int(hex_color[1:3], 16)
        g = int(hex_color[3:5], 16)
        b = int(hex_color[5:7], 16)
        return f'#{int(r*alpha):02x}{int(g*alpha):02x}{int(b*alpha):02x}'
    
    def animate(self):
        """Animation loop"""
        self.phase = (self.phase + 2) % 360
        self.draw_shield()
        self.after(30, self.animate)


class NeonGraph(tk.Frame):
    """Real-time neon graph for system stats"""
    
    def __init__(self, parent, width=300, height=120, title="CPU", color=None):
        super().__init__(parent, bg=COLORS['bg_dark'])
        self.width = width
        self.height = height
        self.title = title
        self.color = color or COLORS['cyan']
        
        self.data = deque([0] * 30, maxlen=30)
        
        # Canvas
        self.canvas = tk.Canvas(self, width=width, height=height, 
                              bg=COLORS['bg_dark'], highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        # Start animation
        self.animate()
    
    def add_value(self, value):
        """Add new data point"""
        self.data.append(value)
    
    def animate(self):
        """Draw graph"""
        self.canvas.delete('all')
        
        # Background grid
        for i in range(5):
            y = self.height * i // 4
            self.canvas.create_line(0, y, self.width, y, 
                                   fill=COLORS['grid'], width=1)
        
        # Draw gradient fill
        points = [0, self.height]
        for i, val in enumerate(self.data):
            x = i * self.width / (len(self.data) - 1)
            y = self.height - (val / 100) * self.height
            points.extend([x, y])
        points.extend([self.width, self.height])
        
        # Create gradient effect
        self.canvas.create_polygon(points, fill=self.hex_to_rgba(self.color, 0.2), outline='')
        
        # Draw line
        for i in range(len(self.data) - 1):
            x1 = i * self.width / (len(self.data) - 1)
            x2 = (i + 1) * self.width / (len(self.data) - 1)
            y1 = self.height - (self.data[i] / 100) * self.height
            y2 = self.height - (self.data[i+1] / 100) * self.height
            
            self.canvas.create_line(x1, y1, x2, y2, fill=self.color, width=2)
        
        # Draw glow dots
        for i, val in enumerate(self.data):
            x = i * self.width / (len(self.data) - 1)
            y = self.height - (val / 100) * self.height
            self.canvas.create_oval(x-3, y-3, x+3, y+3, fill=self.color, outline='')
        
        # Title
        current = self.data[-1] if self.data else 0
        self.canvas.create_text(10, 15, text=f"{self.title}: {current:.1f}%",
                              fill=self.color, font=('Consolas', 10, 'bold'),
                              anchor=tk.W)
        
        # Update with new value
        self.data.append(random.uniform(20, 80))
        
        self.after(500, self.animate)
    
    def hex_to_rgba(self, hex_color, alpha):
        """Convert hex to rgba"""
        r = int(hex_color[1:3], 16)
        g = int(hex_color[3:5], 16)
        b = int(hex_color[5:7], 16)
        return f'#{int(r*alpha):02x}{int(g*alpha):02x}{int(b*alpha):02x}'


class MatrixRain(tk.Canvas):
    """Matrix rain background effect"""
    
    def __init__(self, parent, width=200, height=200):
        super().__init__(parent, width=width, height=height, 
                       bg=COLORS['bg_dark'], highlightthickness=0)
        self.width = width
        self.height = height
        self.chars = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF"
        self.columns = width // 15
        self.drops = [random.randint(-100, 0) for _ in range(self.columns)]
        
        self.animate()
    
    def animate(self):
        """Matrix rain animation"""
        self.delete('all')
        
        for i in range(len(self.drops)):
            char = random.choice(self.chars)
            y = self.drops[i] * 15
            
            # Gradient color based on position
            color = COLORS['green'] if y < self.height / 3 else COLORS['green_dark']
            
            self.create_text(i * 15, y, text=char, fill=color, font=('Consolas', 10))
            
            # Reset drop
            if y > self.height and random.random() > 0.975:
                self.drops[i] = 0
            
            self.drops[i] += 1
        
        self.after(50, self.animate)


class CyberButton(tk.Button):
    """Neon-styled button"""
    
    def __init__(self, parent, text, command, color=COLORS['cyan'], **kwargs):
        super().__init__(parent, text=text, command=command,
                        bg=COLORS['bg_medium'], fg=color,
                        font=('Consolas', 12, 'bold'),
                        bd=2, relief=tk.RAISED,
                        padx=20, pady=10, **kwargs)
        
        self.color = color
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
    
    def on_enter(self, event):
        self.config(bg=COLORS['bg_light'], relief=tk.SUNKEN)
    
    def on_leave(self, event):
        self.config(bg=COLORS['bg_medium'], relief=tk.RAISED)


class NeonProgress(tk.Frame):
    """Neon progress bar with glow"""
    
    def __init__(self, parent, width=400, height=30):
        super().__init__(parent, bg=COLORS['bg_dark'])
        self.width = width
        self.height = height
        self.value = 0
        
        self.canvas = tk.Canvas(self, width=width, height=height,
                              bg=COLORS['bg_dark'], highlightthickness=0)
        self.canvas.pack()
        
        self.animate()
    
    def set_value(self, value):
        """Set progress value"""
        self.value = min(100, max(0, value))
    
    def animate(self):
        """Draw progress"""
        self.canvas.delete('all')
        
        # Background
        self.canvas.create_rounded_rectangle(0, 0, self.width, self.height, 
                                           fill=COLORS['bg_medium'], radius=15)
        
        # Progress
        if self.value > 0:
            prog_width = (self.value / 100) * (self.width - 6)
            color = COLORS['green'] if self.value < 70 else COLORS['orange'] if self.value < 90 else COLORS['red']
            
            # Glow effect
            for i in range(3, 0, -1):
                self.canvas.create_rounded_rectangle(3, 3, prog_width + i*2, self.height - 3,
                                                   fill=self.hex_to_rgba(color, 0.3), radius=15)
            
            # Main bar
            self.canvas.create_rounded_rectangle(3, 3, prog_width, self.height - 3,
                                               fill=color, radius=15)
        
        # Text
        self.canvas.create_text(self.width//2, self.height//2,
                              text=f"{int(self.value)}%",
                              fill=COLORS['white'], font=('Consolas', 12, 'bold'))
        
        self.after(100, self.animate)
    
    def hex_to_rgba(self, hex_color, alpha):
        r = int(hex_color[1:3], 16)
        g = int(hex_color[3:5], 16)
        b = int(hex_color[5:7], 16)
        return f'#{int(r*alpha):02x}{int(g*alpha):02x}{int(b*alpha):02x}'


class CyberDashboard(tk.Tk):
    """Main Cyber Dashboard"""
    
    def __init__(self):
        super().__init__()
        
        self.title("SecureGuard - Cyber Defense Center")
        self.geometry("1600x1000")
        self.configure(bg=COLORS['bg_dark'])
        
        # Custom title bar
        self.create_title_bar()
        
        # Main content
        self.create_content()
        
        self.center_window()
    
    def create_title_bar(self):
        """Create custom title bar"""
        title_frame = tk.Frame(self, bg=COLORS['bg_dark'], height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        # Logo with glow
        logo = tk.Label(title_frame, text='🛡️', font=('Segoe UI', 32),
                       bg=COLORS['bg_dark'], fg=COLORS['cyan'])
        logo.pack(side=tk.LEFT, padx=20)
        
        # Title
        title = tk.Label(title_frame, text='SECUREGUARD',
                        font=('Consolas', 24, 'bold'),
                        bg=COLORS['bg_dark'], fg=COLORS['cyan'])
        title.pack(side=tk.LEFT)
        
        subtitle = tk.Label(title_frame, text='CYBER DEFENSE CENTER',
                          font=('Consolas', 10),
                          bg=COLORS['bg_dark'], fg=COLORS['gray'])
        subtitle.pack(side=tk.LEFT, padx=10)
        
        # Status indicators
        status_frame = tk.Frame(title_frame, bg=COLORS['bg_dark'])
        status_frame.pack(side=tk.RIGHT, padx=20)
        
        self.status_labels = {}
        statuses = [
            ('FIREWALL', COLORS['green']),
            ('ANTIVIRUS', COLORS['green']),
            ('CLOUD', COLORS['cyan']),
            ('AI', COLORS['purple'])
        ]
        
        for name, color in statuses:
            lbl = tk.Label(status_frame, text=name,
                          font=('Consolas', 10, 'bold'),
                          bg=COLORS['bg_dark'], fg=color)
            lbl.pack(side=tk.LEFT, padx=10)
            self.status_labels[name] = lbl
        
        # Time
        self.time_label = tk.Label(title_frame, font=('Consolas', 12),
                                  bg=COLORS['bg_dark'], fg=COLORS['cyan'])
        self.time_label.pack(side=tk.RIGHT, padx=30)
        self.update_time()
    
    def create_content(self):
        """Create main content area"""
        # Main container
        main = tk.Frame(self, bg=COLORS['bg_dark'])
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left panel
        left = tk.Frame(main, bg=COLORS['bg_dark'])
        left.pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # Cyber Shield
        shield_label = tk.Label(left, text="PROTECTION STATUS",
                              font=('Consolas', 14, 'bold'),
                              bg=COLORS['bg_dark'], fg=COLORS['cyan'])
        shield_label.pack(pady=10)
        
        shield = CyberShield(left, width=250, height=280)
        shield.pack(pady=10)
        
        # Quick stats
        stats_frame = tk.Frame(left, bg=COLORS['bg_medium'], bd=2, relief=tk.RAISED)
        stats_frame.pack(pady=10, fill=tk.X)
        
        for label, icon in [('Threats Blocked', '🛡️'), ('Files Scanned', '📁'), 
                           ('Processes', '⚙️'), ('Connections', '🌐')]:
            row = tk.Frame(stats_frame, bg=COLORS['bg_medium'])
            row.pack(fill=tk.X, padx=10, pady=5)
            tk.Label(row, text=icon, font=('Segoe UI', 16),
                    bg=COLORS['bg_medium']).pack(side=tk.LEFT)
            tk.Label(row, text=f"{random.randint(1000, 99999):,}",
                    font=('Consolas', 14, 'bold'), fg=COLORS['cyan'],
                    bg=COLORS['bg_medium']).pack(side=tk.LEFT, padx=10)
            tk.Label(row, text=label, font=('Consolas', 9),
                    bg=COLORS['bg_medium'], fg=COLORS['gray']).pack(side=tk.LEFT)
        
        # Center panel
        center = tk.Frame(main, bg=COLORS['bg_dark'])
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        
        # System graphs
        graphs_label = tk.Label(center, text="SYSTEM MONITOR",
                              font=('Consolas', 14, 'bold'),
                              bg=COLORS['bg_dark'], fg=COLORS['cyan'])
        graphs_label.pack(pady=10)
        
        # Graph containers
        graph_frame = tk.Frame(center, bg=COLORS['bg_dark'])
        graph_frame.pack(fill=tk.BOTH, expand=True)
        
        self.cpu_graph = NeonGraph(graph_frame, width=400, height=120, 
                                  title="CPU", color=COLORS['cyan'])
        self.cpu_graph.pack(pady=5)
        
        self.mem_graph = NeonGraph(graph_frame, width=400, height=120,
                                  title="MEMORY", color=COLORS['magenta'])
        self.mem_graph.pack(pady=5)
        
        self.net_graph = NeonGraph(graph_frame, width=400, height=120,
                                   title="NETWORK", color=COLORS['green'])
        self.net_graph.pack(pady=5)
        
        # Right panel
        right = tk.Frame(main, bg=COLORS['bg_dark'])
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        
        # Activity log
        log_label = tk.Label(right, text="SECURITY LOG",
                           font=('Consolas', 14, 'bold'),
                           bg=COLORS['bg_dark'], fg=COLORS['cyan'])
        log_label.pack(pady=10)
        
        log_frame = tk.Frame(right, bg=COLORS['bg_medium'], bd=2)
        log_frame.pack(pady=10)
        
        self.log_text = tk.Text(log_frame, width=40, height=15,
                               bg=COLORS['bg_dark'], fg=COLORS['green'],
                               font=('Consolas', 9), bd=0)
        self.log_text.pack(padx=5, pady=5)
        
        # Add sample logs
        self.add_log("System initialized")
        self.add_log("Threat database updated")
        self.add_log("Firewall active")
        
        # Action buttons
        btn_frame = tk.Frame(right, bg=COLORS['bg_dark'])
        btn_frame.pack(pady=20)
        
        CyberButton(btn_frame, "🔍 QUICK SCAN", self.quick_scan, COLORS['cyan']).pack(pady=5)
        CyberButton(btn_frame, "📊 FULL SCAN", self.full_scan, COLORS['purple']).pack(pady=5)
        CyberButton(btn_frame, "🛡️ UPDATE", self.update_db, COLORS['green']).pack(pady=5)
    
    def add_log(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def quick_scan(self):
        """Quick scan action"""
        self.add_log("Starting quick scan...")
    
    def full_scan(self):
        """Full scan action"""
        self.add_log("Starting full system scan...")
    
    def update_db(self):
        """Update database"""
        self.add_log("Checking for updates...")
    
    def update_time(self):
        """Update time display"""
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.time_label.config(text=now)
        self.after(1000, self.update_time)
    
    def center_window(self):
        """Center window"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')


def run_cyber_dashboard():
    """Run the cyber dashboard"""
    app = CyberDashboard()
    app.mainloop()


if __name__ == '__main__':
    run_cyber_dashboard()
