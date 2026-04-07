using System;
using System.Drawing;
using System.Windows.Forms;

namespace SecureGuard.Core
{
    /// <summary>
    /// System Tray Manager - provides system tray icon with context menu
    /// </summary>
    public class SystemTrayManager : IDisposable
    {
        private NotifyIcon? _notifyIcon;
        
        public event EventHandler? OnOpenClicked;
        public event EventHandler? OnDisableProtectionClicked;
        public event EventHandler? OnEnableProtectionClicked;
        public event EventHandler? OnExitClicked;
        
        public bool IsVisible => _notifyIcon?.Visible ?? false;
        
        public SystemTrayManager()
        {
            Initialize();
        }
        
        private void Initialize()
        {
            _notifyIcon = new NotifyIcon
            {
                Text = "SecureGuard Antivirus",
                Visible = false
            };
            
            var contextMenu = new ContextMenuStrip();
            
            var openItem = new ToolStripMenuItem("Open SecureGuard");
            openItem.Click += (s, e) => OnOpenClicked?.Invoke(this, EventArgs.Empty);
            openItem.Font = new Font(openItem.Font, FontStyle.Bold);
            contextMenu.Items.Add(openItem);
            
            contextMenu.Items.Add(new ToolStripSeparator());
            
            var protectItem = new ToolStripMenuItem("Enable Protection");
            protectItem.Click += (s, e) => OnEnableProtectionClicked?.Invoke(this, EventArgs.Empty);
            contextMenu.Items.Add(protectItem);
            
            var disableItem = new ToolStripMenuItem("Disable Protection");
            disableItem.Click += (s, e) => OnDisableProtectionClicked?.Invoke(this, EventArgs.Empty);
            contextMenu.Items.Add(disableItem);
            
            contextMenu.Items.Add(new ToolStripSeparator());
            
            var exitItem = new ToolStripMenuItem("Exit");
            exitItem.Click += (s, e) => OnExitClicked?.Invoke(this, EventArgs.Empty);
            contextMenu.Items.Add(exitItem);
            
            _notifyIcon.ContextMenuStrip = contextMenu;
            _notifyIcon.DoubleClick += (s, e) => OnOpenClicked?.Invoke(this, EventArgs.Empty);
            _notifyIcon.Icon = CreateShieldIcon();
        }
        
        private Icon CreateShieldIcon()
        {
            var bitmap = new Bitmap(32, 32);
            using (var g = Graphics.FromImage(bitmap))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                
                var shieldBrush = new SolidBrush(Color.FromArgb(35, 134, 54));
                var points = new Point[]
                {
                    new Point(16, 2),
                    new Point(28, 8),
                    new Point(28, 18),
                    new Point(16, 30),
                    new Point(4, 18),
                    new Point(4, 8)
                };
                g.FillPolygon(shieldBrush, points);
                
                var whitePen = new Pen(Color.White, 3);
                g.DrawLine(whitePen, 10, 16, 14, 20);
                g.DrawLine(whitePen, 14, 20, 22, 12);
            }
            
            return Icon.FromHandle(bitmap.GetHicon());
        }
        
        public void Show()
        {
            if (_notifyIcon != null) _notifyIcon.Visible = true;
        }
        
        public void Hide()
        {
            if (_notifyIcon != null) _notifyIcon.Visible = false;
        }
        
        public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
        {
            _notifyIcon?.ShowBalloonTip(5000, title, message, icon);
        }
        
        public void ShowThreatAlert(string threatName, string filePath)
        {
            ShowNotification("Threat Detected!", $"{threatName}\n{filePath}", ToolTipIcon.Warning);
        }
        
        public void UpdateStatus(bool protectionEnabled)
        {
            if (_notifyIcon != null)
            {
                _notifyIcon.Text = protectionEnabled ? "SecureGuard - Protected" : "SecureGuard - Unprotected";
            }
        }
        
        public void Dispose()
        {
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
                _notifyIcon = null;
            }
        }
    }
}
