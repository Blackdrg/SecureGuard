using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.Core
{
    /// <summary>
    /// Feature 7: Smart Protection Mode (Context-Aware Security)
    /// Automatically adapts protection level based on user activity
    /// </summary>
    public class ContextAwareProtection : IDisposable
    {
        private readonly Timer _contextMonitorTimer;
        private ProtectionMode _currentMode = ProtectionMode.Normal;
        private string _currentContext = "Normal";
        private bool _isAutoDetectionEnabled = true;
        private readonly object _lock = new();
        
        // Context detection components
        private readonly List<ContextRule> _contextRules;
        private readonly ProcessMonitor _processMonitor;
        
        public event EventHandler<ModeChangedEventArgs>? ModeChanged;
        public event EventHandler<ContextDetectedEventArgs>? ContextDetected;

        public ContextAwareProtection()
        {
            _contextRules = new List<ContextRule>();
            _processMonitor = new ProcessMonitor();
            
            _contextMonitorTimer = new Timer(MonitorContext, null, TimeSpan.Zero, TimeSpan.FromSeconds(10));
            
            InitializeContextRules();
            Core.Logger.Log("Info", "Context-Aware Protection initialized");
        }

        private void InitializeContextRules()
        {
            // Gaming mode rules
            _contextRules.Add(new ContextRule
            {
                Mode = ProtectionMode.Gaming,
                Name = "Gaming",
                Triggers = new List<ContextTrigger>
                {
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "steam", Weight = 50 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "epicgames", Weight = 50 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "gog", Weight = 40 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "battle.net", Weight = 40 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "minecraft", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "valorant", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "fortnite", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "game", Weight = 20 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "Gaming", Weight = 15 }
                },
                Settings = new ProtectionSettings
                {
                    RealTimeProtectionLevel = ProtectionLevel.Minimal,
                    ScanOnFileAccess = false,
                    NetworkFiltering = false,
                    ProcessHeuristics = false,
                    SilentMode = true,
                    Notifications = false,
                    MaxCpuUsage = 5
                }
            });

            // Banking mode rules
            _contextRules.Add(new ContextRule
            {
                Mode = ProtectionMode.Banking,
                Name = "Banking",
                Triggers = new List<ContextTrigger>
                {
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "chrome", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "firefox", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "msedge", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "opera", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "bank", Weight = 60 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "Banking", Weight = 60 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "payment", Weight = 50 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "secure", Weight = 40 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "login", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "bank", Weight = 40 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "paypal", Weight = 50 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "chase", Weight = 50 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "wellsfargo", Weight = 50 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "bankofamerica", Weight = 50 }
                },
                Settings = new ProtectionSettings
                {
                    RealTimeProtectionLevel = ProtectionLevel.Maximum,
                    ScanOnFileAccess = true,
                    NetworkFiltering = true,
                    ProcessHeuristics = true,
                    SilentMode = false,
                    Notifications = true,
                    MaxCpuUsage = 50,
                    EnableKeyloggerProtection = true,
                    EnableScreenshotProtection = true,
                    EnableClipboardProtection = true
                }
            });

            // Browsing mode rules
            _contextRules.Add(new ContextRule
            {
                Mode = ProtectionMode.Browsing,
                Name = "Browsing",
                Triggers = new List<ContextTrigger>
                {
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "chrome", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "firefox", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "msedge", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "opera", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "brave", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "Browser", Weight = 20 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "Google", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "YouTube", Weight = 15 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "Facebook", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.WindowTitle, Value = "Twitter", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "http", Weight = 5 },
                    new ContextTrigger { Type = TriggerType.Url, Value = "https", Weight = 5 }
                },
                Settings = new ProtectionSettings
                {
                    RealTimeProtectionLevel = ProtectionLevel.High,
                    ScanOnFileAccess = true,
                    NetworkFiltering = true,
                    ProcessHeuristics = true,
                    SilentMode = false,
                    Notifications = true,
                    MaxCpuUsage = 30,
                    EnablePhishingProtection = true,
                    EnableMalwareUrlBlocking = true
                }
            });

            // Work mode rules
            _contextRules.Add(new ContextRule
            {
                Mode = ProtectionMode.Work,
                Name = "Work",
                Triggers = new List<ContextTrigger>
                {
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "outlook", Weight = 40 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "excel", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "word", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "powerpoint", Weight = 25 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "teams", Weight = 40 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "slack", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "zoom", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "visual studio", Weight = 30 },
                    new ContextTrigger { Type = TriggerType.ProcessName, Value = "code", Weight = 25 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "9", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "10", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "11", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "14", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "15", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "16", Weight = 10 },
                    new ContextTrigger { Type = TriggerType.HourOfDay, Value = "17", Weight = 10 }
                },
                Settings = new ProtectionSettings
                {
                    RealTimeProtectionLevel = ProtectionLevel.Normal,
                    ScanOnFileAccess = true,
                    NetworkFiltering = true,
                    ProcessHeuristics = true,
                    SilentMode = false,
                    Notifications = true,
                    MaxCpuUsage = 25
                }
            });

            // Idle/Deep Scan mode rules
            _contextRules.Add(new ContextRule
            {
                Mode = ProtectionMode.Idle,
                Name = "Idle",
                Triggers = new List<ContextTrigger>
                {
                    new ContextTrigger { Type = TriggerType.IdleTime, Value = "300", Weight = 100 }, // 5 minutes
                    new ContextTrigger { Type = TriggerType.IdleTime, Value = "600", Weight = 80 },  // 10 minutes
                    new ContextTrigger { Type = TriggerType.IdleTime, Value = "900", Weight = 60 }   // 15 minutes
                },
                Settings = new ProtectionSettings
                {
                    RealTimeProtectionLevel = ProtectionLevel.Normal,
                    ScanOnFileAccess = false,
                    NetworkFiltering = false,
                    ProcessHeuristics = true,
                    SilentMode = true,
                    Notifications = false,
                    MaxCpuUsage = 80,
                    EnableDeepScan = true,
                    EnableScheduledScans = true
                }
            });

            Core.Logger.Log("Info", $"Loaded {_contextRules.Count} context rules");
        }

        private void MonitorContext(object? state)
        {
            if (!_isAutoDetectionEnabled) return;

            try
            {
                var detectedContext = DetectContext();
                
                if (detectedContext.DetectedMode != _currentMode)
                {
                    SetMode(detectedContext.DetectedMode, detectedContext.Reason);
                }
                
                ContextDetected?.Invoke(this, new ContextDetectedEventArgs(detectedContext));
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Context monitoring error", ex);
            }
        }

        private ContextAnalysis DetectContext()
        {
            var analysis = new ContextAnalysis
            {
                DetectedAt = DateTime.Now,
                Scores = new Dictionary<ProtectionMode, int>()
            };

            // Initialize scores
            foreach (var rule in _contextRules)
            {
                if (!analysis.Scores.ContainsKey(rule.Mode))
                    analysis.Scores[rule.Mode] = 0;
            }

            // Check process triggers
            var runningProcesses = GetRunningProcesses();
            
            foreach (var rule in _contextRules)
            {
                foreach (var trigger in rule.Triggers)
                {
                    if (trigger.Type == TriggerType.ProcessName)
                    {
                        if (runningProcesses.Any(p => p.ToLower().Contains(trigger.Value.ToLower())))
                        {
                            analysis.Scores[rule.Mode] += trigger.Weight;
                        }
                    }
                }
            }

            // Check window title triggers
            var activeWindow = GetActiveWindowTitle();
            if (!string.IsNullOrEmpty(activeWindow))
            {
                foreach (var rule in _contextRules)
                {
                    foreach (var trigger in rule.Triggers)
                    {
                        if (trigger.Type == TriggerType.WindowTitle)
                        {
                            if (activeWindow.ToLower().Contains(trigger.Value.ToLower()))
                            {
                                analysis.Scores[rule.Mode] += trigger.Weight;
                            }
                        }
                    }
                }
            }

            // Check idle time
            var idleTime = GetIdleTime();
            foreach (var rule in _contextRules)
            {
                foreach (var trigger in rule.Triggers)
                {
                    if (trigger.Type == TriggerType.IdleTime)
                    {
                        if (int.TryParse(trigger.Value, out int threshold) && idleTime >= threshold)
                        {
                            analysis.Scores[rule.Mode] += trigger.Weight;
                        }
                    }
                }
            }

            // Check time of day
            var currentHour = DateTime.Now.Hour;
            foreach (var rule in _contextRules)
            {
                foreach (var trigger in rule.Triggers)
                {
                    if (trigger.Type == TriggerType.HourOfDay)
                    {
                        if (int.TryParse(trigger.Value, out int hour) && currentHour == hour)
                        {
                            analysis.Scores[rule.Mode] += trigger.Weight;
                        }
                    }
                }
            }

            // Determine best match
            var bestMode = analysis.Scores.OrderByDescending(x => x.Value).First();
            
            if (bestMode.Value > 30)
            {
                analysis.DetectedMode = bestMode.Key;
                analysis.Confidence = Math.Min(100, bestMode.Value);
            }
            else
            {
                analysis.DetectedMode = ProtectionMode.Normal;
                analysis.Confidence = 100;
            }

            analysis.Reason = $"Score: {bestMode.Value} for {bestMode.Key}";
            
            return analysis;
        }

        private List<string> GetRunningProcesses()
        {
            var processes = new List<string>();
            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        processes.Add(process.ProcessName);
                    }
                    catch { }
                }
            }
            catch { }
            return processes;
        }

        private string GetActiveWindowTitle()
        {
            try
            {
                var hwnd = GetForegroundWindow();
                if (hwnd != IntPtr.Zero)
                {
                    var sb = new System.Text.StringBuilder(256);
                    GetWindowText(hwnd, sb, 256);
                    return sb.ToString();
                }
            }
            catch { }
            return "";
        }

        private int GetIdleTime()
        {
            try
            {
                var lastInput = new LASTINPUTINFO();
                lastInput.cbSize = (uint)Marshal.SizeOf(lastInput);
                
                if (GetLastInputInfo(ref lastInput))
                {
                    var idleTime = (uint)Environment.TickCount - lastInput.dwTime;
                    return (int)(idleTime / 1000); // Convert to seconds
                }
            }
            catch { }
            return 0;
        }

        public void SetMode(ProtectionMode mode, string reason = "")
        {
            lock (_lock)
            {
                var previousMode = _currentMode;
                _currentMode = mode;
                
                // Get settings for new mode
                var rule = _contextRules.FirstOrDefault(r => r.Mode == mode);
                var settings = rule?.Settings ?? new ProtectionSettings();
                
                // Apply settings
                ApplyProtectionSettings(settings);
                
                _currentContext = rule?.Name ?? "Normal";
                
                Core.Logger.Log("Info", $"Protection mode changed: {previousMode} -> {mode} ({reason})");
                
                ModeChanged?.Invoke(this, new ModeChangedEventArgs(previousMode, mode, reason));
            }
        }

        private void ApplyProtectionSettings(ProtectionSettings settings)
        {
            // Apply settings to various engines
            Core.Logger.Log("Debug", $"Applying protection settings: Silent={settings.SilentMode}, Level={settings.RealTimeProtectionLevel}");
            
            // These would integrate with actual protection engines
            // For now, just log the settings
        }

        public ProtectionMode GetCurrentMode()
        {
            lock (_lock)
            {
                return _currentMode;
            }
        }

        public string GetCurrentContext()
        {
            lock (_lock)
            {
                return _currentContext;
            }
        }

        public ProtectionSettings GetCurrentSettings()
        {
            lock (_lock)
            {
                var rule = _contextRules.FirstOrDefault(r => r.Mode == _currentMode);
                return rule?.Settings ?? new ProtectionSettings();
            }
        }

        public void EnableAutoDetection()
        {
            _isAutoDetectionEnabled = true;
            Core.Logger.Log("Info", "Auto context detection enabled");
        }

        public void DisableAutoDetection()
        {
            _isAutoDetectionEnabled = false;
            Core.Logger.Log("Info", "Auto context detection disabled");
        }

        public List<ContextRule> GetAllRules()
        {
            return _contextRules.ToList();
        }

        public void Dispose()
        {
            _contextMonitorTimer.Dispose();
            Core.Logger.Log("Info", "Context-Aware Protection disposed");
        }

        // Windows API imports
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }
    }

    public enum ProtectionMode
    {
        Normal,
        Gaming,
        Banking,
        Browsing,
        Work,
        Idle,
        Custom
    }

    public enum ProtectionLevel
    {
        Minimal,
        Low,
        Normal,
        High,
        Maximum
    }

    public enum TriggerType
    {
        ProcessName,
        WindowTitle,
        Url,
        HourOfDay,
        IdleTime,
        NetworkActivity
    }

    public class ProtectionSettings
    {
        public ProtectionLevel RealTimeProtectionLevel { get; set; } = ProtectionLevel.Normal;
        public bool ScanOnFileAccess { get; set; } = true;
        public bool NetworkFiltering { get; set; } = true;
        public bool ProcessHeuristics { get; set; } = true;
        public bool SilentMode { get; set; } = false;
        public bool Notifications { get; set; } = true;
        public int MaxCpuUsage { get; set; } = 25;
        public bool EnablePhishingProtection { get; set; } = false;
        public bool EnableMalwareUrlBlocking { get; set; } = false;
        public bool EnableKeyloggerProtection { get; set; } = false;
        public bool EnableScreenshotProtection { get; set; } = false;
        public bool EnableClipboardProtection { get; set; } = false;
        public bool EnableDeepScan { get; set; } = false;
        public bool EnableScheduledScans { get; set; } = false;
    }

    public class ContextRule
    {
        public ProtectionMode Mode { get; set; }
        public string Name { get; set; } = "";
        public List<ContextTrigger> Triggers { get; set; } = new();
        public ProtectionSettings Settings { get; set; } = new();
    }

    public class ContextTrigger
    {
        public TriggerType Type { get; set; }
        public string Value { get; set; } = "";
        public int Weight { get; set; }
    }

    public class ContextAnalysis
    {
        public ProtectionMode DetectedMode { get; set; }
        public int Confidence { get; set; }
        public string Reason { get; set; } = "";
        public DateTime DetectedAt { get; set; }
        public Dictionary<ProtectionMode, int> Scores { get; set; } = new();
    }

    public class ModeChangedEventArgs : EventArgs
    {
        public ProtectionMode PreviousMode { get; }
        public ProtectionMode NewMode { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public ModeChangedEventArgs(ProtectionMode previousMode, ProtectionMode newMode, string reason)
        {
            PreviousMode = previousMode;
            NewMode = newMode;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }

    public class ContextDetectedEventArgs : EventArgs
    {
        public ContextAnalysis Analysis { get; }
        public DateTime Timestamp { get; }

        public ContextDetectedEventArgs(ContextAnalysis analysis)
        {
            Analysis = analysis;
            Timestamp = DateTime.Now;
        }
    }

    public class ProcessMonitor
    {
        public event EventHandler<ProcessEventArgs>? ProcessStarted;
        public event EventHandler<ProcessEventArgs>? ProcessStopped;

        private readonly List<string> _monitoredProcesses = new();
        private readonly Timer _timer;

        public ProcessMonitor()
        {
            _timer = new Timer(CheckProcesses, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }

        private void CheckProcesses(object? state)
        {
            // Check for specific processes
        }

        public void AddProcess(string processName)
        {
            if (!_monitoredProcesses.Contains(processName))
                _monitoredProcesses.Add(processName);
        }

        public void RemoveProcess(string processName)
        {
            _monitoredProcesses.Remove(processName);
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }

    public class ProcessEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public int ProcessId { get; }
        public DateTime Timestamp { get; }

        public ProcessEventArgs(string processName, int processId)
        {
            ProcessName = processName;
            ProcessId = processId;
            Timestamp = DateTime.Now;
        }
    }
}

