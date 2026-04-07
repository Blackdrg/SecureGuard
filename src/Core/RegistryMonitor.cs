using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SecureGuard.Core
{
    public class RegistryMonitor : IDisposable
    {
        private bool _isRunning;
        private CancellationTokenSource? _cts;
        private readonly Dictionary<string, string> _lastKnownValues = new();
        private readonly object _lock = new();
        
        private static readonly string[] CriticalKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"SYSTEM\CurrentControlSet\Services",
            @"SOFTWARE\Classes\*\shell\open\command"
        };

        public event EventHandler<RegistryChangeEventArgs>? RegistryChangeDetected;
        public event EventHandler<SuspiciousRegistryChangeEventArgs>? SuspiciousChange;

        public RegistryMonitor()
        {
            Logger.Log("Info", "Registry Monitor initialized");
        }

        public void Start()
        {
            if (_isRunning) return;
            _cts = new CancellationTokenSource();
            _isRunning = true;
            Task.Run(() => MonitorRegistry(_cts.Token));
            Logger.Log("Info", "Registry Monitor started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            Logger.Log("Info", "Registry Monitor stopped");
        }

        private async Task MonitorRegistry(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    foreach (var keyPath in CriticalKeys)
                    {
                        CheckRegistryKey(keyPath);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Registry monitoring error", ex);
                }
                await Task.Delay(10000, token);
            }
        }

        private void CheckRegistryKey(string keyPath)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    var keyName = $"{keyPath}\\{valueName}";
                    var currentValue = key.GetValue(valueName)?.ToString() ?? "";
                    
                    lock (_lock)
                    {
                        if (_lastKnownValues.TryGetValue(keyName, out var lastValue))
                        {
                            if (lastValue != currentValue)
                            {
                                RegistryChangeDetected?.Invoke(this, new RegistryChangeEventArgs(keyName, lastValue, currentValue));
                                if (IsSuspiciousChange(valueName, currentValue))
                                {
                                    SuspiciousChange?.Invoke(this, new SuspiciousRegistryChangeEventArgs(keyName, currentValue, "Suspicious modification"));
                                }
                                _lastKnownValues[keyName] = currentValue;
                            }
                        }
                        else
                        {
                            _lastKnownValues[keyName] = currentValue;
                        }
                    }
                }
            }
            catch { }
        }

        private bool IsSuspiciousChange(string valueName, string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            var suspiciousPatterns = new[] { ".exe", ".bat", ".cmd", ".ps1", ".vbs", "powershell", "cmd.exe" };
            var valueLower = value.ToLower();
            return Array.Exists(suspiciousPatterns, p => valueLower.Contains(p));
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }

    public class RegistryChangeEventArgs : EventArgs
    {
        public string KeyPath { get; }
        public string OldValue { get; }
        public string NewValue { get; }
        public DateTime Timestamp { get; }

        public RegistryChangeEventArgs(string keyPath, string oldValue, string newValue)
        {
            KeyPath = keyPath;
            OldValue = oldValue;
            NewValue = newValue;
            Timestamp = DateTime.Now;
        }
    }

    public class SuspiciousRegistryChangeEventArgs : EventArgs
    {
        public string KeyPath { get; }
        public string Value { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public SuspiciousRegistryChangeEventArgs(string keyPath, string value, string reason)
        {
            KeyPath = keyPath;
            Value = value;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }
}

