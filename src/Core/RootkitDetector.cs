using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    public class RootkitDetector : IDisposable
    {
        private bool _isRunning;
        private CancellationTokenSource? _cts;

        public event EventHandler<RootkitDetectedEventArgs>? RootkitFound;

        public RootkitDetector()
        {
            Logger.Log("Info", "Rootkit Detector initialized");
        }

        public void Start()
        {
            if (_isRunning) return;
            _cts = new CancellationTokenSource();
            _isRunning = true;
            Task.Run(() => ScanForRootkits(_cts.Token));
            Logger.Log("Info", "Rootkit Detector started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            Logger.Log("Info", "Rootkit Detector stopped");
        }

        private async Task ScanForRootkits(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    DetectHiddenProcesses();
                    DetectHiddenServices();
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Rootkit scan error", ex);
                }
                await Task.Delay(60000, token);
            }
        }

        private void DetectHiddenProcesses()
        {
            try
            {
                var wmiProcesses = new HashSet<string>();
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Process"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        wmiProcesses.Add(obj["Name"]?.ToString() ?? "");
                    }
                }

                var normalProcesses = new HashSet<string>();
                foreach (var proc in Process.GetProcesses())
                {
                    try { normalProcesses.Add(proc.ProcessName + ".exe"); }
                    catch { }
                }

                foreach (var wmiProc in wmiProcesses)
                {
                    if (!string.IsNullOrEmpty(wmiProc) && !normalProcesses.Contains(wmiProc))
                    {
                        var procName = wmiProc.Replace(".exe", "");
                        RootkitFound?.Invoke(this, new RootkitDetectedEventArgs(procName, "Hidden process", ThreatSeverity.High));
                        Logger.Log("Warning", $"Potential rootkit: {wmiProc}");
                    }
                }
            }
            catch (Exception ex) { Logger.Log("Error", "Hidden process detection error", ex); }
        }

        private void DetectHiddenServices()
        {
            try
            {
                var suspiciousPatterns = new[] { "rootkit", "stealth", "hide" };
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Service"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var name = obj["Name"]?.ToString() ?? "";
                        if (suspiciousPatterns.Any(p => name.ToLower().Contains(p)))
                        {
                            RootkitFound?.Invoke(this, new RootkitDetectedEventArgs(name, "Suspicious service", ThreatSeverity.High));
                        }
                    }
                }
            }
            catch (Exception ex) { Logger.Log("Error", "Service detection error", ex); }
        }

        public void Dispose() { Stop(); _cts?.Dispose(); }
    }

    public class RootkitDetectedEventArgs : EventArgs
    {
        public string Name { get; }
        public string Description { get; }
        public ThreatSeverity Severity { get; }
        public DateTime Timestamp { get; }

        public RootkitDetectedEventArgs(string name, string description, ThreatSeverity severity)
        {
            Name = name;
            Description = description;
            Severity = severity;
            Timestamp = DateTime.Now;
        }
    }

    public class RootkitInfo
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public ThreatSeverity Severity { get; set; }
    }
}

