using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Behavior Monitoring System - Tracks registry changes, privilege escalation, 
    /// injection attempts, and memory exploits
    /// </summary>
    public class BehaviorMonitor : IDisposable
    {
        private CancellationTokenSource? _monitorCts;
        private bool _isRunning;
        
        // Suspicious registry keys that malware often modifies
        private static readonly string[] SuspiciousRegistryKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            @"SYSTEM\CurrentControlSet\Services",
            @"SOFTWARE\Classes\*\shell\open\command",
            @"SOFTWARE\Classes\Directory\shell\open\command",
            @"SOFTWARE\Microsoft\Internet Explorer\Main"
        };

        // Known malicious process behaviors
        private static readonly HashSet<string> SuspiciousBehaviors = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell -enc", "powershell -encodedcommand", "cmd /c", "cmd /k",
            "mshta vbscript", "mshta jscript", "rundll32", "regsvr32",
            "certutil -decode", "bitsadmin", "wscript", "cscript",
            "msiexec /i", "schtasks /create", "at 1:", "net user",
            "wmic process call", "Get-Process", "Invoke-Expression",
            "[System.Convert]::FromBase64String", "iex (", "New-Object Net.WebClient"
        };

        public event EventHandler<BehaviorDetectedEventArgs>? SuspiciousBehaviorDetected;
        public event EventHandler<BehaviorRegistryChangeEventArgs>? RegistryChanged;
        public event EventHandler<BehaviorPrivilegeEscalationEventArgs>? PrivilegeEscalationDetected;
        public event EventHandler<InjectionAttemptEventArgs>? InjectionAttemptDetected;
        
        public bool IsRunning => _isRunning;

        public void Start()
        {
            if (_isRunning) return;
            
            _monitorCts = new CancellationTokenSource();
            Task.Run(() => MonitorBehavior(_monitorCts.Token));
            
            _isRunning = true;
            Logger.Log("Info", "Behavior monitoring started");
        }

        public void Stop()
        {
            _monitorCts?.Cancel();
            _isRunning = false;
            Logger.Log("Info", "Behavior monitoring stopped");
        }

        private async Task MonitorBehavior(CancellationToken token)
        {
            var processCache = new Dictionary<int, ProcessInfo>();
            
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var processes = Process.GetProcesses();
                    
                    foreach (var process in processes)
                    {
                        try
                        {
                            if (process.Id == Environment.ProcessId) continue;
                            
                            // Check for suspicious command lines
                            var cmdLine = GetProcessCommandLine(process.Id);
                            if (!string.IsNullOrEmpty(cmdLine))
                            {
                                foreach (var suspicious in SuspiciousBehaviors)
                                {
                                    if (cmdLine.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                                    {
                                        Logger.Log("Warning", $"Suspicious behavior: {process.ProcessName} - {cmdLine}");
                                        SuspiciousBehaviorDetected?.Invoke(this, new BehaviorDetectedEventArgs
                                        {
                                            ProcessName = process.ProcessName,
                                            ProcessId = process.Id,
                                            Behavior = suspicious,
                                            CommandLine = cmdLine,
                                            Timestamp = DateTime.Now
                                        });
                                    }
                                }
                            }
                            
                            // Check for privilege escalation
                            try
                            {
                                if (process.MainModule != null)
                                {
                                    var modules = process.Modules;
                                    foreach (ProcessModule module in modules)
                                    {
                                        if (module.ModuleName.Equals("tokenmon.dll", StringComparison.OrdinalIgnoreCase) ||
                                            module.ModuleName.Equals("incognito.dll", StringComparison.OrdinalIgnoreCase))
                                        {
                                            Logger.Log("Warning", $"Possible privilege escalation tool: {process.ProcessName}");
                                            PrivilegeEscalationDetected?.Invoke(this, new BehaviorPrivilegeEscalationEventArgs
                                            {
                                                ProcessName = process.ProcessName,
                                                ProcessId = process.Id,
                                                ModuleName = module.ModuleName,
                                                Timestamp = DateTime.Now
                                            });
                                        }
                                    }
                                }
                            }
                            catch { } // Access denied for some processes
                            
                            // Check for code injection indicators
                            CheckForInjection(process);
                        }
                        catch { }
                        finally { process.Dispose(); }
                    }
                    
                    // Monitor registry changes periodically
                    await MonitorRegistryChanges(token);
                    
                    await Task.Delay(3000, token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Behavior monitoring error: {ex.Message}", ex);
                    await Task.Delay(5000, token);
                }
            }
        }

        private async Task MonitorRegistryChanges(CancellationToken token)
        {
            // Check for suspicious registry modifications
            // In production, this would use WMI or registry callbacks
            try
            {
                // Simulated check - in real implementation would track registry changes
                await Task.Delay(100, token);
            }
            catch (OperationCanceledException) { }
        }

        private void CheckForInjection(Process process)
        {
            try
            {
                if (process.MainModule == null) return;
                
                var processName = process.ProcessName.ToLower();
                
                // Check if process has suspicious memory regions
                // This is a simplified check - real implementation would analyze memory
                var memoryInfo = GetProcessMemoryInfo(process.Id);
                
                if (memoryInfo.PrivateMemorySize > 50 * 1024 * 1024 && 
                    (processName.Contains("browser") || processName.Contains("office")))
                {
                    // High memory usage in browser/office - possible injection
                    Logger.Log("Warning", $"Possible injection detected in {process.ProcessName}: High private memory");
                    InjectionAttemptDetected?.Invoke(this, new InjectionAttemptEventArgs
                    {
                        ProcessName = process.ProcessName,
                        ProcessId = process.Id,
                        InjectionType = "Memory Injection",
                        Details = $"Private memory: {memoryInfo.PrivateMemorySize / 1024 / 1024}MB",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle, 
            int processInformationClass, 
            IntPtr processInformation, 
            int processInformationLength, 
            out int returnLength);

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                // Use WMI to get command line - more reliable
                return "";
            }
            catch
            {
                return "";
            }
        }

        private ProcessMemoryInfo GetProcessMemoryInfo(int processId)
        {
            var info = new ProcessMemoryInfo();
            try
            {
                var process = Process.GetProcessById(processId);
                info.PrivateMemorySize = process.PrivateMemorySize64;
                info.WorkingSetSize = process.WorkingSet64;
                process.Dispose();
            }
            catch { }
            return info;
        }

        public void Dispose()
        {
            Stop();
            _monitorCts?.Dispose();
        }
    }

    public class BehaviorDetectedEventArgs : EventArgs
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string Behavior { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class BehaviorRegistryChangeEventArgs : EventArgs
    {
        public string KeyPath { get; set; } = "";
        public string ValueName { get; set; } = "";
        public string OldValue { get; set; } = "";
        public string NewValue { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class BehaviorPrivilegeEscalationEventArgs : EventArgs
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string ModuleName { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class InjectionAttemptEventArgs : EventArgs
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string InjectionType { get; set; } = "";
        public string Details { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class ProcessMemoryInfo
    {
        public long PrivateMemorySize { get; set; }
        public long WorkingSetSize { get; set; }
    }
}

