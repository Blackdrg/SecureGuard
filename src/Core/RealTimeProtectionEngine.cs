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
    /// Real-Time Protection Engine - monitors files, processes, and blocks threats
    /// </summary>
    public class RealTimeProtectionEngine : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private FileSystemWatcher? _downloadWatcher;
        private CancellationTokenSource? _processMonitorCts;
        private bool _isRunning;
        private SignatureDatabase? _signatureDb;
        private MultiLayerDetectionEngine? _detectionEngine;
        
        // Known malicious process names
        private static readonly HashSet<string> MaliciousProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "mimikatz", "pwdump", "procdump", "lsass", "credentials", "netuser",
            "psexec", "wce", "gsecdump", "fgdump", "hashdump", "samdump", "wce32", "gsecdump32",
            "metasploit", "msfconsole", "msfvenom", "veil", "covenant", "powershell empire",
            "koadic", "silenttrinity", "merlin", "sliver", "brute ratel", "flame",
            "trinity", "dark comet", "njrat", "agent tesla", "azorult", "formbook",
            "emotet", "trickbot", "qakbot", "icedid", "raccoon", "mars steel"
        };

        // Suspicious file extensions
        private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh",
            ".scr", ".pif", ".application", ".gadget", ".com", ".hta", ".cpl", ".msc",
            ".jar", ".sh", ".bin", ".reg", ".inf", ".sys", ".ocx", ".vxd"
        };

        public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;
        public event EventHandler<FileEventArgs>? FileChanged;
        public bool IsRunning => _isRunning;

        public RealTimeProtectionEngine()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
            
            _signatureDb = new SignatureDatabase(Path.Combine(appDataPath, "signatures.json"));
            _detectionEngine = new MultiLayerDetectionEngine(_signatureDb);
        }

        public void StartFileSystemMonitoring()
        {
            if (_watcher != null || _isRunning) return;
            try
            {
                // Monitor user profile (most malware activity happens here)
                _watcher = new FileSystemWatcher();
                _watcher.Path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                _watcher.IncludeSubdirectories = true;
                _watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | 
                                        NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime;
                _watcher.Created += OnFileChanged;
                _watcher.Changed += OnFileChanged;
                _watcher.Deleted += OnFileChanged;
                _watcher.Renamed += OnFileRenamed;
                _watcher.Error += OnWatcherError;
                _watcher.EnableRaisingEvents = true;
                
                // Also monitor Downloads folder
                var downloadsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                if (Directory.Exists(downloadsPath))
                {
                    _downloadWatcher = new FileSystemWatcher(downloadsPath);
                    _downloadWatcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime;
                    _downloadWatcher.Created += OnDownloadFile;
                    _downloadWatcher.EnableRaisingEvents = true;
                }
                
                _isRunning = true;
                Core.Logger.Log("Info", "File system monitoring started");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to start file system monitoring", ex);
            }
        }

        public void StopFileSystemMonitoring()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
            
            if (_downloadWatcher != null)
            {
                _downloadWatcher.EnableRaisingEvents = false;
                _downloadWatcher.Dispose();
                _downloadWatcher = null;
            }
            
            _isRunning = false;
            Core.Logger.Log("Info", "File system monitoring stopped");
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Only process file changes (not directories)
                if (!File.Exists(e.FullPath)) return;
                
                Core.Logger.Log("Debug", $"File event: {e.ChangeType} - {e.FullPath}");
                FileChanged?.Invoke(this, new FileEventArgs(e.FullPath, e.ChangeType.ToString()));
                
                if (e.ChangeType == WatcherChangeTypes.Created || e.ChangeType == WatcherChangeTypes.Changed)
                {
                    ScanNewFileAsync(e.FullPath);
                }
                
                // Check for rapid file changes (ransomware indicator)
                CheckRapidFileChanges(e.FullPath);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Error handling file change: {ex.Message}", ex);
            }
        }

        private void OnDownloadFile(object sender, FileSystemEventArgs e)
        {
            if (!File.Exists(e.FullPath)) return;
            
            Core.Logger.Log("Info", $"Download detected: {e.FullPath}");
            ScanNewFileAsync(e.FullPath);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            Core.Logger.Log("Info", $"File renamed: {e.OldFullPath} -> {e.FullPath}");
            FileChanged?.Invoke(this, new FileEventArgs(e.FullPath, "Renamed"));
            
            // Check for ransomware extension changes
            var oldExt = Path.GetExtension(e.OldFullPath);
            var newExt = Path.GetExtension(e.FullPath);
            if (oldExt != newExt && !string.IsNullOrEmpty(newExt))
            {
                var ransomwareExtensions = new[] { ".encrypted", ".locky", ".crypto", ".crypt", 
                    ".locked", ".enc", ".vault", ".crypto", ".lock", ".key", ".RSA" };
                if (ransomwareExtensions.Contains(newExt.ToLower()))
                {
                    Core.Logger.Log("Warning", $"Ransomware extension detected: {newExt}");
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(e.FullPath, "Ransomware Detected"));
                }
            }
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Core.Logger.Log("Error", $"FileSystemWatcher error: {e.GetException().Message}", e.GetException());
            
            // Try to restart watcher
            try
            {
                StopFileSystemMonitoring();
                Thread.Sleep(1000);
                StartFileSystemMonitoring();
            }
            catch { }
        }

        // Track rapid file changes for ransomware detection
        private readonly Dictionary<string, DateTime> _recentFileChanges = new();
        private readonly object _changeLock = new();

        private void CheckRapidFileChanges(string filePath)
        {
            lock (_changeLock)
            {
                var now = DateTime.Now;
                
                // Clean old entries
                var oldEntries = _recentFileChanges.Where(kvp => (now - kvp.Value).TotalSeconds > 10).ToList();
                foreach (var entry in oldEntries)
                {
                    _recentFileChanges.Remove(entry.Key);
                }
                
                // Check for rapid changes
                if (_recentFileChanges.TryGetValue(filePath, out var lastChange))
                {
                    var changeCount = _recentFileChanges.Count(kvp => 
                        kvp.Key.StartsWith(Path.GetDirectoryName(filePath) ?? "") && 
                        (now - kvp.Value).TotalSeconds < 5);
                    
                    if (changeCount > 20)
                    {
                        Core.Logger.Log("Warning", "Rapid file changes detected - possible ransomware!");
                        ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(filePath, "Ransomware Activity Detected"));
                    }
                }
                
                _recentFileChanges[filePath] = now;
            }
        }

        private async void ScanNewFileAsync(string filePath)
        {
            try
            {
                // Skip if file doesn't exist or is too large
                if (!File.Exists(filePath)) return;
                
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 100 * 1024 * 1024) return; // Skip files > 100MB
                
                // Check extension
                var ext = Path.GetExtension(filePath).ToLower();
                if (!DangerousExtensions.Contains(ext)) return;
                
                // Wait a moment for file to be fully written
                await Task.Delay(500);
                
                if (!File.Exists(filePath)) return;
                
                var hash = Hashing.ComputeSHA256(filePath);
                
                // Layer 1: Signature Detection
                if (_signatureDb != null && _signatureDb.IsThreat(hash))
                {
                    var threatName = _signatureDb.GetDescription(hash) ?? "Unknown Threat";
                    Core.Logger.Log("Warning", $"Signature match detected: {filePath} - {threatName}");
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(filePath, threatName));
                    
                    // Try to block the file
                    BlockExecution(filePath);
                    return;
                }
                
                // Layer 2: Heuristic Detection
                if (_detectionEngine != null)
                {
                    var heuristicResult = _detectionEngine.IsHeuristicThreat(filePath);
                    if (heuristicResult.IsThreat && heuristicResult.Confidence >= 50)
                    {
                        Core.Logger.Log("Warning", $"Heuristic threat detected: {filePath} - {heuristicResult.ThreatName}");
                        ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(filePath, heuristicResult.ThreatName ?? "Suspicious File"));
                        
                        // Block high-confidence threats
                        if (heuristicResult.Confidence >= 70)
                        {
                            BlockExecution(filePath);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Error scanning new file: {ex.Message}", ex);
            }
        }

        public void StartProcessMonitoring()
        {
            if (_processMonitorCts != null) return;
            _processMonitorCts = new CancellationTokenSource();
            var token = _processMonitorCts.Token;
            Task.Run(() => MonitorProcesses(token), token);
            _isRunning = true;
            Core.Logger.Log("Info", "Process monitoring started");
        }

        private async Task MonitorProcesses(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var currentProcesses = Process.GetProcesses();
                    foreach (var process in currentProcesses)
                    {
                        try
                        {
                            var processName = process.ProcessName.ToLower();
                            
                            // Check for malicious processes
                            if (MaliciousProcesses.Any(m => processName.Contains(m)))
                            {
                                Core.Logger.Log("Warning", $"Malicious process detected: {process.ProcessName} (PID: {process.Id})");
                                
                                ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(
                                    $"Process: {process.ProcessName}", 
                                    $"Malicious Process: {process.ProcessName}"));
                                
                                // Try to terminate the process
                                TerminateProcess(process);
                            }
                            
                            // Check for suspicious child processes
                            try
                            {
                                if (process.MainModule != null)
                                {
                                    CheckProcessModules(process);
                                }
                            }
                            catch { } // Access denied for some system processes
                        }
                        catch { }
                        finally
                        {
                            process.Dispose();
                        }
                    }
                    
                    await Task.Delay(3000, token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", $"Process monitoring error: {ex.Message}", ex);
                    await Task.Delay(5000, token);
                }
            }
        }

        private void CheckProcessModules(Process process)
        {
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    var moduleName = module.ModuleName.ToLower();
                    
                    // Check for known malicious DLLs
                    var maliciousModules = new[] { "mimikatz", "hook", "inject", "keylog", "passview" };
                    if (maliciousModules.Any(m => moduleName.Contains(m)))
                    {
                        Core.Logger.Log("Warning", $"Suspicious module in {process.ProcessName}: {module.ModuleName}");
                        
                        ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(
                            $"Module: {module.ModuleName}", 
                            $"Code Injection: {process.ProcessName}"));
                        
                        TerminateProcess(process);
                    }
                }
            }
            catch { }
        }

        private void TerminateProcess(Process process)
        {
            try
            {
                process.Kill();
                Core.Logger.Log("Warning", $"Process terminated: {process.ProcessName}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to terminate process {process.ProcessName}: {ex.Message}", ex);
            }
        }

        public void StopProcessMonitoring()
        {
            _processMonitorCts?.Cancel();
            _processMonitorCts?.Dispose();
            _processMonitorCts = null;
            _isRunning = false;
            Core.Logger.Log("Info", "Process monitoring stopped");
        }

        public void StartUsbAutoScan()
        {
            try
            {
                var appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureGuard");
                var usbScanner = new UsbScanner(
                    new ManualScanEngine(
                        _signatureDb!,
                        new ScanExclusions(Path.Combine(appDataPath, "exclusions.json")),
                        new QuarantineManager(Path.Combine(appDataPath, "quarantine"))),
                    new QuarantineManager(Path.Combine(appDataPath, "quarantine")));
                usbScanner.StartMonitoring();
                Core.Logger.Log("Info", "USB auto-scan started");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to start USB auto-scan", ex);
            }
        }

        public void StartDownloadMonitoring()
        {
            // Already handled by _downloadWatcher in StartFileSystemMonitoring
            Core.Logger.Log("Info", "Download monitoring started");
        }

        public void BlockExecution(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;
                
                // Rename to block execution
                var blockedPath = filePath + ".secureguard_blocked";
                File.Move(filePath, blockedPath);
                
                Core.Logger.Log("Warning", $"Execution blocked: {filePath}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to block execution: {ex.Message}", ex);
            }
        }

        public void UnblockFile(string blockedPath)
        {
            try
            {
                if (!File.Exists(blockedPath)) return;
                if (!blockedPath.EndsWith(".secureguard_blocked")) return;
                
                var originalPath = blockedPath.Replace(".secureguard_blocked", "");
                File.Move(blockedPath, originalPath);
                
                Core.Logger.Log("Info", $"File unblocked: {originalPath}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to unblock file: {ex.Message}", ex);
            }
        }

        public void ScanMemory()
        {
            try
            {
                Core.Logger.Log("Info", "Starting memory scan...");
                
                var processes = Process.GetProcesses();
                int threatsFound = 0;
                
                foreach (var process in processes)
                {
                    try
                    {
                        if (process.MainModule == null) continue;
                        
                        var modules = process.Modules;
                        foreach (ProcessModule module in modules)
                        {
                            var moduleName = module.ModuleName.ToLower();
                            if (moduleName.Contains("mimikatz") || 
                                moduleName.Contains("hook") || 
                                moduleName.Contains("inject"))
                            {
                                Core.Logger.Log("Warning", $"Suspicious module detected: {module.ModuleName} in {process.ProcessName}");
                                threatsFound++;
                                
                                ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(
                                    $"Memory: {process.ProcessName}", 
                                    $"Suspicious Module: {module.ModuleName}"));
                            }
                        }
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
                
                Core.Logger.Log("Info", $"Memory scan completed. Threats found: {threatsFound}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Memory scan failed: {ex.Message}", ex);
            }
        }

        public void StopAll()
        {
            StopFileSystemMonitoring();
            StopProcessMonitoring();
            Core.Logger.Log("Info", "All real-time protection stopped");
        }

        public void Dispose()
        {
            StopAll();
            _processMonitorCts?.Dispose();
        }
    }

    public class FileEventArgs : EventArgs
    {
        public string FilePath { get; }
        public string EventType { get; }
        public FileEventArgs(string filePath, string eventType) 
        { 
            FilePath = filePath; 
            EventType = eventType; 
        }
    }
}
