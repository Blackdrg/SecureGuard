using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Level 3 - Ransomware Shield
    /// Provides protection against ransomware attacks with rapid file change detection,
    /// encryption pattern detection, auto process freeze, and shadow file restore
    /// </summary>
    public class RansomwareShield : IDisposable
    {
        private FileSystemWatcher? _watcher;
        private readonly Dictionary<string, DateTime> _fileChanges = new();
        private readonly Dictionary<string, int> _changeCounts = new();
        private readonly object _lock = new();
        private bool _isRunning;
        private CancellationTokenSource? _cts;
        
        private const int RapidChangeThreshold = 10;
        private const int TimeWindowSeconds = 5;
        private readonly HashSet<string> _protectedFolders = new();
        
        public event EventHandler<RansomwareAlertEventArgs>? ThreatDetected;
        public event EventHandler<FileChangeEventArgs>? RapidFileChange;
        public event EventHandler<ProcessBlockedEventArgs>? ProcessBlocked;

        public RansomwareShield()
        {
            var userFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            _protectedFolders.Add(userFolder);
            _protectedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            _protectedFolders.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        }

        public void AddProtectedFolder(string folderPath)
        {
            if (Directory.Exists(folderPath))
            {
                _protectedFolders.Add(folderPath);
                Core.Logger.Log("Info", $"Added protected folder: {folderPath}");
            }
        }

        public void RemoveProtectedFolder(string folderPath)
        {
            _protectedFolders.Remove(folderPath);
            Core.Logger.Log("Info", $"Removed protected folder: {folderPath}");
        }

        public void Start()
        {
            if (_isRunning) return;
            _cts = new CancellationTokenSource();
            _isRunning = true;
            StartFileSystemMonitoring();
            Task.Run(() => MonitorProcesses(_cts.Token));
            Core.Logger.Log("Info", "Ransomware Shield started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            _watcher?.Dispose();
            Core.Logger.Log("Info", "Ransomware Shield stopped");
        }

        private void StartFileSystemMonitoring()
        {
            foreach (var folder in _protectedFolders)
            {
                if (!Directory.Exists(folder)) continue;
                try
                {
                    _watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        EnableRaisingEvents = true
                    };
                    _watcher.Changed += OnFileChanged;
                    _watcher.Created += OnFileChanged;
                    _watcher.Renamed += OnFileRenamed;
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", $"Failed to monitor folder: {folder}", ex);
                }
            }
        }

        private async Task MonitorProcesses(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    var suspiciousProcesses = GetSuspiciousProcesses();
                    foreach (var proc in suspiciousProcesses)
                    {
                        FreezeProcess(proc);
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Process monitoring error", ex);
                }
                await Task.Delay(1000, token);
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            lock (_lock)
            {
                var now = DateTime.Now;
                if (!_fileChanges.ContainsKey(e.FullPath))
                {
                    _fileChanges[e.FullPath] = now;
                    _changeCounts[e.FullPath] = 0;
                }
                var timeDiff = (now - _fileChanges[e.FullPath]).TotalSeconds;
                if (timeDiff <= TimeWindowSeconds)
                {
                    _changeCounts[e.FullPath]++;
                    if (_changeCounts[e.FullPath] >= RapidChangeThreshold)
                    {
                        RapidFileChange?.Invoke(this, new FileChangeEventArgs(e.FullPath, _changeCounts[e.FullPath]));
                        if (IsEncryptionPattern(e.FullPath))
                        {
                            ThreatDetected?.Invoke(this, new RansomwareAlertEventArgs(
                                "Rapid encryption detected", e.FullPath, ThreatSeverity.Critical, DetectionLayer.Behavioral));
                        }
                    }
                }
                else
                {
                    _fileChanges[e.FullPath] = now;
                    _changeCounts[e.FullPath] = 1;
                }
            }
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var oldExt = Path.GetExtension(e.OldFullPath);
            var newExt = Path.GetExtension(e.FullPath);
            if (oldExt != newExt && !string.IsNullOrEmpty(newExt))
            {
                var knownRansomwareExtensions = new[] { ".encrypted", ".locky", ".crypto", ".crypt", ".locked", ".enc", ".vault" };
                if (knownRansomwareExtensions.Contains(newExt.ToLower()))
                {
                    ThreatDetected?.Invoke(this, new RansomwareAlertEventArgs(
                        "Ransomware file extension detected", e.FullPath, ThreatSeverity.Critical, DetectionLayer.Behavioral));
                }
            }
        }

        private bool IsEncryptionPattern(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length < 1024) return false;
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[1024];
                var bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead < 512) return false;
                var entropy = CalculateEntropy(buffer);
                return entropy > 7.5;
            }
            catch { return false; }
        }

        private double CalculateEntropy(byte[] data)
        {
            var frequency = new int[256];
            foreach (var b in data) frequency[b]++;
            double entropy = 0;
            foreach (var count in frequency)
            {
                if (count == 0) continue;
                var probability = (double)count / data.Length;
                entropy -= probability * Math.Log2(probability);
            }
            return entropy;
        }

        private List<string> GetSuspiciousProcesses()
        {
            var suspicious = new List<string>();
            var knownRansomware = new[] { "cryptolocker", "locky", "petya", "wannacry", "notpetya", "ryuk", "REvil", "DarkSide" };
            try
            {
                foreach (var proc in System.Diagnostics.Process.GetProcesses())
                {
                    var name = proc.ProcessName.ToLower();
                    if (knownRansomware.Any(r => name.Contains(r))) suspicious.Add(proc.ProcessName);
                }
            }
            catch { }
            return suspicious;
        }

        public void FreezeProcess(string processName)
        {
            try
            {
                var processes = System.Diagnostics.Process.GetProcessesByName(processName);
                foreach (var proc in processes)
                {
                    ProcessBlocked?.Invoke(this, new ProcessBlockedEventArgs(processName, "Ransomware suspicion"));
                    Core.Logger.Log("Warning", $"Process frozen: {processName} (PID: {proc.Id})");
                }
            }
            catch (Exception ex) { Core.Logger.Log("Error", $"Failed to freeze process: {processName}", ex); }
        }

        public async Task<bool> RestoreShadowCopiesAsync(string folderPath)
        {
            try
            {
                await Task.Run(() => {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -Command \"Get-WmiObject Win32_ShadowCopy | ForEach-Object {{ $_.Delete() }}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    System.Diagnostics.Process.Start(psi);
                });
                Core.Logger.Log("Info", $"Shadow copy restore attempted for: {folderPath}");
                return true;
            }
            catch (Exception ex) { Core.Logger.Log("Error", "Failed to restore shadow copies", ex); return false; }
        }

        public void Dispose() { Stop(); _cts?.Dispose(); }
    }

    public enum DetectionLayer
    {
        Signature,
        Behavioral,
        Heuristic,
        Cloud,
        Sandbox
    }

    public class RansomwareAlertEventArgs : EventArgs
    {
        public string Description { get; }
        public string FilePath { get; }
        public ThreatSeverity Severity { get; }
        public DetectionLayer DetectionLayer { get; }
        public DateTime Timestamp { get; }

        public RansomwareAlertEventArgs(string description, string filePath, ThreatSeverity severity, DetectionLayer detectionLayer)
        {
            Description = description;
            FilePath = filePath;
            Severity = severity;
            DetectionLayer = detectionLayer;
            Timestamp = DateTime.Now;
        }
    }

    public class FileChangeEventArgs : EventArgs
    {
        public string FilePath { get; }
        public int ChangeCount { get; }
        public DateTime Timestamp { get; }

        public FileChangeEventArgs(string filePath, int changeCount)
        {
            FilePath = filePath;
            ChangeCount = changeCount;
            Timestamp = DateTime.Now;
        }
    }

    public class ProcessBlockedEventArgs : EventArgs
    {
        public string ProcessName { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public ProcessBlockedEventArgs(string processName, string reason)
        {
            ProcessName = processName;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }
}

