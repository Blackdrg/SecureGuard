using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace SecureGuard.Core
{
    /// <summary>
    /// Download Monitoring module for Level 2 Real-Time Protection
    /// Monitors and scans downloaded files
    /// </summary>
    public class DownloadMonitor : IDisposable
    {
        private readonly FileSystemWatcher _downloadWatcher;
        private readonly ManualScanEngine _scanEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly HashSet<string> _monitoredFolders;
        private bool _isMonitoring;
        private readonly object _lockObject = new();

        public event EventHandler<DownloadDetectedEventArgs>? DownloadDetected;
        public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

        public DownloadMonitor(ManualScanEngine scanEngine, QuarantineManager quarantineManager)
        {
            _scanEngine = scanEngine;
            _quarantineManager = quarantineManager;
            _monitoredFolders = new HashSet<string>();

            // Watch common download folders
            var downloadPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads");

            _downloadWatcher = new FileSystemWatcher(downloadPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                IncludeSubdirectories = true,
                EnableRaisingEvents = false
            };

            _downloadWatcher.Created += OnFileCreated;
            _downloadWatcher.Changed += OnFileChanged;
            _downloadWatcher.Error += OnWatcherError;
        }

        /// <summary>
        /// Adds a folder to monitor for downloads
        /// </summary>
        public void AddMonitoredFolder(string folderPath)
        {
            lock (_lockObject)
            {
                if (!_monitoredFolders.Contains(folderPath) && Directory.Exists(folderPath))
                {
                    _monitoredFolders.Add(folderPath);
                    Logger.Log("Info", $"Added download monitor folder: {folderPath}");
                }
            }
        }

        /// <summary>
        /// Removes a folder from download monitoring
        /// </summary>
        public void RemoveMonitoredFolder(string folderPath)
        {
            lock (_lockObject)
            {
                _monitoredFolders.Remove(folderPath);
                Logger.Log("Info", $"Removed download monitor folder: {folderPath}");
            }
        }

        /// <summary>
        /// Starts download monitoring
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring) return;

            _downloadWatcher.EnableRaisingEvents = true;
            _isMonitoring = true;
            Logger.Log("Info", "Download monitoring started");
        }

        /// <summary>
        /// Stops download monitoring
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring) return;

            _downloadWatcher.EnableRaisingEvents = false;
            _isMonitoring = false;
            Logger.Log("Info", "Download monitoring stopped");
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            ProcessDownloadedFile(e.FullPath);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            ProcessDownloadedFile(e.FullPath);
        }

        private void ProcessDownloadedFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return;

                // Wait for file to be fully written
                if (!WaitForFileAccess(filePath, TimeSpan.FromSeconds(5)))
                {
                    Logger.Log("Warning", $"Could not access file: {filePath}");
                    return;
                }

                var fileInfo = new FileInfo(filePath);
                
                // Skip small files (likely not threats)
                if (fileInfo.Length < 1024) return;

                Logger.Log("Info", $"Download detected: {filePath}");
                DownloadDetected?.Invoke(this, new DownloadDetectedEventArgs(filePath, fileInfo.Length));

                // Scan the downloaded file
                var threats = _scanEngine.ScanFolder(Path.GetDirectoryName(filePath) ?? "");
                
                foreach (var threat in threats)
                {
                    if (threat.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                    {
                        Logger.Log("Warning", $"Threat detected in downloaded file: {filePath}");
                        ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(filePath, "Downloaded malware"));
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Error processing downloaded file: {filePath}", ex);
            }
        }

        private bool WaitForFileAccess(string filePath, TimeSpan timeout)
        {
            var endTime = DateTime.Now.Add(timeout);
            while (DateTime.Now < endTime)
            {
                try
                {
                    using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.None);
                    return true;
                }
                catch (IOException)
                {
                    Thread.Sleep(100);
                }
            }
            return false;
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Logger.Log("Error", "Download monitor error", e.GetException());
        }

        public void Dispose()
        {
            StopMonitoring();
            _downloadWatcher.Dispose();
        }
    }

    public class DownloadDetectedEventArgs : EventArgs
    {
        public string FilePath { get; }
        public long FileSize { get; }
        public DateTime Timestamp { get; }

        public DownloadDetectedEventArgs(string filePath, long fileSize)
        {
            FilePath = filePath;
            FileSize = fileSize;
            Timestamp = DateTime.Now;
        }
    }

    public class ThreatDetectedEventArgs : EventArgs
    {
        public string FilePath { get; }
        public string ThreatType { get; }
        public DateTime Timestamp { get; }

        public ThreatDetectedEventArgs(string filePath, string threatType)
        {
            FilePath = filePath;
            ThreatType = threatType;
            Timestamp = DateTime.Now;
        }
    }
}

