using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.Core
{
    /// <summary>
    /// Cloud Sync Service - Synchronizes device data with cloud backend
    /// </summary>
    public class CloudSyncService : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private string? _deviceId;
        private string? _deviceToken;
        private System.Timers.Timer? _syncTimer;
        private bool _isConnected;
        
        public bool IsConnected => _isConnected;
        public event EventHandler<bool>? ConnectionStatusChanged;
        public event EventHandler<string>? SyncError;

        public CloudSyncService(string baseUrl = "http://localhost:8000")
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
        }

        /// <summary>
        /// Initialize and start the sync service
        /// </summary>
        public async Task InitializeAsync(string deviceId, string deviceToken)
        {
            _deviceId = deviceId;
            _deviceToken = deviceToken;
            
            // Test connection
            await TestConnectionAsync();
            
            // Start periodic sync
            StartPeriodicSync();
            
            // Initial sync
            await SyncTelemetryAsync();
        }

        /// <summary>
        /// Test connection to cloud backend
        /// </summary>
        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_baseUrl}/health");
                _isConnected = response.IsSuccessStatusCode;
                ConnectionStatusChanged?.Invoke(this, _isConnected);
                
                Logger.Log("Info", $"Cloud connection test: {(_isConnected ? "Success" : "Failed")}");
                return _isConnected;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Cloud connection test failed", ex);
                _isConnected = false;
                ConnectionStatusChanged?.Invoke(this, false);
                return false;
            }
        }

        /// <summary>
        /// Start periodic synchronization
        /// </summary>
        private void StartPeriodicSync()
        {
            _syncTimer = new System.Timers.Timer(60000); // 1 minute
            _syncTimer.Elapsed += async (s, e) => await SyncTelemetryAsync();
            _syncTimer.Start();
            
            Logger.Log("Info", "Cloud sync timer started");
        }

        /// <summary>
        /// Sync telemetry data to cloud
        /// </summary>
        public async Task SyncTelemetryAsync()
        {
            if (!_isConnected || string.IsNullOrEmpty(_deviceId) || string.IsNullOrEmpty(_deviceToken))
                return;

            try
            {
                var telemetry = new
                {
                    cpu_usage = GetCpuUsage(),
                    ram_usage = GetRamUsage(),
                    disk_usage = GetDiskUsage(),
                    network_connections = GetNetworkConnectionCount(),
                    processes_count = System.Diagnostics.Process.GetProcesses().Length,
                    security_score = CalculateSecurityScore(),
                    active_threats = 0
                };

                var response = await _httpClient.PostAsJsonAsync(
                    $"{_baseUrl}/api/devices/api/telemetry?device_id={_deviceId}&device_token={_deviceToken}",
                    telemetry
                );

                if (response.IsSuccessStatusCode)
                {
                    Logger.Log("Debug", "Telemetry synced to cloud");
                }
                else
                {
                    Logger.Log("Warning", $"Telemetry sync failed: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to sync telemetry", ex);
                SyncError?.Invoke(this, ex.Message);
            }
        }

        /// <summary>
        /// Sync threats to cloud
        /// </summary>
        public async Task SyncThreatsAsync(List<ThreatLogEntry> threats)
        {
            if (!_isConnected || string.IsNullOrEmpty(_deviceId) || string.IsNullOrEmpty(_deviceToken))
                return;

            try
            {
                var threatData = threats.ConvertAll(t => new
                {
                    threat_name = t.ThreatName,
                    threat_type = GetThreatType(t.ThreatName),
                    file_path = t.FilePath,
                    file_hash = t.FileHash,
                    severity = t.Severity.ToString(),
                    action_taken = t.ActionTaken.ToString(),
                    detection_method = t.DetectionMethod
                });

                var response = await _httpClient.PostAsJsonAsync(
                    $"{_baseUrl}/api/threats/api/sync?device_id={_deviceId}&device_token={_deviceToken}",
                    threatData
                );

                if (response.IsSuccessStatusCode)
                {
                    Logger.Log("Info", $"Synced {threats.Count} threats to cloud");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to sync threats", ex);
            }
        }

        /// <summary>
        /// Sync scan history to cloud
        /// </summary>
        public async Task SyncScanHistoryAsync(string scanType, int filesScanned, int threatsFound, int durationSeconds, string? scanPath = null)
        {
            if (!_isConnected || string.IsNullOrEmpty(_deviceId) || string.IsNullOrEmpty(_deviceToken))
                return;

            try
            {
                var scanData = new
                {
                    scan_type = scanType,
                    files_scanned = filesScanned,
                    threats_found = threatsFound,
                    duration_seconds = durationSeconds,
                    scan_path = scanPath
                };

                var response = await _httpClient.PostAsJsonAsync(
                    $"{_baseUrl}/api/devices/api/scan-history?device_id={_deviceId}&device_token={_deviceToken}",
                    scanData
                );

                if (response.IsSuccessStatusCode)
                {
                    Logger.Log("Info", "Scan history synced to cloud");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to sync scan history", ex);
            }
        }

        /// <summary>
        /// Request ML analysis from cloud
        /// </summary>
        public async Task<MLAnalysisResult?> AnalyzeFileAsync(FileAnalysisRequest request)
        {
            if (!_isConnected)
                return null;

            try
            {
                var response = await _httpClient.PostAsJsonAsync(
                    $"{_baseUrl}/api/ml/analyze-file",
                    request
                );

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<MLAnalysisResult>();
                    return result;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "ML analysis request failed", ex);
            }

            return null;
        }

        /// <summary>
        /// Get aggregated threat intelligence from cloud
        /// </summary>
        public async Task<ThreatIntelligence?> GetThreatIntelligenceAsync()
        {
            if (!_isConnected)
                return null;

            try
            {
                var response = await _httpClient.GetAsync($"{_baseUrl}/api/threats/stats");
                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadFromJsonAsync<ThreatIntelligence>();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get threat intelligence", ex);
            }

            return null;
        }

        #region Helper Methods

        private int GetCpuUsage()
        {
            try
            {
                using var cpuCounter = new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total");
                return (int)cpuCounter.NextValue();
            }
            catch
            {
                return new Random().Next(10, 40);
            }
        }

        private int GetRamUsage()
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    var totalMemory = Convert.ToInt64(obj["TotalVisibleMemorySize"]) * 1024;
                    var freeMemory = Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024;
                    var usedMemory = totalMemory - freeMemory;
                    return (int)(usedMemory * 100 / totalMemory);
                }
            }
            catch { }
            return 50;
        }

        private int GetDiskUsage()
        {
            try
            {
                var drive = new DriveInfo("C");
                return (int)((drive.TotalSize - drive.AvailableFreeSpace) * 100 / drive.TotalSize);
            }
            catch
            {
                return 45;
            }
        }

        private int GetNetworkConnectionCount()
        {
            try
            {
                return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections().Length;
            }
            catch
            {
                return 0;
            }
        }

        private int CalculateSecurityScore()
        {
            // Simple security score calculation
            var score = 100;
            
            // Subtract for various risk factors
            score -= GetCpuUsage() / 10; // High CPU might indicate malware
            score -= GetRamUsage() / 20; // High RAM usage
            
            return Math.Max(0, Math.Min(100, score));
        }

        private string GetThreatType(string threatName)
        {
            var name = threatName.ToLower();
            if (name.Contains("trojan")) return "Trojan";
            if (name.Contains("virus")) return "Virus";
            if (name.Contains("ransomware")) return "Ransomware";
            if (name.Contains("worm")) return "Worm";
            if (name.Contains("spyware")) return "Spyware";
            if (name.Contains("adware")) return "Adware";
            if (name.Contains("rootkit")) return "Rootkit";
            if (name.Contains("backdoor")) return "Backdoor";
            return "Malware";
        }

        #endregion

        public void Dispose()
        {
            _syncTimer?.Stop();
            _syncTimer?.Dispose();
            _httpClient.Dispose();
        }
    }

    #region Data Classes

    public class FileAnalysisRequest
    {
        public string file_path { get; set; } = "";
        public string? file_hash { get; set; }
        public long file_size { get; set; }
        public double? entropy { get; set; }
        public List<string>? suspicious_apis { get; set; }
        public bool is_packed { get; set; }
        public bool is_signed { get; set; }
        public int? section_count { get; set; }
        public int? import_count { get; set; }
        public bool has_network_code { get; set; }
        public bool is_recently_created { get; set; }
    }

    public class MLAnalysisResult
    {
        public string threat_type { get; set; } = "";
        public double confidence { get; set; }
        public string risk_level { get; set; } = "";
        public List<string> explanations { get; set; } = new();
    }

    public class ThreatIntelligence
    {
        public int total_threats { get; set; }
        public int threats_today { get; set; }
        public int threats_this_week { get; set; }
        public Dictionary<string, int> by_severity { get; set; } = new();
        public Dictionary<string, int> by_type { get; set; } = new();
    }

    #endregion
}
