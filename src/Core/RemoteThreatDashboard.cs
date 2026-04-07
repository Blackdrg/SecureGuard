using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace SecureGuard.Core
{
    /// <summary>
    /// Remote Threat Dashboard - Admin panel for managing multiple devices
    /// </summary>
    public class RemoteThreatDashboard : IDisposable
    {
        private readonly string _appDataPath;
        private readonly string _devicesPath;
        private readonly string _alertsPath;
        private List<DeviceInfo> _devices;
        private List<RemoteAlert> _alerts;

        public event EventHandler<DeviceAlertEventArgs>? DeviceAlert;
        
        public RemoteThreatDashboard()
        {
            _appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(_appDataPath);
            
            _devicesPath = Path.Combine(_appDataPath, "remote_devices.json");
            _alertsPath = Path.Combine(_appDataPath, "remote_alerts.json");
            
            _devices = LoadDevices();
            _alerts = LoadAlerts();
        }

        private List<DeviceInfo> LoadDevices()
        {
            try
            {
                if (File.Exists(_devicesPath))
                {
                    var json = File.ReadAllText(_devicesPath);
                    return JsonSerializer.Deserialize<List<DeviceInfo>>(json) ?? new List<DeviceInfo>();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load remote devices", ex);
            }
            return new List<DeviceInfo>();
        }

        private void SaveDevices()
        {
            try
            {
                var json = JsonSerializer.Serialize(_devices, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_devicesPath, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save remote devices", ex);
            }
        }

        private List<RemoteAlert> LoadAlerts()
        {
            try
            {
                if (File.Exists(_alertsPath))
                {
                    var json = File.ReadAllText(_alertsPath);
                    return JsonSerializer.Deserialize<List<RemoteAlert>>(json) ?? new List<RemoteAlert>();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load alerts", ex);
            }
            return new List<RemoteAlert>();
        }

        private void SaveAlerts()
        {
            try
            {
                var json = JsonSerializer.Serialize(_alerts, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_alertsPath, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save alerts", ex);
            }
        }

        /// <summary>
        /// Register a device with the dashboard
        /// </summary>
        public void RegisterDevice(DeviceInfo device)
        {
            device.RegisteredDate = DateTime.Now;
            device.LastSeen = DateTime.Now;
            
            var existing = _devices.FirstOrDefault(d => d.DeviceId == device.DeviceId);
            if (existing != null)
            {
                existing.LastSeen = DateTime.Now;
                existing.Status = device.Status;
                existing.SecurityScore = device.SecurityScore;
            }
            else
            {
                _devices.Add(device);
            }
            
            SaveDevices();
            Core.Logger.Log("Info", $"Device registered: {device.DeviceName}");
        }

        /// <summary>
        /// Update device status
        /// </summary>
        public void UpdateDeviceStatus(string deviceId, string status, int securityScore)
        {
            var device = _devices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device != null)
            {
                device.Status = status;
                device.SecurityScore = securityScore;
                device.LastSeen = DateTime.Now;
                SaveDevices();
            }
        }

        /// <summary>
        /// Remove a device from the dashboard
        /// </summary>
        public void RemoveDevice(string deviceId)
        {
            var device = _devices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device != null)
            {
                _devices.Remove(device);
                SaveDevices();
                Core.Logger.Log("Info", $"Device removed: {device.DeviceName}");
            }
        }

        /// <summary>
        /// Get all registered devices
        /// </summary>
        public List<DeviceInfo> GetDevices()
        {
            return _devices.ToList();
        }

        /// <summary>
        /// Get device by ID
        /// </summary>
        public DeviceInfo? GetDevice(string deviceId)
        {
            return _devices.FirstOrDefault(d => d.DeviceId == deviceId);
        }

        /// <summary>
        /// Get devices with security issues
        /// </summary>
        public List<DeviceInfo> GetDevicesWithIssues()
        {
            return _devices.Where(d => 
                d.Status == "Warning" || 
                d.Status == "Critical" ||
                d.SecurityScore < 70)
                .ToList();
        }

        /// <summary>
        /// Add an alert for a device
        /// </summary>
        public void AddAlert(RemoteAlert alert)
        {
            alert.Id = Guid.NewGuid().ToString();
            alert.Timestamp = DateTime.Now;
            
            _alerts.Insert(0, alert);
            
            // Keep last 100 alerts
            if (_alerts.Count > 100)
            {
                _alerts = _alerts.Take(100).ToList();
            }
            
            SaveAlerts();
            
            DeviceAlert?.Invoke(this, new DeviceAlertEventArgs
            {
                DeviceId = alert.DeviceId,
                AlertType = alert.Type,
                Message = alert.Message,
                Severity = alert.Severity
            });
        }

        /// <summary>
        /// Get recent alerts
        /// </summary>
        public List<RemoteAlert> GetAlerts(int count = 20)
        {
            return _alerts.Take(count).ToList();
        }

        /// <summary>
        /// Get alerts for a specific device
        /// </summary>
        public List<RemoteAlert> GetAlertsForDevice(string deviceId)
        {
            return _alerts.Where(a => a.DeviceId == deviceId).ToList();
        }

        /// <summary>
        /// Clear alerts for a device
        /// </summary>
        public void ClearAlertsForDevice(string deviceId)
        {
            _alerts.RemoveAll(a => a.DeviceId == deviceId);
            SaveAlerts();
        }

        /// <summary>
        /// Send command to device (simulated)
        /// </summary>
        public DashboardCommand SendCommand(string deviceId, string command, string parameters = "")
        {
            var dashboardCommand = new DashboardCommand
            {
                Id = Guid.NewGuid().ToString(),
                DeviceId = deviceId,
                Command = command,
                Parameters = parameters,
                SentTime = DateTime.Now,
                Status = "Sent"
            };
            
            Core.Logger.Log("Info", $"Command sent to {deviceId}: {command}");
            
            return dashboardCommand;
        }

        /// <summary>
        /// Get dashboard statistics
        /// </summary>
        public DashboardStats GetStats()
        {
            var onlineDevices = _devices.Count(d => d.Status == "Online");
            var warningDevices = _devices.Count(d => d.Status == "Warning");
            var offlineDevices = _devices.Count(d => d.Status == "Offline");
            var avgScore = _devices.Count > 0 ? (int)_devices.Average(d => d.SecurityScore) : 0;
            
            return new DashboardStats
            {
                TotalDevices = _devices.Count,
                OnlineDevices = onlineDevices,
                WarningDevices = warningDevices,
                OfflineDevices = offlineDevices,
                TotalAlerts = _alerts.Count,
                CriticalAlerts = _alerts.Count(a => a.Severity == "Critical"),
                AverageSecurityScore = avgScore
            };
        }

        /// <summary>
        /// Generate dashboard report
        /// </summary>
        public DashboardReport GenerateReport()
        {
            var report = new DashboardReport
            {
                GeneratedDate = DateTime.Now,
                Stats = GetStats(),
                Devices = GetDevices(),
                RecentAlerts = GetAlerts(10),
                DevicesNeedingAttention = GetDevicesWithIssues()
            };
            
            return report;
        }

        public void Dispose()
        {
            SaveDevices();
            SaveAlerts();
        }
    }

    public class DeviceInfo
    {
        public string DeviceId { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public string DeviceType { get; set; } = ""; // Computer, Mobile, Tablet
        public string OsVersion { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string Status { get; set; } = "Offline"; // Online, Offline, Warning, Critical
        public int SecurityScore { get; set; } = 100;
        public int ThreatsBlocked { get; set; }
        public bool IsProtected { get; set; } = true;
        public DateTime RegisteredDate { get; set; }
        public DateTime LastSeen { get; set; }
        public string Location { get; set; } = "";
    }

    public class RemoteAlert
    {
        public string Id { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public string Type { get; set; } = ""; // Threat, Warning, Info
        public string Severity { get; set; } = ""; // Low, Medium, High, Critical
        public string Message { get; set; } = "";
        public string Details { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public bool Acknowledged { get; set; }
    }

    public class DashboardCommand
    {
        public string Id { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string Command { get; set; } = ""; // Scan, Update, Quarantine, Block
        public string Parameters { get; set; } = "";
        public DateTime SentTime { get; set; }
        public DateTime? CompletedTime { get; set; }
        public string Status { get; set; } = ""; // Sent, InProgress, Completed, Failed
        public string Result { get; set; } = "";
    }

    public class DashboardStats
    {
        public int TotalDevices { get; set; }
        public int OnlineDevices { get; set; }
        public int WarningDevices { get; set; }
        public int OfflineDevices { get; set; }
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int AverageSecurityScore { get; set; }
    }

    public class DashboardReport
    {
        public DateTime GeneratedDate { get; set; }
        public DashboardStats Stats { get; set; } = null!;
        public List<DeviceInfo> Devices { get; set; } = new();
        public List<RemoteAlert> RecentAlerts { get; set; } = new();
        public List<DeviceInfo> DevicesNeedingAttention { get; set; } = new();
    }

    public class DeviceAlertEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = "";
        public string AlertType { get; set; } = "";
        public string Message { get; set; } = "";
        public string Severity { get; set; } = "";
    }
}

