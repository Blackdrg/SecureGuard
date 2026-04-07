using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Device Control - Blocks USB drives, external disks, and unknown devices
    /// </summary>
    public class DeviceControl : IDisposable
    {
        private CancellationTokenSource? _monitorCts;
        private bool _isRunning;
        
        // Blocked device types
        private HashSet<string> _blockedDeviceClasses;
        private HashSet<string> _allowedDevices;
        
        // Device classes that can be blocked
        private static readonly Dictionary<string, string> DeviceClasses = new()
        {
            { "4d36e972-e325-11ce-bfc1-08002be10318", "Network Adapter" },
            { "4d36e967-e325-11ce-bfc1-08002be10318", "Disk Drive" },
            { "4d36e980-e325-11ce-bfc1-08002be10318", "DVD/CD-ROM Drive" },
            { "4d36e965-e325-11ce-bfc1-08002be10318", "Human Interface Device" },
            { "4d36e968-e325-11ce-bfc1-08002be10318", "Monitor" },
            { "4d36e979-e325-11ce-bfc1-08002be10318", "Portable Device" },
            { "6bdd1fc6-810f-11d0-bec7-08002be2092f", "Imaging Device" },
            { "c166523c-fe0c-4a94-a586-f1a80cfbbf3e", "Mobile Device" }
        };

        public event EventHandler<DeviceBlockedEventArgs>? DeviceBlocked;
        public event EventHandler<DeviceAllowedEventArgs>? DeviceAllowed;
        
        public bool IsRunning => _isRunning;
        public bool IsUsbBlockingEnabled { get; set; } = true;
        public bool IsExternalStorageBlockingEnabled { get; set; } = true;

        public DeviceControl()
        {
            _blockedDeviceClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _allowedDevices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            // Default block USB and external storage
            _blockedDeviceClasses.Add("4d36e967-e325-11ce-bfc1-08002be10318"); // Disk Drive
            _blockedDeviceClasses.Add("4d36e979-e325-11ce-bfc1-08002be10318"); // Portable Device
            _blockedDeviceClasses.Add("c166523c-fe0c-4a94-a586-f1a80cfbbf3e"); // Mobile Device
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _monitorCts = new CancellationTokenSource();
            Task.Run(() => MonitorDevices(_monitorCts.Token));
            
            _isRunning = true;
            Core.Logger.Log("Info", "Device control started");
        }

        public void Stop()
        {
            _monitorCts?.Cancel();
            _isRunning = false;
            Core.Logger.Log("Info", "Device control stopped");
        }

        private async Task MonitorDevices(CancellationToken token)
        {
            var previousDevices = new HashSet<string>();
            
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var currentDevices = await GetConnectedDevicesAsync();
                    
                    // Find new devices
                    var newDevices = currentDevices.Except(previousDevices).ToList();
                    
                    foreach (var device in newDevices)
                    {
                        if (ShouldBlockDevice(device))
                        {
                            BlockDevice(device);
                        }
                        else
                        {
                            Core.Logger.Log("Info", $"Device allowed: {device}");
                            DeviceAllowed?.Invoke(this, new DeviceAllowedEventArgs
                            {
                                DeviceId = device,
                                DeviceType = GetDeviceType(device),
                                Timestamp = DateTime.Now
                            });
                        }
                    }
                    
                    previousDevices = new HashSet<string>(currentDevices);
                    
                    await Task.Delay(5000, token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", $"Device monitoring error: {ex.Message}", ex);
                    await Task.Delay(10000, token);
                }
            }
        }

        private async Task<List<string>> GetConnectedDevicesAsync()
        {
            var devices = new List<string>();
            
            await Task.Run(() =>
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        "SELECT * FROM Win32_PnPEntity WHERE Present=TRUE");
                    
                    foreach (ManagementObject device in searcher.Get())
                    {
                        var deviceId = device["DeviceID"]?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(deviceId))
                        {
                            devices.Add(deviceId);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Failed to get device list", ex);
                }
            });
            
            return devices;
        }

        private bool ShouldBlockDevice(string deviceId)
        {
            // Check if device is in allowed list
            foreach (var allowed in _allowedDevices)
            {
                if (deviceId.Contains(allowed, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
            
            // Check if device class is blocked
            foreach (var blockedClass in _blockedDeviceClasses)
            {
                if (deviceId.Contains(blockedClass, StringComparison.OrdinalIgnoreCase))
                {
                    // Additional check for USB/external
                    if (IsUsbBlockingEnabled && IsUsbDevice(deviceId))
                    {
                        return true;
                    }
                    
                    if (IsExternalStorageBlockingEnabled && IsExternalStorage(deviceId))
                    {
                        return true;
                    }
                }
            }
            
            return false;
        }

        private bool IsUsbDevice(string deviceId)
        {
            // USB device IDs typically contain "USB"
            return deviceId.Contains("USB", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsExternalStorage(string deviceId)
        {
            // External storage indicators
            return deviceId.Contains("USB", StringComparison.OrdinalIgnoreCase) ||
                   deviceId.Contains("SD", StringComparison.OrdinalIgnoreCase) ||
                   deviceId.Contains("REMOVABLE", StringComparison.OrdinalIgnoreCase);
        }

        private void BlockDevice(string deviceId)
        {
            Core.Logger.Log("Warning", $"Blocked device: {deviceId}");
            
            DeviceBlocked?.Invoke(this, new DeviceBlockedEventArgs
            {
                DeviceId = deviceId,
                DeviceType = GetDeviceType(deviceId),
                Reason = "Unauthorized device",
                Timestamp = DateTime.Now
            });
        }

        private string GetDeviceType(string deviceId)
        {
            foreach (var kvp in DeviceClasses)
            {
                if (deviceId.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value;
                }
            }
            return "Unknown Device";
        }

        /// <summary>
        /// Add a device to allowed list
        /// </summary>
        public void AllowDevice(string deviceIdentifier)
        {
            _allowedDevices.Add(deviceIdentifier);
            Core.Logger.Log("Info", $"Device added to allow list: {deviceIdentifier}");
        }

        /// <summary>
        /// Remove a device from allowed list
        /// </summary>
        public void RemoveAllowedDevice(string deviceIdentifier)
        {
            _allowedDevices.Remove(deviceIdentifier);
            Core.Logger.Log("Info", $"Device removed from allow list: {deviceIdentifier}");
        }

        /// <summary>
        /// Block a device class
        /// </summary>
        public void BlockDeviceClass(string deviceClass)
        {
            _blockedDeviceClasses.Add(deviceClass);
            Core.Logger.Log("Info", $"Device class blocked: {deviceClass}");
        }

        /// <summary>
        /// Unblock a device class
        /// </summary>
        public void UnblockDeviceClass(string deviceClass)
        {
            _blockedDeviceClasses.Remove(deviceClass);
            Core.Logger.Log("Info", $"Device class unblocked: {deviceClass}");
        }

        /// <summary>
        /// Get current device control status
        /// </summary>
        public DeviceControlStatus GetStatus()
        {
            return new DeviceControlStatus
            {
                IsRunning = _isRunning,
                UsbBlockingEnabled = IsUsbBlockingEnabled,
                ExternalStorageBlockingEnabled = IsExternalStorageBlockingEnabled,
                BlockedDeviceClasses = _blockedDeviceClasses.ToList(),
                AllowedDevices = _allowedDevices.ToList()
            };
        }

        public void Dispose()
        {
            Stop();
            _monitorCts?.Dispose();
        }
    }

    public class DeviceBlockedEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = "";
        public string DeviceType { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class DeviceAllowedEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = "";
        public string DeviceType { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class DeviceControlStatus
    {
        public bool IsRunning { get; set; }
        public bool UsbBlockingEnabled { get; set; }
        public bool ExternalStorageBlockingEnabled { get; set; }
        public List<string> BlockedDeviceClasses { get; set; } = new();
        public List<string> AllowedDevices { get; set; } = new();
    }
}

