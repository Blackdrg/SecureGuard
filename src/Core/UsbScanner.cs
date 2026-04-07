using System;
using System.Collections.Generic;
using System.IO;
using System.Management;

namespace SecureGuard.Core
{
    /// <summary>
    /// USB Auto-Scan module for Level 2 Real-Time Protection
    /// Monitors and scans USB drives when inserted
    /// </summary>
    public class UsbScanner : IDisposable
    {
        private ManagementEventWatcher? _insertWatcher;
        private ManagementEventWatcher? _removeWatcher;
        private readonly ManualScanEngine _scanEngine;
        private readonly QuarantineManager _quarantineManager;
        private bool _isMonitoring;
        
        public event EventHandler<UsbEventArgs>? UsbInserted;
        public event EventHandler<UsbEventArgs>? UsbRemoved;
        public event EventHandler<ScanCompletedEventArgs>? ScanCompleted;

        public UsbScanner(ManualScanEngine scanEngine, QuarantineManager quarantineManager)
        {
            _scanEngine = scanEngine;
            _quarantineManager = quarantineManager;
        }

        /// <summary>
        /// Starts monitoring for USB drive insertion and removal
        /// </summary>
        public void StartMonitoring()
        {
            if (_isMonitoring) return;

            try
            {
                // Watch for USB insertion
                var insertQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'");
                _insertWatcher = new ManagementEventWatcher(insertQuery);
                _insertWatcher.EventArrived += OnUsbInserted;
                _insertWatcher.Start();

                // Watch for USB removal
                var removeQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'");
                _removeWatcher = new ManagementEventWatcher(removeQuery);
                _removeWatcher.EventArrived += OnUsbRemoved;
                _removeWatcher.Start();

                _isMonitoring = true;
                Logger.Log("Info", "USB monitoring started");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to start USB monitoring", ex);
            }
        }

        /// <summary>
        /// Stops USB monitoring
        /// </summary>
        public void StopMonitoring()
        {
            if (!_isMonitoring) return;

            try
            {
                _insertWatcher?.Stop();
                _removeWatcher?.Stop();
                _insertWatcher?.Dispose();
                _removeWatcher?.Dispose();
                _isMonitoring = false;
                Logger.Log("Info", "USB monitoring stopped");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to stop USB monitoring", ex);
            }
        }

        private void OnUsbInserted(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var driveLetter = GetUsbDriveLetter(targetInstance);

                if (!string.IsNullOrEmpty(driveLetter))
                {
                    Logger.Log("Info", $"USB drive inserted: {driveLetter}");
                    UsbInserted?.Invoke(this, new UsbEventArgs(driveLetter));
                    
                    // Auto-scan the USB drive
                    ScanUsbDrive(driveLetter);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error handling USB insertion", ex);
            }
        }

        private void OnUsbRemoved(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                var driveLetter = GetUsbDriveLetter(targetInstance);

                if (!string.IsNullOrEmpty(driveLetter))
                {
                    Logger.Log("Info", $"USB drive removed: {driveLetter}");
                    UsbRemoved?.Invoke(this, new UsbEventArgs(driveLetter));
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error handling USB removal", ex);
            }
        }

        private string? GetUsbDriveLetter(ManagementBaseObject usbDevice)
        {
            try
            {
                var deviceId = usbDevice["DeviceID"]?.ToString();
                if (string.IsNullOrEmpty(deviceId)) return null;

                // Get all removable drives
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType == DriveType.Removable && drive.IsReady)
                    {
                        return drive.Name;
                    }
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Scans a USB drive for threats
        /// </summary>
        public void ScanUsbDrive(string drivePath)
        {
            try
            {
                Logger.Log("Info", $"Starting USB scan for: {drivePath}");
                
                var threats = _scanEngine.ScanFolder(drivePath);
                
                Logger.Log("Info", $"USB scan completed. Threats found: {threats.Count}");
                ScanCompleted?.Invoke(this, new ScanCompletedEventArgs(threats.Count, drivePath));
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"USB scan failed for {drivePath}", ex);
            }
        }

        /// <summary>
        /// Gets list of currently connected removable drives
        /// </summary>
        public List<string> GetConnectedUsbDrives()
        {
            var drives = new List<string>();
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType == DriveType.Removable && drive.IsReady)
                    {
                        drives.Add(drive.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get USB drives", ex);
            }
            return drives;
        }

        public void Dispose()
        {
            StopMonitoring();
            _insertWatcher?.Dispose();
            _removeWatcher?.Dispose();
        }
    }

    public class UsbEventArgs : EventArgs
    {
        public string DrivePath { get; }
        public DateTime Timestamp { get; }

        public UsbEventArgs(string drivePath)
        {
            DrivePath = drivePath;
            Timestamp = DateTime.Now;
        }
    }

    public class ScanCompletedEventArgs : EventArgs
    {
        public int ThreatsFound { get; }
        public string ScanPath { get; }
        public DateTime Timestamp { get; }

        public ScanCompletedEventArgs(int threatsFound, string scanPath)
        {
            ThreatsFound = threatsFound;
            ScanPath = scanPath;
            Timestamp = DateTime.Now;
        }
    }
}

