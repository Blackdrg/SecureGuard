using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Performance Optimizer - Ensures antivirus uses minimal resources
    /// Target: CPU < 5% idle, RAM < 150MB, minimal disk I/O
    /// </summary>
    public class PerformanceOptimizer : IDisposable
    {
        private CancellationTokenSource? _cts;
        private bool _isRunning;
        
        // Performance targets
        private const int TargetCpuPercent = 5;
        private const long TargetRamMB = 150;
        
        // Current usage
        private int _currentCpuUsage;
        private long _currentRamUsage;
        private int _currentDiskActivity;
        
        // Throttling
        private int _scanDelayMs = 100;
        private bool _isLowPowerMode;
        
        public event EventHandler<PerformanceAlertEventArgs>? PerformanceAlert;
        
        public int CurrentCpuUsage => _currentCpuUsage;
        public long CurrentRamUsage => _currentRamUsage;
        public int CurrentDiskActivity => _currentDiskActivity;
        public bool IsLowPowerMode => _isLowPowerMode;
        
        public PerformanceOptimizer()
        {
            Logger.Log("Info", "PerformanceOptimizer initialized");
        }
        
        /// <summary>
        /// Start performance monitoring
        /// </summary>
        public void Start()
        {
            if (_isRunning) return;
            
            _cts = new CancellationTokenSource();
            _isRunning = true;
            
            Task.Run(() => MonitorPerformance(_cts.Token));
            
            Logger.Log("Info", "Performance monitoring started");
        }
        
        /// <summary>
        /// Stop performance monitoring
        /// </summary>
        public void Stop()
        {
            _cts?.Cancel();
            _isRunning = false;
            Logger.Log("Info", "Performance monitoring stopped");
        }
        
        /// <summary>
        /// Enable low power mode for gaming/performance
        /// </summary>
        public void SetLowPowerMode(bool enabled)
        {
            _isLowPowerMode = enabled;
            _scanDelayMs = enabled ? 500 : 100;
            
            Logger.Log("Info", $"Low power mode: {enabled}");
        }
        
        /// <summary>
        /// Get optimal delay for scanning operations
        /// </summary>
        public int GetScanDelay()
        {
            // Adjust delay based on system load
            if (_currentCpuUsage > 50)
                return 500;
            if (_currentCpuUsage > 30)
                return 200;
            if (_currentCpuUsage > 10)
                return _scanDelayMs;
            
            return _scanDelayMs / 2; // Minimum delay
        }
        
        /// <summary>
        /// Should skip intensive operations
        /// </summary>
        public bool ShouldSkipIntensiveOperations()
        {
            // Skip if CPU is too high
            if (_currentCpuUsage > 80)
                return true;
            
            // Skip if RAM is too high
            if (_currentRamUsage > 500 * 1024 * 1024) // 500MB
                return true;
            
            // Skip if user is in low power mode
            if (_isLowPowerMode)
                return true;
            
            return false;
        }
        
        /// <summary>
        /// Monitor system performance
        /// </summary>
        private async Task MonitorPerformance(CancellationToken token)
        {
            var lastCpuCheck = DateTime.MinValue;
            var lastRamCheck = DateTime.MinValue;
            
            while (!token.IsCancellationRequested)
            {
                try
                {
                    // Check CPU every 2 seconds
                    if (DateTime.Now - lastCpuCheck > TimeSpan.FromSeconds(2))
                    {
                        _currentCpuUsage = GetCpuUsage();
                        lastCpuCheck = DateTime.Now;
                        
                        if (_currentCpuUsage > 80)
                        {
                            PerformanceAlert?.Invoke(this, new PerformanceAlertEventArgs(
                                "CPU", _currentCpuUsage, "High CPU usage detected"));
                        }
                    }
                    
                    // Check RAM every 5 seconds
                    if (DateTime.Now - lastRamCheck > TimeSpan.FromSeconds(5))
                    {
                        _currentRamUsage = GetRamUsage();
                        lastRamCheck = DateTime.Now;
                        
                        // Alert if over target
                        if (_currentRamUsage > TargetRamMB * 1024 * 1024)
                        {
                            var overTarget = (int)((_currentRamUsage / (1024 * 1024)) - TargetRamMB);
                            PerformanceAlert?.Invoke(this, new PerformanceAlertEventArgs(
                                "RAM", (int)(_currentRamUsage / (1024 * 1024)), 
                                $"RAM usage {overTarget}MB over target"));
                        }
                    }
                    
                    await Task.Delay(1000, token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Performance monitoring error", ex);
                    await Task.Delay(5000, token);
                }
            }
        }
        
        /// <summary>
        /// Get current CPU usage
        /// </summary>
        private int GetCpuUsage()
        {
            try
            {
                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // First call returns 0
                Thread.Sleep(100);
                return (int)cpuCounter.NextValue();
            }
            catch
            {
                // Fallback estimation
                var processes = Process.GetProcesses();
                long totalTime = 0;
                
                foreach (var process in processes)
                {
                    try
                    {
                        totalTime += process.TotalProcessorTime.Ticks;
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
                
                return Math.Min(100, (int)(totalTime / 10000));
            }
        }
        
        /// <summary>
        /// Get current RAM usage by SecureGuard
        /// </summary>
        private long GetRamUsage()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                return currentProcess.WorkingSet64;
            }
            catch
            {
                return 0;
            }
        }
        
        /// <summary>
        /// Get available system RAM
        /// </summary>
        public long GetAvailableSystemRam()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var freeMemory = Convert.ToInt64(obj["FreePhysicalMemory"]);
                    return freeMemory * 1024; // Convert KB to bytes
                }
            }
            catch { }
            
            return 0;
        }
        
        /// <summary>
        /// Get performance report
        /// </summary>
        public PerformanceReport GetReport()
        {
            return new PerformanceReport
            {
                CpuUsage = _currentCpuUsage,
                RamUsageMB = (int)(_currentRamUsage / (1024 * 1024)),
                TargetCpuPercent = TargetCpuPercent,
                TargetRamMB = (int)TargetRamMB,
                IsWithinTargets = _currentCpuUsage <= TargetCpuPercent && 
                                 (_currentRamUsage / (1024 * 1024)) <= TargetRamMB,
                LowPowerMode = _isLowPowerMode,
                DiskActivity = _currentDiskActivity
            };
        }
        
        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
    
    public class PerformanceAlertEventArgs : EventArgs
    {
        public string Metric { get; }
        public int Value { get; }
        public string Message { get; }
        
        public PerformanceAlertEventArgs(string metric, int value, string message)
        {
            Metric = metric;
            Value = value;
            Message = message;
        }
    }
    
    public class PerformanceReport
    {
        public int CpuUsage { get; set; }
        public int RamUsageMB { get; set; }
        public int TargetCpuPercent { get; set; }
        public int TargetRamMB { get; set; }
        public bool IsWithinTargets { get; set; }
        public bool LowPowerMode { get; set; }
        public int DiskActivity { get; set; }
    }
}

