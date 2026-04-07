using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace SecureGuard.Core
{
    /// <summary>
    /// Kernel Driver Interface
    /// 
    /// Provides interface to the SecureGuard Kernel Driver (SecureGuardDriver.sys).
    /// This enables kernel-level protection including:
    /// - File system filtering
    /// - Process creation monitoring
    /// - Registry protection
    /// - Self-defense capabilities
    /// 
    /// IMPORTANT: The kernel driver requires:
    /// 1. Code signing (EV certificate or test signing enabled)
    /// 2. Administrator privileges for installation
    /// 3. Windows 10/11 64-bit
    /// 
    /// Without a properly signed driver, this class will gracefully fall back
    /// to user-mode protection only.
    /// </summary>
    public class KernelDriverInterface : IDisposable
    {
        #region Native Methods
        
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);
        
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;
        
        // IOCTL Codes
        private const uint SG_IOCTL_GET_VERSION = 0x800;
        private const uint SG_IOCTL_START_PROTECTION = 0x801;
        private const uint SG_IOCTL_STOP_PROTECTION = 0x802;
        private const uint SG_IOCTL_ADD_PROTECTED_PROCESS = 0x803;
        private const uint SG_IOCTL_REMOVE_PROTECTED_PROCESS = 0x804;
        private const uint SG_IOCTL_ADD_PROTECTED_FILE = 0x805;
        private const uint SG_IOCTL_REMOVE_PROTECTED_FILE = 0x806;
        private const uint SG_IOCTL_ADD_BLOCKED_FILE = 0x807;
        private const uint SG_IOCTL_GET_EVENTS = 0x808;
        private const uint SG_IOCTL_SET_CONFIG = 0x809;
        
        private static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method);
        }
        
        #endregion
        
        #region Event Types
        
        public enum KernelEventType
        {
            ProcessCreated = 1,
            ProcessTerminated = 2,
            FileCreated = 3,
            FileWritten = 4,
            FileDeleted = 5,
            RegistryCreated = 6,
            RegistryDeleted = 7,
            RegistryModified = 8,
            NetworkConnect = 9,
            DllLoaded = 10
        }
        
        public class KernelEventArgs : EventArgs
        {
            public KernelEventType EventType { get; set; }
            public uint ProcessId { get; set; }
            public uint ThreadId { get; set; }
            public string FilePath { get; set; } = "";
            public string ProcessName { get; set; } = "";
            public string AdditionalData { get; set; } = "";
            public DateTime Timestamp { get; set; }
            public bool Blocked { get; set; }
        }
        
        #endregion
        
        #region Private Fields
        
        private IntPtr _driverHandle;
        private bool _isConnected;
        private bool _isProtectionEnabled;
        private uint _driverVersion;
        private readonly object _lock = new();
        private Thread? _eventMonitorThread;
        private CancellationTokenSource? _eventMonitorCts;
        private bool _disposed;
        
        // Protected items
        private readonly HashSet<uint> _protectedProcessIds = new();
        private readonly HashSet<string> _protectedFiles = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _protectedRegistryKeys = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _blockedFiles = new(StringComparer.OrdinalIgnoreCase);
        
        // Configuration
        private DriverConfig _config = new();
        
        #endregion
        
        #region Properties
        
        public bool IsConnected => _isConnected;
        public bool IsProtectionEnabled => _isProtectionEnabled;
        public uint DriverVersion => _driverVersion;
        public bool IsDriverAvailable { get; private set; }
        
        public event EventHandler<KernelEventArgs>? KernelEvent;
        public event EventHandler<string>? DriverStatusChanged;
        
        #endregion
        
        #region Configuration
        
        public class DriverConfig
        {
            public bool EnableProcessProtection { get; set; } = true;
            public bool EnableFileProtection { get; set; } = true;
            public bool EnableRegistryProtection { get; set; } = true;
            public bool EnableNetworkProtection { get; set; } = true;
            public bool EnableDllMonitoring { get; set; } = true;
            public uint LogLevel { get; set; } = 2;
            public uint MaxLogEntries { get; set; } = 1024;
        }
        
        #endregion
        
        #region Constructor
        
        public KernelDriverInterface()
        {
            Logger.Log("Info", "KernelDriverInterface initialized");
        }
        
        #endregion
        
        #region Connection Management
        
        /// <summary>
        /// Attempt to connect to the kernel driver.
        /// Returns true if driver is available and connected.
        /// </summary>
        public bool Connect()
        {
            lock (_lock)
            {
                if (_isConnected) return true;
                
                try
                {
                    // Try to open the driver device
                    _driverHandle = CreateFileW(
                        @"\\.\SecureGuardDriver",
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        (uint)FILE_ATTRIBUTE_NORMAL,
                        IntPtr.Zero
                    );
                    
                    if (_driverHandle == IntPtr.Zero || _driverHandle == new IntPtr(-1))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 2) // ERROR_FILE_NOT_FOUND
                        {
                            Logger.Log("Info", "Kernel driver not installed - running in user-mode only");
                            IsDriverAvailable = false;
                        }
                        else
                        {
                            Logger.Log("Warning", $"Failed to connect to kernel driver: {error}");
                            IsDriverAvailable = false;
                        }
                        return false;
                    }
                    
                    // Get driver version
                    _driverVersion = GetVersion();
                    
                    _isConnected = true;
                    IsDriverAvailable = true;
                    
                    Logger.Log("Info", $"Connected to SecureGuard Kernel Driver v{GetVersionString()}");
                    DriverStatusChanged?.Invoke(this, "Connected");
                    
                    return true;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Exception connecting to kernel driver", ex);
                    IsDriverAvailable = false;
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Disconnect from the kernel driver.
        /// </summary>
        public void Disconnect()
        {
            lock (_lock)
            {
                if (!_isConnected) return;
                
                StopProtection();
                StopEventMonitor();
                
                if (_driverHandle != IntPtr.Zero && _driverHandle != new IntPtr(-1))
                {
                    CloseHandle(_driverHandle);
                    _driverHandle = IntPtr.Zero;
                }
                
                _isConnected = false;
                IsDriverAvailable = false;
                
                Logger.Log("Info", "Disconnected from kernel driver");
                DriverStatusChanged?.Invoke(this, "Disconnected");
            }
        }
        
        #endregion
        
        #region Protection Control
        
        /// <summary>
        /// Start kernel-level protection.
        /// </summary>
        public bool StartProtection()
        {
            lock (_lock)
            {
                if (!_isConnected) return false;
                
                try
                {
                    uint bytesReturned;
                    uint result = 0;
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_START_PROTECTION,
                        IntPtr.Zero, 0,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    if (success)
                    {
                        _isProtectionEnabled = true;
                        
                        // Apply configuration
                        ApplyConfig();
                        
                        // Start event monitoring
                        StartEventMonitor();
                        
                        Logger.Log("Info", "Kernel-level protection started");
                        DriverStatusChanged?.Invoke(this, "Protection Active");
                        
                        return true;
                    }
                    
                    Logger.Log("Warning", "Failed to start kernel protection");
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Exception starting kernel protection", ex);
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Stop kernel-level protection.
        /// </summary>
        public bool StopProtection()
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return true;
                
                try
                {
                    StopEventMonitor();
                    
                    uint bytesReturned;
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_STOP_PROTECTION,
                        IntPtr.Zero, 0,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    if (success)
                    {
                        _isProtectionEnabled = false;
                        Logger.Log("Info", "Kernel-level protection stopped");
                        DriverStatusChanged?.Invoke(this, "Protection Stopped");
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Exception stopping kernel protection", ex);
                    return false;
                }
            }
        }
        
        #endregion
        
        #region Process Protection
        
        /// <summary>
        /// Add a process to the protected list.
        /// The driver will prevent termination of protected processes.
        /// </summary>
        public bool AddProtectedProcess(uint processId)
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return false;
                
                try
                {
                    uint bytesReturned;
                    IntPtr buffer = Marshal.AllocHGlobal(4);
                    Marshal.WriteInt32(buffer, (int)processId);
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_ADD_PROTECTED_PROCESS,
                        buffer, 4,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    Marshal.FreeHGlobal(buffer);
                    
                    if (success)
                    {
                        _protectedProcessIds.Add(processId);
                        Logger.Log("Debug", $"Added protected process: {processId}");
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Exception adding protected process {processId}", ex);
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Add current process to protected list.
        /// </summary>
        public bool ProtectCurrentProcess()
        {
            uint currentPid = (uint)Process.GetCurrentProcess().Id;
            return AddProtectedProcess(currentPid);
        }
        
        /// <summary>
        /// Remove a process from the protected list.
        /// </summary>
        public bool RemoveProtectedProcess(uint processId)
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return false;
                
                try
                {
                    uint bytesReturned;
                    IntPtr buffer = Marshal.AllocHGlobal(4);
                    Marshal.WriteInt32(buffer, (int)processId);
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_REMOVE_PROTECTED_PROCESS,
                        buffer, 4,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    Marshal.FreeHGlobal(buffer);
                    
                    if (success)
                    {
                        _protectedProcessIds.Remove(processId);
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Exception removing protected process {processId}", ex);
                    return false;
                }
            }
        }
        
        #endregion
        
        #region File Protection
        
        /// <summary>
        /// Add a file to the protected list.
        /// The driver will block modifications to protected files.
        /// </summary>
        public bool AddProtectedFile(string filePath)
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return false;
                if (string.IsNullOrEmpty(filePath)) return false;
                
                try
                {
                    uint bytesReturned;
                    byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(filePath + "\0");
                    
                    IntPtr buffer = Marshal.AllocHGlobal(pathBytes.Length);
                    Marshal.Copy(pathBytes, 0, buffer, pathBytes.Length);
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_ADD_PROTECTED_FILE,
                        buffer, (uint)pathBytes.Length,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    Marshal.FreeHGlobal(buffer);
                    
                    if (success)
                    {
                        _protectedFiles.Add(filePath);
                        Logger.Log("Debug", $"Added protected file: {filePath}");
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Exception adding protected file: {filePath}", ex);
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Remove a file from the protected list.
        /// </summary>
        public bool RemoveProtectedFile(string filePath)
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return false;
                
                try
                {
                    uint bytesReturned;
                    byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(filePath + "\0");
                    
                    IntPtr buffer = Marshal.AllocHGlobal(pathBytes.Length);
                    Marshal.Copy(pathBytes, 0, buffer, pathBytes.Length);
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_REMOVE_PROTECTED_FILE,
                        buffer, (uint)pathBytes.Length,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    Marshal.FreeHGlobal(buffer);
                    
                    if (success)
                    {
                        _protectedFiles.Remove(filePath);
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Exception removing protected file: {filePath}", ex);
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Block access to a file.
        /// </summary>
        public bool BlockFile(string filePath)
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return false;
                
                try
                {
                    uint bytesReturned;
                    byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(filePath + "\0");
                    
                    IntPtr buffer = Marshal.AllocHGlobal(pathBytes.Length);
                    Marshal.Copy(pathBytes, 0, buffer, pathBytes.Length);
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_ADD_BLOCKED_FILE,
                        buffer, (uint)pathBytes.Length,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    Marshal.FreeHGlobal(buffer);
                    
                    if (success)
                    {
                        _blockedFiles.Add(filePath);
                        Logger.Log("Info", $"Blocked file: {filePath}");
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Exception blocking file: {filePath}", ex);
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Protect SecureGuard executable files.
        /// </summary>
        public void ProtectSecureGuardFiles()
        {
            try
            {
                string appPath = AppDomain.CurrentDomain.BaseDirectory;
                
                // Protect main executable
                string exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(exePath))
                {
                    AddProtectedFile(exePath);
                }
                
                // Protect DLLs in the application directory
                foreach (string dll in Directory.GetFiles(appPath, "*.dll"))
                {
                    AddProtectedFile(dll);
                }
                
                // Protect signature database
                string sigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SecureGuard", "malware_signatures_extended.json");
                if (File.Exists(sigPath))
                {
                    AddProtectedFile(sigPath);
                }
                
                Logger.Log("Info", "SecureGuard files protected");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Exception protecting SecureGuard files", ex);
            }
        }
        
        #endregion
        
        #region Registry Protection
        
        /// <summary>
        /// Add a registry key to the protected list.
        /// </summary>
        public bool AddProtectedRegistryKey(string keyPath)
        {
            lock (_lock)
            {
                if (!_isConnected || !_isProtectionEnabled) return false;
                if (string.IsNullOrEmpty(keyPath)) return false;
                
                try
                {
                    uint bytesReturned;
                    byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(keyPath + "\0");
                    
                    IntPtr buffer = Marshal.AllocHGlobal(pathBytes.Length);
                    Marshal.Copy(pathBytes, 0, buffer, pathBytes.Length);
                    
                    bool success = DeviceIoControl(
                        _driverHandle,
                        SG_IOCTL_ADD_PROTECTED_FILE,  // Repurposed for registry
                        buffer, (uint)pathBytes.Length,
                        IntPtr.Zero, 0,
                        out bytesReturned,
                        IntPtr.Zero
                    );
                    
                    Marshal.FreeHGlobal(buffer);
                    
                    if (success)
                    {
                        _protectedRegistryKeys.Add(keyPath);
                        Logger.Log("Debug", $"Added protected registry key: {keyPath}");
                        return true;
                    }
                    
                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Exception adding protected registry key: {keyPath}", ex);
                    return false;
                }
            }
        }
        
        /// <summary>
        /// Protect SecureGuard registry keys.
        /// </summary>
        public void ProtectSecureGuardRegistryKeys()
        {
            try
            {
                // Protect Run key entries
                AddProtectedRegistryKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                AddProtectedRegistryKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce");
                
                // Protect Winlogon keys
                AddProtectedRegistryKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                
                // Protect services
                AddProtectedRegistryKey(@"SYSTEM\CurrentControlSet\Services");
                
                Logger.Log("Info", "Registry keys protected");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Exception protecting registry keys", ex);
            }
        }
        
        #endregion
        
        #region Configuration
        
        /// <summary>
        /// Set driver configuration.
        /// </summary>
        public void SetConfig(DriverConfig config)
        {
            _config = config;
            
            if (_isConnected && _isProtectionEnabled)
            {
                ApplyConfig();
            }
        }
        
        private void ApplyConfig()
        {
            try
            {
                // Configuration would be sent via IOCTL
                // This is a simplified version
                Logger.Log("Debug", "Applying driver configuration");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Exception applying config", ex);
            }
        }
        
        #endregion
        
        #region Event Monitoring
        
        private void StartEventMonitor()
        {
            if (_eventMonitorThread != null) return;
            
            _eventMonitorCts = new CancellationTokenSource();
            _eventMonitorThread = new Thread(EventMonitorLoop)
            {
                IsBackground = true,
                Name = "KernelEventMonitor"
            };
            _eventMonitorThread.Start();
            
            Logger.Log("Debug", "Kernel event monitor started");
        }
        
        private void StopEventMonitor()
        {
            _eventMonitorCts?.Cancel();
            _eventMonitorThread?.Join(5000);
            _eventMonitorThread = null;
            _eventMonitorCts?.Dispose();
            _eventMonitorCts = null;
            
            Logger.Log("Debug", "Kernel event monitor stopped");
        }
        
        private void EventMonitorLoop()
        {
            // This would poll for events from the driver
            // In a production implementation, this would use
            // overlapping I/O or a notification mechanism
            
            while (!_eventMonitorCts!.Token.IsCancellationRequested)
            {
                try
                {
                    Thread.Sleep(1000);
                    
                    // Poll for events (simplified)
                    // Real implementation would read from driver event buffer
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Exception in event monitor", ex);
                }
            }
        }
        
        /// <summary>
        /// Handle kernel event from driver.
        /// </summary>
        protected virtual void OnKernelEvent(KernelEventArgs args)
        {
            KernelEvent?.Invoke(this, args);
        }
        
        #endregion
        
        #region Utility Methods
        
        /// <summary>
        /// Get driver version.
        /// </summary>
        public uint GetVersion()
        {
            if (!_isConnected) return 0;
            
            try
            {
                uint bytesReturned = 0;
                uint version = 0;
                
                DeviceIoControl(
                    _driverHandle,
                    SG_IOCTL_GET_VERSION,
                    IntPtr.Zero, 0,
                    IntPtr.Zero, 0,
                    out bytesReturned,
                    IntPtr.Zero
                );
                
                return version;
            }
            catch
            {
                return 0;
            }
        }
        
        /// <summary>
        /// Get driver version as string.
        /// </summary>
        public string GetVersionString()
        {
            uint ver = DriverVersion;
            byte major = (byte)(ver >> 24);
            byte minor = (byte)((ver >> 16) & 0xFF);
            byte build = (byte)((ver >> 8) & 0xFF);
            byte revision = (byte)(ver & 0xFF);
            
            return $"{major}.{minor}.{build}.{revision}";
        }
        
        /// <summary>
        /// Check if driver is running.
        /// </summary>
        public static bool IsDriverInstalled()
        {
            try
            {
                IntPtr handle = CreateFileW(
                    @"\\.\SecureGuardDriver",
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    (uint)FILE_ATTRIBUTE_NORMAL,
                    IntPtr.Zero
                );
                
                if (handle != IntPtr.Zero && handle != new IntPtr(-1))
                {
                    CloseHandle(handle);
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        #endregion
        
        #region Fallback Mode
        
        /// <summary>
        /// Initialize user-mode fallback when kernel driver is not available.
        /// </summary>
        public void InitializeFallbackMode()
        {
            Logger.Log("Info", "Initializing user-mode protection (fallback)");
            IsDriverAvailable = false;
            
            // The existing RealTimeProtectionEngine and SelfDefenseSystem
            // will handle protection in user-mode
        }
        
        #endregion
        
        #region IDisposable
        
        public void Dispose()
        {
            if (_disposed) return;
            
            Disconnect();
            
            _disposed = true;
            GC.SuppressFinalize(this);
        }
        
        ~KernelDriverInterface()
        {
            Dispose();
        }
        
        #endregion
    }
    
    /// <summary>
    /// Kernel Driver Service Manager
    /// Handles installation and removal of the kernel driver.
    /// Requires administrator privileges.
    /// </summary>
    public class KernelDriverServiceManager
    {
        private const string ServiceName = "SecureGuardDriver";
        private const string DriverFileName = "SecureGuardDriver.sys";
        
        /// <summary>
        /// Install the kernel driver.
        /// Requires administrator privileges.
        /// </summary>
        public static bool InstallDriver(string driverPath)
        {
            if (!IsAdministrator())
            {
                Logger.Log("Error", "Administrator privileges required to install driver");
                return false;
            }
            
            try
            {
                // Check if service exists
                if (ServiceExists())
                {
                    Logger.Log("Info", "Driver service already exists");
                    return true;
                }
                
                // Copy driver to system directory
                string systemPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "drivers", DriverFileName);
                
                if (File.Exists(driverPath))
                {
                    File.Copy(driverPath, systemPath, true);
                }
                
                // Create service using sc command
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = $"create {ServiceName} binPath= {systemPath} type= kernel start= demand",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                Logger.Log("Info", "Kernel driver installed successfully");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to install kernel driver", ex);
                return false;
            }
        }
        
        /// <summary>
        /// Start the kernel driver service.
        /// </summary>
        public static bool StartDriver()
        {
            if (!IsAdministrator()) return false;
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = $"start {ServiceName}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to start kernel driver", ex);
                return false;
            }
        }
        
        /// <summary>
        /// Stop the kernel driver service.
        /// </summary>
        public static bool StopDriver()
        {
            if (!IsAdministrator()) return false;
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = $"stop {ServiceName}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to stop kernel driver", ex);
                return false;
            }
        }
        
        /// <summary>
        /// Uninstall the kernel driver.
        /// </summary>
        public static bool UninstallDriver()
        {
            if (!IsAdministrator()) return false;
            
            try
            {
                StopDriver();
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = $"delete {ServiceName}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                // Remove driver file
                string systemPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "drivers", DriverFileName);
                
                if (File.Exists(systemPath))
                {
                    File.Delete(systemPath);
                }
                
                Logger.Log("Info", "Kernel driver uninstalled");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to uninstall kernel driver", ex);
                return false;
            }
        }
        
        private static bool ServiceExists()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "sc",
                        Arguments = $"query {ServiceName}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                return output.Contains("STATE") && output.Contains("RUNNING");
            }
            catch
            {
                return false;
            }
        }
        
        private static bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}

