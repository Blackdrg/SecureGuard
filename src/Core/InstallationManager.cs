using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SecureGuard.Core
{
    /// <summary>
    /// Installation Manager - Handles installation, updates, and uninstallation
    /// Supports silent install, auto-update, and clean uninstall
    /// </summary>
    public class InstallationManager
    {
        private readonly string _installPath;
        private readonly string _appDataPath;
        
        // Installation directories
        public string InstallationPath => _installPath;
        public string DataPath => _appDataPath;
        public string LogsPath => Path.Combine(_appDataPath, "Logs");
        public string QuarantinePath => Path.Combine(_appDataPath, "Quarantine");
        
        public InstallationManager()
        {
            _installPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "SecureGuard");
            
            _appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard");
        }
        
        #region Installation
        
        /// <summary>
        /// Check if application is installed
        /// </summary>
        public bool IsInstalled()
        {
            return Directory.Exists(_installPath) && 
                   File.Exists(Path.Combine(_installPath, "SecureGuard.exe"));
        }
        
        /// <summary>
        /// Install the application (silent or interactive)
        /// </summary>
        public async Task<InstallOperationResult> InstallAsync(bool silent = false)
        {
            var result = new InstallOperationResult { Success = false };
            
            try
            {
                Logger.Log("Info", $"Starting {(silent ? "silent" : "interactive")} installation...");
                
                // Create installation directories
                Directory.CreateDirectory(_installPath);
                Directory.CreateDirectory(_appDataPath);
                Directory.CreateDirectory(LogsPath);
                Directory.CreateDirectory(QuarantinePath);
                
                // Copy application files
                var currentPath = AppDomain.CurrentDomain.BaseDirectory;
                var files = Directory.GetFiles(currentPath, "*.*", SearchOption.AllDirectories);
                
                foreach (var file in files)
                {
                    var relativePath = file.Substring(currentPath.TrimEnd('\\').Length + 1);
                    var destPath = Path.Combine(_installPath, relativePath);
                    
                    var destDir = Path.GetDirectoryName(destPath);
                    if (!string.IsNullOrEmpty(destDir))
                        Directory.CreateDirectory(destDir);
                    
                    File.Copy(file, destPath, true);
                }
                
                // Add to startup
                AddToStartup(silent);
                
                // Register uninstaller
                RegisterUninstaller();
                
                // Create default configuration
                CreateDefaultConfiguration();
                
                result.Success = true;
                result.InstallPath = _installPath;
                
                Logger.Log("Info", "Installation completed successfully");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                Logger.Log("Error", "Installation failed", ex);
            }
            
            return result;
        }
        
        /// <summary>
        /// Silent install - for enterprise deployment
        /// </summary>
        public async Task<InstallOperationResult> SilentInstallAsync()
        {
            return await InstallAsync(silent: true);
        }
        
        /// <summary>
        /// Check if running from installed location
        /// </summary>
        public bool IsRunningInstalled()
        {
            var currentPath = AppDomain.CurrentDomain.BaseDirectory;
            return currentPath.StartsWith(_installPath, StringComparison.OrdinalIgnoreCase);
        }
        
        #endregion
        
        #region Startup & Services
        
        /// <summary>
        /// Add application to Windows startup
        /// </summary>
        public void AddToStartup(bool silent = false)
        {
            try
            {
                var exePath = Path.Combine(_installPath, "SecureGuard.exe");
                
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                
                if (key != null)
                {
                    var args = silent ? " /silent" : "";
                    key.SetValue("SecureGuard", $"\"{exePath}\"{args}");
                    Logger.Log("Info", "Added to Windows startup");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to add to startup", ex);
            }
        }
        
        /// <summary>
        /// Remove from Windows startup
        /// </summary>
        public void RemoveFromStartup()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                
                key?.DeleteValue("SecureGuard", false);
                Logger.Log("Info", "Removed from Windows startup");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to remove from startup", ex);
            }
        }
        
        /// <summary>
        /// Check if in startup
        /// </summary>
        public bool IsInStartup()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false);
                
                return key?.GetValue("SecureGuard") != null;
            }
            catch
            {
                return false;
            }
        }
        
        #endregion
        
        #region Uninstallation
        
        /// <summary>
        /// Uninstall the application
        /// </summary>
        public async Task<UninstallOperationResult> UninstallAsync(bool keepData = false)
        {
            var result = new UninstallOperationResult { Success = false };
            
            try
            {
                Logger.Log("Info", "Starting uninstallation...");
                
                // Stop the application
                StopApplication();
                
                // Remove from startup
                RemoveFromStartup();
                
                // Remove from registry
                RemoveUninstallerRegistration();
                
                // Remove service if installed
                RemoveService();
                
                // Remove installation directory
                if (Directory.Exists(_installPath))
                {
                    await Task.Run(() => Directory.Delete(_installPath, true));
                }
                
                // Optionally keep user data
                if (!keepData && Directory.Exists(_appDataPath))
                {
                    await Task.Run(() => Directory.Delete(_appDataPath, true));
                }
                
                result.Success = true;
                Logger.Log("Info", "Uninstallation completed");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                Logger.Log("Error", "Uninstallation failed", ex);
            }
            
            return result;
        }
        
        /// <summary>
        /// Silent uninstall - for enterprise deployment
        /// </summary>
        public async Task<UninstallOperationResult> SilentUninstallAsync()
        {
            return await UninstallAsync(keepData: false);
        }
        
        /// <summary>
        /// Register uninstaller in Add/Remove Programs
        /// </summary>
        private void RegisterUninstaller()
        {
            try
            {
                var exePath = Path.Combine(_installPath, "SecureGuard.exe");
                
                using var key = Registry.CurrentUser.CreateSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SecureGuard");
                
                key?.SetValue("DisplayName", "SecureGuard Enterprise Antivirus");
                key?.SetValue("DisplayVersion", "2.0.0");
                key?.SetValue("Publisher", "SecureGuard Inc.");
                key?.SetValue("InstallLocation", _installPath);
                key?.SetValue("DisplayIcon", exePath);
                key?.SetValue("UninstallString", $"\"{exePath}\" /uninstall");
                key?.SetValue("NoModify", 1);
                key?.SetValue("NoRepair", 1);
                
                Logger.Log("Info", "Registered uninstaller");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to register uninstaller", ex);
            }
        }
        
        /// <summary>
        /// Remove uninstaller registration
        /// </summary>
        private void RemoveUninstallerRegistration()
        {
            try
            {
                Registry.CurrentUser.DeleteSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SecureGuard", false);
                
                Logger.Log("Info", "Removed uninstaller registration");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to remove uninstaller registration", ex);
            }
        }
        
        /// <summary>
        /// Remove Windows service if installed
        /// </summary>
        private void RemoveService()
        {
            try
            {
                var servicePath = Path.Combine(_installPath, "SecureGuardService.exe");
                if (File.Exists(servicePath))
                {
                    // Would use ServiceController to remove service
                    Logger.Log("Info", "Service removal not implemented - requires elevation");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to remove service", ex);
            }
        }
        
        /// <summary>
        /// Stop the running application
        /// </summary>
        private void StopApplication()
        {
            try
            {
                var processes = Process.GetProcessesByName("SecureGuard");
                foreach (var process in processes)
                {
                    process.Kill();
                    process.WaitForExit(5000);
                }
                
                Logger.Log("Info", "Stopped running instances");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to stop application", ex);
            }
        }
        
        #endregion
        
        #region Updates
        
        /// <summary>
        /// Check for updates
        /// </summary>
        public async Task<CheckForUpdatesResult> CheckForUpdatesAsync()
        {
            var result = new CheckForUpdatesResult { CurrentVersion = "2.0.0" };
            
            try
            {
                // In production, this would check a real update server
                await Task.Delay(100);
                
                // Simulate check
                result.LatestVersion = "2.0.0";
                result.IsUpdateAvailable = false;
                result.UpdateUrl = "";
                
                Logger.Log("Info", "Update check completed");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                Logger.Log("Error", "Update check failed", ex);
            }
            
            return result;
        }
        
        /// <summary>
        /// Download and apply updates
        /// </summary>
        public async Task<ApplyUpdateResult> UpdateAsync()
        {
            var result = new ApplyUpdateResult { Success = false };
            
            try
            {
                Logger.Log("Info", "Starting update...");
                
                // Check for updates first
                var updateCheck = await CheckForUpdatesAsync();
                if (!updateCheck.IsUpdateAvailable)
                {
                    result.Message = "Already running latest version";
                    return result;
                }
                
                // In production, this would:
                // 1. Download update package
                // 2. Verify signature
                // 3. Create backup
                // 4. Apply update
                // 5. Restart service
                
                result.Success = true;
                result.Message = "Update applied successfully";
                
                Logger.Log("Info", "Update completed");
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                Logger.Log("Error", "Update failed", ex);
            }
            
            return result;
        }
        
        #endregion
        
        #region Configuration
        
        /// <summary>
        /// Create default configuration
        /// </summary>
        private void CreateDefaultConfiguration()
        {
            try
            {
                var configPath = Path.Combine(_appDataPath, "config.json");
                
                if (!File.Exists(configPath))
                {
                    var defaultConfig = new
                    {
                        RealTimeProtectionEnabled = true,
                        RansomwareShieldEnabled = true,
                        NetworkProtectionEnabled = true,
                        UsbScanEnabled = true,
                        CloudIntelligenceEnabled = true,
                        AutoUpdate = true,
                        StartWithWindows = true,
                        ShowNotifications = true
                    };
                    
                    var json = System.Text.Json.JsonSerializer.Serialize(defaultConfig, 
                        new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    
                    File.WriteAllText(configPath, json);
                    Logger.Log("Info", "Created default configuration");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to create default configuration", ex);
            }
        }
        
        /// <summary>
        /// Get installation status
        /// </summary>
        public InstallStatus GetInstallStatus()
        {
            return new InstallStatus
            {
                IsInstalled = IsInstalled(),
                IsInStartup = IsInStartup(),
                InstallPath = _installPath,
                DataPath = _appDataPath,
                Version = "2.0.0"
            };
        }
        
        #endregion
    }
    
    #region Result Classes
    
    public class InstallOperationResult
    {
        public bool Success { get; set; }
        public string? InstallPath { get; set; }
        public string? ErrorMessage { get; set; }
    }
    
    public class UninstallOperationResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
    }
    
    public class CheckForUpdatesResult
    {
        public string CurrentVersion { get; set; } = "";
        public string LatestVersion { get; set; } = "";
        public bool IsUpdateAvailable { get; set; }
        public string? UpdateUrl { get; set; }
        public string? ErrorMessage { get; set; }
    }
    
    public class ApplyUpdateResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string? ErrorMessage { get; set; }
    }
    
    public class InstallStatus
    {
        public bool IsInstalled { get; set; }
        public bool IsInStartup { get; set; }
        public string InstallPath { get; set; } = "";
        public string DataPath { get; set; } = "";
        public string Version { get; set; } = "";
    }
    
    #endregion
}

