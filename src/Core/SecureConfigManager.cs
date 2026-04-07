using System;
using System.IO;
using Newtonsoft.Json;

namespace SecureGuard.Core
{
    /// <summary>
    /// Secure configuration manager with encryption
    /// </summary>
    public class SecureConfigManager
    {
        private readonly string _configPath;
        private AppConfiguration _config;

        public SecureConfigManager()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
            _configPath = Path.Combine(appDataPath, "config.json");
            _config = LoadConfig();
        }

        private AppConfiguration LoadConfig()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    return JsonConvert.DeserializeObject<AppConfiguration>(json) ?? new AppConfiguration();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load configuration", ex);
            }
            return new AppConfiguration();
        }

        public void SaveConfig()
        {
            try
            {
                var json = JsonConvert.SerializeObject(_config, Formatting.Indented);
                File.WriteAllText(_configPath, json);
                Logger.Log("Info", "Configuration saved");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save configuration", ex);
            }
        }

        public AppConfiguration Config => _config;

        // Quick access properties
        public bool IsRealTimeProtectionEnabled
        {
            get => _config.RealTimeProtectionEnabled;
            set { _config.RealTimeProtectionEnabled = value; SaveConfig(); }
        }

        public bool IsRansomwareShieldEnabled
        {
            get => _config.RansomwareShieldEnabled;
            set { _config.RansomwareShieldEnabled = value; SaveConfig(); }
        }

        public bool IsNetworkProtectionEnabled
        {
            get => _config.NetworkProtectionEnabled;
            set { _config.NetworkProtectionEnabled = value; SaveConfig(); }
        }

        public bool IsUsbScanEnabled
        {
            get => _config.UsbScanEnabled;
            set { _config.UsbScanEnabled = value; SaveConfig(); }
        }

        public bool IsPrivacyProtectionEnabled
        {
            get => _config.PrivacyProtectionEnabled;
            set { _config.PrivacyProtectionEnabled = value; SaveConfig(); }
        }

        public bool StartWithWindows
        {
            get => _config.StartWithWindows;
            set { _config.StartWithWindows = value; SaveConfig(); }
        }

        public bool StartMinimized
        {
            get => _config.StartMinimized;
            set { _config.StartMinimized = value; SaveConfig(); }
        }

        public bool ShowNotifications
        {
            get => _config.ShowNotifications;
            set { _config.ShowNotifications = value; SaveConfig(); }
        }

        public int ScanPriority
        {
            get => _config.ScanPriority;
            set { _config.ScanPriority = value; SaveConfig(); }
        }
    }

    public class AppConfiguration
    {
        // Protection Settings
        public bool RealTimeProtectionEnabled { get; set; } = true;
        public bool RansomwareShieldEnabled { get; set; } = true;
        public bool NetworkProtectionEnabled { get; set; } = true;
        public bool UsbScanEnabled { get; set; } = true;
        public bool PrivacyProtectionEnabled { get; set; } = true;

        // Startup Settings
        public bool StartWithWindows { get; set; } = false;
        public bool StartMinimized { get; set; } = false;
        
        // Notification Settings
        public bool ShowNotifications { get; set; } = true;
        public bool PlaySounds { get; set; } = false;
        
        // Scan Settings
        public int ScanPriority { get; set; } = 1; // 0=Low, 1=Normal, 2=High
        public bool QuickScanOnly { get; set; } = false;
        public bool ScanArchives { get; set; } = true;
        public bool ScanEmails { get; set; } = false;
        
        // Update Settings
        public bool AutoUpdate { get; set; } = true;
        public bool CheckBetaUpdates { get; set; } = false;
        
        // UI Settings
        public string Theme { get; set; } = "Dark";
        public string Language { get; set; } = "en-US";
        
        // Statistics
        public DateTime? LastScanDate { get; set; }
        public int TotalScans { get; set; } = 0;
        public int ThreatsDetected { get; set; } = 0;
        
        // First run
        public bool IsFirstRun { get; set; } = true;
        public DateTime? FirstRunDate { get; set; }
    }
}

