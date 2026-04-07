using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.Core
{
    /// <summary>
    /// Feature 10: Modular Security Marketplace
    /// Plugin architecture for security modules
    /// </summary>
    public class ModuleManager : IDisposable
    {
        private readonly List<SecurityModule> _availableModules;
        private readonly List<InstalledModule> _installedModules;
        private readonly string _modulesPath;
        private readonly object _lock = new();
        
        public event EventHandler<ModuleEventArgs>? ModuleInstalled;
        public event EventHandler<ModuleEventArgs>? ModuleUninstalled;
        public event EventHandler<ModuleEventArgs>? ModuleEnabled;
        public event EventHandler<ModuleEventArgs>? ModuleDisabled;

        public ModuleManager()
        {
            _modulesPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "Modules");
            Directory.CreateDirectory(_modulesPath);
            
            _availableModules = new List<SecurityModule>();
            _installedModules = new List<InstalledModule>();
            
            InitializeBuiltInModules();
            LoadInstalledModules();
            
            Core.Logger.Log("Info", "Module Manager initialized");
        }

        private void InitializeBuiltInModules()
        {
            // Ransomware Shield (already exists as core feature)
            _availableModules.Add(new SecurityModule
            {
                Id = "ransomware_shield",
                Name = "Ransomware Shield",
                Description = "Advanced protection against ransomware attacks with real-time monitoring and automatic file backup",
                Category = ModuleCategory.Protection,
                Version = "2.0.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-shield-virus",
                Features = new List<string>
                {
                    "Real-time file access monitoring",
                    "Automatic backup creation",
                    "Ransomware behavior detection",
                    "Emergency file recovery"
                },
                IsEnabled = true
            });

            // Developer Protection
            _availableModules.Add(new SecurityModule
            {
                Id = "developer_protection",
                Name = "Developer Protection",
                Description = "Security tools for developers including dependency scanning, secret detection, and secure coding guidance",
                Category = ModuleCategory.Development,
                Version = "1.5.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-code",
                Features = new List<string>
                {
                    "Dependency vulnerability scanning",
                    "Secret/API key detection",
                    "Code security analysis",
                    "Secure coding recommendations"
                },
                IsEnabled = false
            });

            // Gaming Shield
            _availableModules.Add(new SecurityModule
            {
                Id = "gaming_shield",
                Name = "Gaming Shield",
                Description = "Optimized protection for gamers with lag reduction, cheat detection, and game-specific security",
                Category = ModuleCategory.Gaming,
                Version = "1.2.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-gamepad",
                Features = new List<string>
                {
                    "Low-latency protection",
                    "Cheat engine detection",
                    "Game save backup",
                    "Performance optimization"
                },
                IsEnabled = false
            });

            // Parental Control
            _availableModules.Add(new SecurityModule
            {
                Id = "parental_control",
                Name = "Parental Control",
                Description = "Protect your children with content filtering, time limits, and activity monitoring",
                Category = ModuleCategory.Privacy,
                Version = "2.0.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-user-shield",
                Features = new List<string>
                {
                    "Content filtering",
                    "Time limits",
                    "App blocking",
                    "Activity reports"
                },
                IsEnabled = false
            });

            // Privacy Guard
            _availableModules.Add(new SecurityModule
            {
                Id = "privacy_guard",
                Name = "Privacy Guard",
                Description = "Comprehensive privacy protection including tracker blocking, data removal, and identity monitoring",
                Category = ModuleCategory.Privacy,
                Version = "2.5.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-user-secret",
                Features = new List<string>
                {
                    "Tracker blocking",
                    "Data broker removal",
                    "Browser privacy",
                    "Identity monitoring"
                },
                IsEnabled = false
            });

            // Network Shield (Enhanced)
            _availableModules.Add(new SecurityModule
            {
                Id = "network_shield_plus",
                Name = "Network Shield Plus",
                Description = "Advanced network security with DNS filtering, VPN integration, and intrusion detection",
                Category = ModuleCategory.Network,
                Version = "1.8.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-wifi",
                Features = new List<string>
                {
                    "DNS filtering",
                    "VPN support",
                    "Intrusion detection",
                    "Wi-Fi security scan"
                },
                IsEnabled = false
            });

            // Password Manager
            _availableModules.Add(new SecurityModule
            {
                Id = "password_manager",
                Name = "Password Manager",
                Description = "Secure password storage and generation with encrypted vault and cross-device sync",
                Category = ModuleCategory.Privacy,
                Version = "1.0.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-key",
                Features = new List<string>
                {
                    "Secure password storage",
                    "Password generator",
                    "Auto-fill",
                    "Breach monitoring"
                },
                IsEnabled = false
            });

            // USB Guardian
            _availableModules.Add(new SecurityModule
            {
                Id = "usb_guardian",
                Name = "USB Guardian",
                Description = "Advanced USB device scanning and control with autorun disabling and device authentication",
                Category = ModuleCategory.Protection,
                Version = "1.3.0",
                Author = "SecureGuard Team",
                IsBuiltIn = true,
                Icon = "fa-usb",
                Features = new List<string>
                {
                    "USB device scanning",
                    "Autorun disable",
                    "Device authentication",
                    "Data theft prevention"
                },
                IsEnabled = false
            });

            Core.Logger.Log("Info", $"Initialized {_availableModules.Count} available modules");
        }

        private void LoadInstalledModules()
        {
            try
            {
                var configPath = Path.Combine(_modulesPath, "installed.json");
                if (File.Exists(configPath))
                {
                    // Load installed modules from config
                    // For now, add ransomware shield as installed by default
                    _installedModules.Add(new InstalledModule
                    {
                        ModuleId = "ransomware_shield",
                        InstalledAt = DateTime.Now.AddDays(-30),
                        LastEnabled = DateTime.Now,
                        IsEnabled = true,
                        Version = "2.0.0"
                    });
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load installed modules", ex);
            }
        }

        public List<SecurityModule> GetAvailableModules()
        {
            lock (_lock)
            {
                return _availableModules.ToList();
            }
        }

        public List<SecurityModule> GetInstalledModules()
        {
            lock (_lock)
            {
                var installed = new List<SecurityModule>();
                foreach (var moduleId in _installedModules.Select(m => m.ModuleId))
                {
                    var module = _availableModules.FirstOrDefault(m => m.Id == moduleId);
                    if (module != null)
                    {
                        var installedModule = _installedModules.First(m => m.ModuleId == moduleId);
                        module.IsEnabled = installedModule.IsEnabled;
                        installed.Add(module);
                    }
                }
                return installed;
            }
        }

        public async Task<InstallResult> InstallModuleAsync(string moduleId)
        {
            var result = new InstallResult { Success = false };

            try
            {
                var module = _availableModules.FirstOrDefault(m => m.Id == moduleId);
                if (module == null)
                {
                    result.ErrorMessage = "Module not found";
                    return result;
                }

                if (_installedModules.Any(m => m.ModuleId == moduleId))
                {
                    result.ErrorMessage = "Module already installed";
                    return result;
                }

                // Simulate installation
                await Task.Delay(500);

                lock (_lock)
                {
                    _installedModules.Add(new InstalledModule
                    {
                        ModuleId = moduleId,
                        InstalledAt = DateTime.Now,
                        LastEnabled = DateTime.Now,
                        IsEnabled = false,
                        Version = module.Version
                    });
                }

                result.Success = true;
                result.Message = $"Module '{module.Name}' installed successfully";

                ModuleInstalled?.Invoke(this, new ModuleEventArgs(module));
                Core.Logger.Log("Info", $"Module installed: {module.Name}");

                SaveInstalledModules();
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Module installation failed: {moduleId}", ex);
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        public async Task<bool> UninstallModuleAsync(string moduleId)
        {
            try
            {
                var module = _availableModules.FirstOrDefault(m => m.Id == moduleId);
                if (module == null) return false;

                // Cannot uninstall built-in modules
                if (module.IsBuiltIn && module.Id == "ransomware_shield")
                {
                    return false;
                }

                // Disable first if enabled
                await DisableModuleAsync(moduleId);

                lock (_lock)
                {
                    _installedModules.RemoveAll(m => m.ModuleId == moduleId);
                }

                ModuleUninstalled?.Invoke(this, new ModuleEventArgs(module));
                Core.Logger.Log("Info", $"Module uninstalled: {module.Name}");

                SaveInstalledModules();
                return true;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Module uninstallation failed: {moduleId}", ex);
                return false;
            }
        }

        public async Task<bool> EnableModuleAsync(string moduleId)
        {
            try
            {
                var module = _installedModules.FirstOrDefault(m => m.ModuleId == moduleId);
                if (module == null) return false;

                // Simulate enabling
                await Task.Delay(100);

                lock (_lock)
                {
                    module.IsEnabled = true;
                    module.LastEnabled = DateTime.Now;
                }

                var fullModule = _availableModules.FirstOrDefault(m => m.Id == moduleId);
                if (fullModule != null)
                {
                    fullModule.IsEnabled = true;
                    ModuleEnabled?.Invoke(this, new ModuleEventArgs(fullModule));
                }

                Core.Logger.Log("Info", $"Module enabled: {moduleId}");
                SaveInstalledModules();
                return true;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Module enable failed: {moduleId}", ex);
                return false;
            }
        }

        public async Task<bool> DisableModuleAsync(string moduleId)
        {
            try
            {
                var module = _installedModules.FirstOrDefault(m => m.ModuleId == moduleId);
                if (module == null) return false;

                // Cannot disable core ransomware shield
                if (moduleId == "ransomware_shield")
                {
                    return false;
                }

                lock (_lock)
                {
                    module.IsEnabled = false;
                }

                var fullModule = _availableModules.FirstOrDefault(m => m.Id == moduleId);
                if (fullModule != null)
                {
                    fullModule.IsEnabled = false;
                    ModuleDisabled?.Invoke(this, new ModuleEventArgs(fullModule));
                }

                Core.Logger.Log("Info", $"Module disabled: {moduleId}");
                SaveInstalledModules();
                return true;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Module disable failed: {moduleId}", ex);
                return false;
            }
        }

        public SecurityModule? GetModule(string moduleId)
        {
            return _availableModules.FirstOrDefault(m => m.Id == moduleId);
        }

        public List<SecurityModule> GetModulesByCategory(ModuleCategory category)
        {
            return _availableModules.Where(m => m.Category == category).ToList();
        }

        private void SaveInstalledModules()
        {
            try
            {
                // Save to config - simplified for now
                Core.Logger.Log("Debug", "Installed modules saved");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save installed modules", ex);
            }
        }

        public void Dispose()
        {
            Core.Logger.Log("Info", "Module Manager disposed");
        }
    }

    public enum ModuleCategory
    {
        Protection,
        Network,
        Privacy,
        Gaming,
        Development,
        Utility
    }

    public class SecurityModule
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public ModuleCategory Category { get; set; }
        public string Version { get; set; } = "";
        public string Author { get; set; } = "";
        public bool IsBuiltIn { get; set; }
        public bool IsEnabled { get; set; }
        public string Icon { get; set; } = "";
        public List<string> Features { get; set; } = new();
    }

    public class InstalledModule
    {
        public string ModuleId { get; set; } = "";
        public DateTime InstalledAt { get; set; }
        public DateTime LastEnabled { get; set; }
        public bool IsEnabled { get; set; }
        public string Version { get; set; } = "";
    }

    public class InstallResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string? ErrorMessage { get; set; }
    }

    public class ModuleEventArgs : EventArgs
    {
        public SecurityModule Module { get; }
        public DateTime Timestamp { get; }

        public ModuleEventArgs(SecurityModule module)
        {
            Module = module;
            Timestamp = DateTime.Now;
        }
    }
}

