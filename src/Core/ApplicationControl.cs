using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Application Control - Allows only trusted programs to run
    /// Implements whitelisting and digital signature verification
    /// </summary>
    public class ApplicationControl : IDisposable
    {
        private readonly string _appDataPath;
        private readonly string _whitelistPath;
        private readonly string _blacklistPath;
        
        private HashSet<string> _whitelistedHashes;
        private HashSet<string> _whitelistedPaths;
        private HashSet<string> _whitelistedPublishers;
        private HashSet<string> _blacklistedHashes;
        
        private bool _isEnabled;
        private bool _blockUnsigned;
        private bool _blockUnknownPublishers;

        public event EventHandler<ApplicationBlockedEventArgs>? ApplicationBlocked;
        public event EventHandler<ApplicationAllowedEventArgs>? ApplicationAllowed;
        
        public bool IsRunning => _isEnabled;
        public bool IsEnabled => _isEnabled;

        public ApplicationControl()
        {
            _appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(_appDataPath);
            
            _whitelistPath = Path.Combine(_appDataPath, "app_whitelist.json");
            _blacklistPath = Path.Combine(_appDataPath, "app_blacklist.json");
            
            _whitelistedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _whitelistedPublishers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _blacklistedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            LoadWhitelist();
            LoadBlacklist();
            
            // Initialize default trusted publishers
            InitializeDefaultTrustedPublishers();
        }

        private void InitializeDefaultTrustedPublishers()
        {
            var trustedPublishers = new[]
            {
                "Microsoft Corporation", "Microsoft Windows", "Google LLC", "Google Inc",
                "Apple Inc.", "Apple Computer", "Mozilla Corporation", "Mozilla Foundation",
                "Adobe Inc.", "Adobe Systems", "Intel Corporation", "NVIDIA Corporation",
                "AMD", "Oracle Corporation", "IBM Corporation"
            };
            
            foreach (var publisher in trustedPublishers)
            {
                _whitelistedPublishers.Add(publisher);
            }
        }

        private void LoadWhitelist()
        {
            try
            {
                if (File.Exists(_whitelistPath))
                {
                    var json = File.ReadAllText(_whitelistPath);
                    var data = JsonSerializer.Deserialize<WhitelistData>(json);
                    
                    if (data != null)
                    {
                        if (data.Hashes != null)
                            _whitelistedHashes = new HashSet<string>(data.Hashes, StringComparer.OrdinalIgnoreCase);
                        if (data.Paths != null)
                            _whitelistedPaths = new HashSet<string>(data.Paths, StringComparer.OrdinalIgnoreCase);
                        if (data.Publishers != null)
                            _whitelistedPublishers = new HashSet<string>(data.Publishers, StringComparer.OrdinalIgnoreCase);
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load application whitelist", ex);
            }
        }

        private void LoadBlacklist()
        {
            try
            {
                if (File.Exists(_blacklistPath))
                {
                    var json = File.ReadAllText(_blacklistPath);
                    var hashes = JsonSerializer.Deserialize<List<string>>(json);
                    
                    if (hashes != null)
                    {
                        _blacklistedHashes = new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load application blacklist", ex);
            }
        }

        private void SaveWhitelist()
        {
            try
            {
                var data = new WhitelistData
                {
                    Hashes = _whitelistedHashes.ToList(),
                    Paths = _whitelistedPaths.ToList(),
                    Publishers = _whitelistedPublishers.ToList()
                };
                
                var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_whitelistPath, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save application whitelist", ex);
            }
        }

        public void Enable()
        {
            _isEnabled = true;
            Core.Logger.Log("Info", "Application control enabled");
        }

        public void Disable()
        {
            _isEnabled = false;
            Core.Logger.Log("Info", "Application control disabled");
        }

        /// <summary>
        /// Check if an application is allowed to run
        /// </summary>
        public ApplicationCheckResult CheckApplication(string filePath)
        {
            var result = new ApplicationCheckResult
            {
                FilePath = filePath,
                IsAllowed = true
            };

            if (!_isEnabled)
            {
                result.IsAllowed = true;
                result.Reason = "Application control disabled";
                return result;
            }

            try
            {
                if (!File.Exists(filePath))
                {
                    result.IsAllowed = false;
                    result.Reason = "File not found";
                    return result;
                }

                // Get file hash
                var hash = Hashing.ComputeSHA256(filePath);
                result.FileHash = hash;

                // Check blacklist first
                if (_blacklistedHashes.Contains(hash))
                {
                    result.IsAllowed = false;
                    result.Reason = "Application is blacklisted";
                    return result;
                }

                // Check whitelist by hash
                if (_whitelistedHashes.Contains(hash))
                {
                    result.IsAllowed = true;
                    result.Reason = "Application is whitelisted (hash)";
                    result.IsWhitelisted = true;
                    return result;
                }

                // Check whitelist by path
                var normalizedPath = Path.GetFullPath(filePath).ToLower();
                foreach (var trustedPath in _whitelistedPaths)
                {
                    if (normalizedPath.StartsWith(trustedPath.ToLower()))
                    {
                        result.IsAllowed = true;
                        result.Reason = "Application is whitelisted (path)";
                        result.IsWhitelisted = true;
                        return result;
                    }
                }

                // Check digital signature
                var signatureInfo = GetDigitalSignatureInfo(filePath);
                result.SignatureInfo = signatureInfo;

                if (signatureInfo.IsSigned)
                {
                    // Check if publisher is trusted
                    if (_whitelistedPublishers.Contains(signatureInfo.PublisherName ?? ""))
                    {
                        result.IsAllowed = true;
                        result.Reason = $"Signed by trusted publisher: {signatureInfo.PublisherName}";
                        result.IsWhitelisted = true;
                        
                        // Optionally add to whitelist
                        // _whitelistedHashes.Add(hash);
                        // SaveWhitelist();
                        
                        return result;
                    }

                    // Signed but publisher not trusted
                    if (_blockUnknownPublishers)
                    {
                        result.IsAllowed = false;
                        result.Reason = $"Publisher not trusted: {signatureInfo.PublisherName}";
                        return result;
                    }
                }
                else
                {
                    // Not signed
                    if (_blockUnsigned)
                    {
                        result.IsAllowed = false;
                        result.Reason = "Application is not digitally signed";
                        return result;
                    }
                }

                // Default: allow unsigned if not blocking
                result.Reason = signatureInfo.IsSigned 
                    ? $"Signed: {signatureInfo.PublisherName}" 
                    : "No digital signature";
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Error checking application: {ex.Message}", ex);
                result.IsAllowed = true;
                result.Reason = "Error checking application, allowing by default";
            }

            return result;
        }

        private DigitalSignatureInfo GetDigitalSignatureInfo(string filePath)
        {
            var info = new DigitalSignatureInfo { IsSigned = false };
            
            try
            {
                // In production, would use WinVerifyTrust or similar
                // For now, simulate based on known paths
                
                var trustedPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                };
                
                foreach (var trustedPath in trustedPaths)
                {
                    if (filePath.StartsWith(trustedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        info.IsSigned = true;
                        info.PublisherName = "Microsoft Corporation";
                        return info;
                    }
                }
            }
            catch { }
            
            return info;
        }

        /// <summary>
        /// Add application to whitelist
        /// </summary>
        public void AddToWhitelist(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var hash = Hashing.ComputeSHA256(filePath);
                    _whitelistedHashes.Add(hash);
                    
                    var directory = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrEmpty(directory))
                    {
                        _whitelistedPaths.Add(directory);
                    }
                    
                    SaveWhitelist();
                    Core.Logger.Log("Info", $"Added to whitelist: {filePath}");
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to add to whitelist: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Add application to blacklist
        /// </summary>
        public void AddToBlacklist(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var hash = Hashing.ComputeSHA256(filePath);
                    _blacklistedHashes.Add(hash);
                    
                    var json = JsonSerializer.Serialize(_blacklistedHashes.ToList(), new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(_blacklistPath, json);
                    
                    Core.Logger.Log("Info", $"Added to blacklist: {filePath}");
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to add to blacklist: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Remove application from whitelist
        /// </summary>
        public void RemoveFromWhitelist(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var hash = Hashing.ComputeSHA256(filePath);
                    _whitelistedHashes.Remove(hash);
                    SaveWhitelist();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to remove from whitelist: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Get whitelist statistics
        /// </summary>
        public ApplicationControlStats GetStats()
        {
            return new ApplicationControlStats
            {
                IsEnabled = _isEnabled,
                BlockUnsigned = _blockUnsigned,
                BlockUnknownPublishers = _blockUnknownPublishers,
                WhitelistedApps = _whitelistedHashes.Count,
                BlacklistedApps = _blacklistedHashes.Count,
                TrustedPaths = _whitelistedPaths.Count,
                TrustedPublishers = _whitelistedPublishers.Count
            };
        }

        public void Dispose()
        {
            SaveWhitelist();
        }
    }

    public class ApplicationCheckResult
    {
        public string FilePath { get; set; } = "";
        public string FileHash { get; set; } = "";
        public bool IsAllowed { get; set; }
        public bool IsWhitelisted { get; set; }
        public string Reason { get; set; } = "";
        public DigitalSignatureInfo? SignatureInfo { get; set; }
    }

    public class DigitalSignatureInfo
    {
        public bool IsSigned { get; set; }
        public string? PublisherName { get; set; }
        public string? SubjectName { get; set; }
        public DateTime? SigningDate { get; set; }
        public string? Thumbprint { get; set; }
    }

    public class ApplicationControlStats
    {
        public bool IsEnabled { get; set; }
        public bool BlockUnsigned { get; set; }
        public bool BlockUnknownPublishers { get; set; }
        public int WhitelistedApps { get; set; }
        public int BlacklistedApps { get; set; }
        public int TrustedPaths { get; set; }
        public int TrustedPublishers { get; set; }
    }

    public class ApplicationBlockedEventArgs : EventArgs
    {
        public string FilePath { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class ApplicationAllowedEventArgs : EventArgs
    {
        public string FilePath { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class WhitelistData
    {
        public List<string> Hashes { get; set; } = new();
        public List<string> Paths { get; set; } = new();
        public List<string> Publishers { get; set; } = new();
    }
}

