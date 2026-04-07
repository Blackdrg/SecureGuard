using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 6: Cross-Device Behavior Intelligence
    /// Shares threat intelligence across user's multiple devices
    /// Creates immunization rules globally when malware infects one device
    /// </summary>
    public class CrossDeviceIntelligence : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly Dictionary<string, DeviceProfile> _registeredDevices = new();
        private readonly Dictionary<string, List<ThreatFingerprint>> _sharedThreats = new();
        private readonly Dictionary<string, ImmunizationRule> _immunizationRules = new();
        private readonly object _lock = new();
        
        private string _deviceId;
        private string _userId;
        private bool _isConnected;
        
        public event EventHandler<DeviceEventArgs>? DeviceRegistered;
        public event EventHandler<ThreatReceivedEventArgs>? ThreatReceivedFromPeer;
        public event EventHandler<ImmunizationEventArgs>? ImmunizationRuleCreated;

        public CrossDeviceIntelligence()
        {
            _httpClient = new HttpClient();
            _deviceId = GetOrCreateDeviceId();
            _userId = GetOrCreateUserId();
            
            Logger.Log("Info", $"Cross-Device Intelligence initialized. Device ID: {_deviceId}");
        }

        /// <summary>
        /// Connects to the cross-device network
        /// </summary>
        public async Task ConnectAsync(string networkEndpoint)
        {
            try
            {
                // In production, this would connect to a real P2P network or cloud service
                _isConnected = true;
                
                // Sync immunization rules from cloud
                await SyncImmunizationRulesAsync();
                
                // Share current device status
                await ShareDeviceStatusAsync();
                
                Logger.Log("Info", "Connected to Cross-Device Intelligence Network");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to connect to cross-device network", ex);
            }
        }

        public void Disconnect()
        {
            _isConnected = false;
            Logger.Log("Info", "Disconnected from Cross-Device Intelligence Network");
        }

        /// <summary>
        /// Registers this device on the network
        /// </summary>
        public async Task RegisterDeviceAsync()
        {
            var profile = new DeviceProfile
            {
                DeviceId = _deviceId,
                UserId = _userId,
                DeviceName = Environment.MachineName,
                OSVersion = Environment.OSVersion.ToString(),
                InstalledApps = GetInstalledApps(),
                LastSeen = DateTime.Now,
                IsOnline = true
            };
            
            lock (_lock)
            {
                _registeredDevices[_deviceId] = profile;
            }
            
            DeviceRegistered?.Invoke(this, new DeviceEventArgs(profile, DeviceEventType.Registered));
            
            await Task.CompletedTask;
            Logger.Log("Info", $"Device registered: {_deviceId}");
        }

        /// <summary>
        /// Shares a threat fingerprint with other devices
        /// </summary>
        public async Task ShareThreatFingerprintAsync(ThreatFingerprint fingerprint)
        {
            if (!_isConnected) return;
            
            fingerprint.SharingDeviceId = _deviceId;
            fingerprint.SharingTimestamp = DateTime.Now;
            
            lock (_lock)
            {
                if (!_sharedThreats.ContainsKey(fingerprint.ThreatHash))
                {
                    _sharedThreats[fingerprint.ThreatHash] = new List<ThreatFingerprint>();
                }
                
                _sharedThreats[fingerprint.ThreatHash].Add(fingerprint);
            }
            
            // Create immunization rule for this threat
            await CreateImmunizationRuleAsync(fingerprint);
            
            // Broadcast to peers (simulated)
            await BroadcastThreatAsync(fingerprint);
            
            Logger.Log("Info", $"Threat fingerprint shared: {fingerprint.ThreatName}");
        }

        /// <summary>
        /// Creates an immunization rule for a threat
        /// </summary>
        private async Task CreateImmunizationRuleAsync(ThreatFingerprint fingerprint)
        {
            var rule = new ImmunizationRule
            {
                RuleId = Guid.NewGuid().ToString(),
                ThreatHash = fingerprint.ThreatHash,
                ThreatName = fingerprint.ThreatName,
                ThreatType = fingerprint.ThreatType,
                CreatedAt = DateTime.Now,
                SourceDevice = fingerprint.SharingDeviceId,
                RuleType = DetermineRuleType(fingerprint),
                RuleData = GenerateRuleData(fingerprint),
                IsActive = true,
                Scope = RuleScope.Global // Applies to all user's devices
            };
            
            lock (_lock)
            {
                _immunizationRules[fingerprint.ThreatHash] = rule;
            }
            
            ImmunizationRuleCreated?.Invoke(this, new ImmunizationEventArgs(rule));
            
            await Task.CompletedTask;
            Logger.Log("Info", $"Immunization rule created: {rule.RuleId} for {fingerprint.ThreatName}");
        }

        /// <summary>
        /// Checks if a file matches any immunization rules
        /// </summary>
        public ImmunizationCheckResult CheckImmunization(string fileHash, string filePath)
        {
            var result = new ImmunizationCheckResult
            {
                FileHash = fileHash,
                FilePath = filePath,
                CheckTime = DateTime.Now
            };
            
            lock (_lock)
            {
                if (_immunizationRules.TryGetValue(fileHash, out var rule))
                {
                    result.IsImmunized = true;
                    result.MatchRule = rule;
                    result.Action = rule.RuleType switch
                    {
                        RuleType.BlockExecution => ImmunizationAction.Block,
                        RuleType.Quarantine => ImmunizationAction.Quarantine,
                        RuleType.Monitor => ImmunizationAction.Monitor,
                        _ => ImmunizationAction.Log
                    };
                }
                else
                {
                    // Check for similar threats
                    var similarRules = _immunizationRules.Values
                        .Where(r => CalculateSimilarity(fileHash, r.ThreatHash) > 0.8)
                        .ToList();
                    
                    if (similarRules.Any())
                    {
                        result.HasSimilarThreats = true;
                        result.SimilarRules = similarRules;
                    }
                }
            }
            
            return result;
        }

        /// <summary>
        /// Gets all registered devices for this user
        /// </summary>
        public List<DeviceProfile> GetUserDevices()
        {
            lock (_lock)
            {
                return _registeredDevices.Values
                    .Where(d => d.UserId == _userId)
                    .OrderByDescending(d => d.LastSeen)
                    .ToList();
            }
        }

        /// <summary>
        /// Gets immunization rules for this device
        /// </summary>
        public List<ImmunizationRule> GetImmunizationRules()
        {
            lock (_lock)
            {
                return _immunizationRules.Values
                    .Where(r => r.IsActive)
                    .OrderByDescending(r => r.CreatedAt)
                    .ToList();
            }
        }

        /// <summary>
        /// Syncs immunization rules from cloud/peer devices
        /// </summary>
        private async Task SyncImmunizationRulesAsync()
        {
            // In production, this would fetch from cloud storage or P2P network
            await Task.Delay(100);
            Logger.Log("Info", "Immunization rules synchronized");
        }

        /// <summary>
        /// Shares device status with network
        /// </summary>
        private async Task ShareDeviceStatusAsync()
        {
            lock (_lock)
            {
                if (_registeredDevices.TryGetValue(_deviceId, out var profile))
                {
                    profile.LastSeen = DateTime.Now;
                    profile.IsOnline = true;
                }
            }
            
            await Task.CompletedTask;
        }

        /// <summary>
        /// Broadcasts threat to peer devices
        /// </summary>
        private async Task BroadcastThreatAsync(ThreatFingerprint fingerprint)
        {
            // In production, this would use P2P networking
            await Task.Delay(50);
            Logger.Log("Info", $"Threat broadcast to peers: {fingerprint.ThreatName}");
        }

        /// <summary>
        /// Receives threat from peer device
        /// </summary>
        public async Task ReceiveThreatFromPeerAsync(ThreatFingerprint fingerprint)
        {
            fingerprint.ReceivedAt = DateTime.Now;
            
            lock (_lock)
            {
                if (!_sharedThreats.ContainsKey(fingerprint.ThreatHash))
                {
                    _sharedThreats[fingerprint.ThreatHash] = new List<ThreatFingerprint>();
                }
                _sharedThreats[fingerprint.ThreatHash].Add(fingerprint);
            }
            
            // Create immunization rule
            await CreateImmunizationRuleAsync(fingerprint);
            
            ThreatReceivedFromPeer?.Invoke(this, new ThreatReceivedEventArgs(fingerprint));
            
            Logger.Log("Info", $"Received threat from peer: {fingerprint.ThreatName} from {fingerprint.SharingDeviceId}");
        }

        /// <summary>
        /// Gets cross-device statistics
        /// </summary>
        public CrossDeviceStats GetStatistics()
        {
            lock (_lock)
            {
                return new CrossDeviceStats
                {
                    TotalDevices = _registeredDevices.Count(d => d.Value.UserId == _userId),
                    OnlineDevices = _registeredDevices.Count(d => d.Value.UserId == _userId && d.Value.IsOnline),
                    SharedThreats = _sharedThreats.Count,
                    ActiveImmunizationRules = _immunizationRules.Count(r => r.Value.IsActive),
                    DeviceId = _deviceId
                };
            }
        }

        private string GetOrCreateDeviceId()
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "device.id");
            
            if (File.Exists(path))
            {
                return File.ReadAllText(path);
            }
            
            var id = Guid.NewGuid().ToString();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, id);
            return id;
        }

        private string GetOrCreateUserId()
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "user.id");
            
            if (File.Exists(path))
            {
                return File.ReadAllText(path);
            }
            
            var id = Guid.NewGuid().ToString();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, id);
            return id;
        }

        private List<string> GetInstalledApps()
        {
            // Simplified - would query installed programs
            return new List<string> { "SecureGuard", "Chrome", "Edge" };
        }

        private RuleType DetermineRuleType(ThreatFingerprint fingerprint)
        {
            return fingerprint.ThreatType.ToLower() switch
            {
                "ransomware" => RuleType.BlockExecution,
                "trojan" => RuleType.BlockExecution,
                "worm" => RuleType.Quarantine,
                "adware" => RuleType.Quarantine,
                "spyware" => RuleType.Monitor,
                _ => RuleType.Log
            };
        }

        private Dictionary<string, object> GenerateRuleData(ThreatFingerprint fingerprint)
        {
            return new Dictionary<string, object>
            {
                ["hash"] = fingerprint.ThreatHash,
                ["name"] = fingerprint.ThreatName,
                ["type"] = fingerprint.ThreatType,
                ["source"] = fingerprint.Source,
                ["created"] = DateTime.Now
            };
        }

        private double CalculateSimilarity(string hash1, string hash2)
        {
            if (string.IsNullOrEmpty(hash1) || string.IsNullOrEmpty(hash2)) return 0;
            if (hash1 == hash2) return 1.0;
            
            // Simple character-based similarity
            int matches = 0;
            var minLen = Math.Min(hash1.Length, hash2.Length);
            for (int i = 0; i < minLen; i++)
            {
                if (hash1[i] == hash2[i]) matches++;
            }
            return (double)matches / Math.Max(hash1.Length, hash2.Length);
        }

        public bool IsConnected => _isConnected;
        public string DeviceId => _deviceId;

        public void Dispose()
        {
            Disconnect();
            _httpClient.Dispose();
        }
    }

    public class DeviceProfile
    {
        public string DeviceId { get; set; } = "";
        public string UserId { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public string OSVersion { get; set; } = "";
        public List<string> InstalledApps { get; set; } = new();
        public DateTime LastSeen { get; set; }
        public bool IsOnline { get; set; }
    }

    public class ThreatFingerprint
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string ThreatHash { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public string Source { get; set; } = "";
        public string SharingDeviceId { get; set; } = "";
        public DateTime SharingTimestamp { get; set; }
        public DateTime? ReceivedAt { get; set; }
    }

    public class ImmunizationRule
    {
        public string RuleId { get; set; } = "";
        public string ThreatHash { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public string SourceDevice { get; set; } = "";
        public RuleType RuleType { get; set; }
        public Dictionary<string, object> RuleData { get; set; } = new();
        public bool IsActive { get; set; }
        public RuleScope Scope { get; set; }
    }

    public class ImmunizationCheckResult
    {
        public string FileHash { get; set; } = "";
        public string FilePath { get; set; } = "";
        public bool IsImmunized { get; set; }
        public ImmunizationRule? MatchRule { get; set; }
        public ImmunizationAction Action { get; set; }
        public bool HasSimilarThreats { get; set; }
        public List<ImmunizationRule> SimilarRules { get; set; } = new();
        public DateTime CheckTime { get; set; }
    }

    public class CrossDeviceStats
    {
        public string DeviceId { get; set; } = "";
        public int TotalDevices { get; set; }
        public int OnlineDevices { get; set; }
        public int SharedThreats { get; set; }
        public int ActiveImmunizationRules { get; set; }
    }

    public enum RuleType
    {
        BlockExecution,
        Quarantine,
        Monitor,
        Log
    }

    public enum RuleScope
    {
        Local,
        Device,
        Global
    }

    public enum ImmunizationAction
    {
        Block,
        Quarantine,
        Monitor,
        Log
    }

    public enum DeviceEventType
    {
        Registered,
        Online,
        Offline,
        Disconnected
    }

    public class DeviceEventArgs : EventArgs
    {
        public DeviceProfile Device { get; }
        public DeviceEventType EventType { get; }
        public DeviceEventArgs(DeviceProfile device, DeviceEventType type) { Device = device; EventType = type; }
    }

    public class ThreatReceivedEventArgs : EventArgs
    {
        public ThreatFingerprint Threat { get; }
        public ThreatReceivedEventArgs(ThreatFingerprint threat) { Threat = threat; }
    }

    public class ImmunizationEventArgs : EventArgs
    {
        public ImmunizationRule Rule { get; }
        public ImmunizationEventArgs(ImmunizationRule rule) { Rule = rule; }
    }
}

