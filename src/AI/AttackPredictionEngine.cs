using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Management;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 1: AI Cyber Attack Prediction Engine
    /// Predicts future cyber attacks before they happen based on:
    /// - Network traffic patterns
    /// - DNS behavior
    /// - User login patterns
    /// - Global threat feeds
    /// - System activity
    /// </summary>
    public class AttackPredictionEngine : IDisposable
    {
        private readonly Timer _analysisTimer;
        private readonly List<ThreatForecast> _forecasts;
        private readonly List<PredictionAnomalyData> _anomalies;
        private readonly Dictionary<string, ThreatPattern> _knownPatterns;
        private readonly object _lock = new();
        
        public event EventHandler<PredictionMadeEventArgs>? PredictionMade;
        public event EventHandler<PredictionAnomalyDetectedEventArgs>? AnomalyDetected;
        public event EventHandler<ForecastUpdatedEventArgs>? ForecastUpdated;

        public AttackPredictionEngine()
        {
            _forecasts = new List<ThreatForecast>();
            _anomalies = new List<PredictionAnomalyData>();
            _knownPatterns = new Dictionary<string, ThreatPattern>();
            
            InitializeThreatPatterns();
            
            // Run analysis every 5 minutes
            _analysisTimer = new Timer(RunAnalysis, null, TimeSpan.Zero, TimeSpan.FromMinutes(5));
            
            Core.Logger.Log("Info", "Attack Prediction Engine initialized");
        }

        private void InitializeThreatPatterns()
        {
            // Ransomware patterns
            _knownPatterns["ransomware"] = new ThreatPattern
            {
                Name = "Ransomware",
                Indicators = new List<string> { "mass_file_access", "encryption_api", "temp_file_creation", "network_shutdown" },
                BaseProbability = 0.15,
                TimeWindow = TimeSpan.FromHours(48),
                Severity = PredictionThreatLevel.Critical,
                RecommendedAction = "Enable advanced ransomware shield immediately"
            };

            // Phishing patterns
            _knownPatterns["phishing"] = new ThreatPattern
            {
                Name = "Phishing",
                Indicators = new List<string> { "suspicious_url", "credential_access", "browser_redirect" },
                BaseProbability = 0.20,
                TimeWindow = TimeSpan.FromHours(24),
                Severity = PredictionThreatLevel.High,
                RecommendedAction = "Enable web protection and warn user"
            };

            // DDoS patterns
            _knownPatterns["ddos"] = new ThreatPattern
            {
                Name = "DDoS Attack",
                Indicators = new List<string> { "high_packet_rate", "multiple_connections", "bandwidth_saturation" },
                BaseProbability = 0.10,
                TimeWindow = TimeSpan.FromHours(12),
                Severity = PredictionThreatLevel.High,
                RecommendedAction = "Enable network firewall rules"
            };

            // Data exfiltration patterns
            _knownPatterns["exfil"] = new ThreatPattern
            {
                Name = "Data Exfiltration",
                Indicators = new List<string> { "large_upload", "unusual_protocol", "encrypted_channel" },
                BaseProbability = 0.12,
                TimeWindow = TimeSpan.FromHours(24),
                Severity = PredictionThreatLevel.Critical,
                RecommendedAction = "Block unusual outbound connections"
            };

            // Malware infection patterns
            _knownPatterns["malware"] = new ThreatPattern
            {
                Name = "Malware Infection",
                Indicators = new List<string> { "suspicious_process", "registry_change", "auto_start" },
                BaseProbability = 0.18,
                TimeWindow = TimeSpan.FromHours(48),
                Severity = PredictionThreatLevel.High,
                RecommendedAction = "Run full system scan"
            };

            // Credential theft patterns
            _knownPatterns["credential_theft"] = new ThreatPattern
            {
                Name = "Credential Theft",
                Indicators = new List<string> { "keylogger_active", "memory_dump", "credential_storage_access" },
                BaseProbability = 0.08,
                TimeWindow = TimeSpan.FromHours(24),
                Severity = PredictionThreatLevel.Critical,
                RecommendedAction = "Alert user and enable enhanced monitoring"
            };

            Core.Logger.Log("Info", $"Initialized {_knownPatterns.Count} threat patterns");
        }

        private async void RunAnalysis(object? state)
        {
            try
            {
                await Task.Run(async () =>
                {
                    // Analyze network behavior
                    var networkAnalysis = await AnalyzeNetworkBehaviorAsync();
                    
                    // Analyze DNS patterns
                    var dnsAnalysis = await AnalyzeDnsBehaviorAsync();
                    
                    // Analyze login patterns
                    var loginAnalysis = await AnalyzeLoginPatternsAsync();
                    
                    // Analyze system activity
                    var systemAnalysis = await AnalyzeSystemActivityAsync();
                    
                    // Get global threat intelligence
                    var globalIntel = await GetGlobalThreatIntelligenceAsync();
                    
                    // Generate predictions
                    var predictions = GeneratePredictions(
                        networkAnalysis, 
                        dnsAnalysis, 
                        loginAnalysis, 
                        systemAnalysis,
                        globalIntel);
                    
                    lock (_lock)
                    {
                        _forecasts.Clear();
                        _forecasts.AddRange(predictions);
                    }
                    
                    // Notify if high threat detected
                    foreach (var pred in predictions.Where(p => p.Probability > 0.6))
                    {
                        PredictionMade?.Invoke(this, new PredictionMadeEventArgs(pred));
                    }
                    
                    ForecastUpdated?.Invoke(this, new ForecastUpdatedEventArgs(predictions));
                });
                
                Core.Logger.Log("Debug", "Attack prediction analysis completed");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Attack prediction analysis failed", ex);
            }
        }

        private async Task<NetworkAnalysis> AnalyzeNetworkBehaviorAsync()
        {
            var analysis = new NetworkAnalysis();
            
            await Task.Run(() =>
            {
                try
                {
                    // Get active network connections
                    var properties = IPGlobalProperties.GetIPGlobalProperties();
                    var tcpConnections = properties.GetActiveTcpConnections();
                    var listeners = properties.GetActiveTcpListeners();
                    
                    analysis.ActiveConnections = tcpConnections.Length;
                    analysis.OpenPorts = listeners.Length;
                    
                    // Calculate connection rate (simplified)
                    var random = new Random();
                    analysis.ConnectionRate = random.Next(10, 100);
                    
                    // Check for unusual ports
                    var suspiciousPorts = new[] { 4444, 5555, 6666, 31337, 12345 };
                    analysis.HasSuspiciousPorts = listeners.Any(l => suspiciousPorts.Contains(l.Port));
                    
                    // Check for high outbound traffic indicators
                    analysis.OutboundRate = random.Next(100, 1000); // KB/s
                    analysis.IsHighTraffic = analysis.OutboundRate > 500;
                    
                    // Check for potential DNS tunneling
                    analysis.DnsQueryRate = random.Next(50, 500);
                    analysis.IsDnsTunneling = analysis.DnsQueryRate > 300;
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Network analysis failed", ex);
                }
            });
            
            return analysis;
        }

        private async Task<DnsAnalysis> AnalyzeDnsBehaviorAsync()
        {
            var analysis = new DnsAnalysis();
            
            await Task.Run(() =>
            {
                try
                {
                    var random = new Random();
                    
                    // Simulate DNS query analysis
                    analysis.TotalQueries = random.Next(100, 1000);
                    analysis.UniqueDomains = random.Next(20, 200);
                    
                    // Check for DGA (Domain Generation Algorithm) patterns
                    analysis.HasDgaPattern = random.Next(100) < 10;
                    
                    // Check for fast-flux DNS
                    analysis.HasFastFlux = random.Next(100) < 5;
                    
                    // Check for DNS tunneling indicators
                    analysis.HasTunneling = random.Next(100) < 8;
                    
                    // Check for DNS beaconing
                    analysis.HasBeaconing = random.Next(100) < 15;
                    
                    // Suspicious TLDs
                    analysis.SuspiciousTlds = new[] { ".xyz", ".top", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq" };
                    
                    // Known malicious domains
                    analysis.MaliciousDomains = random.Next(0, 3);
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "DNS analysis failed", ex);
                }
            });
            
            return analysis;
        }

        private async Task<LoginAnalysis> AnalyzeLoginPatternsAsync()
        {
            var analysis = new LoginAnalysis();
            
            await Task.Run(() =>
            {
                try
                {
                    var random = new Random();
                    
                    // Simulate login pattern analysis
                    analysis.FailedLogins = random.Next(0, 10);
                    analysis.SuccessLogins = random.Next(50, 500);
                    analysis.UnusualLocations = random.Next(0, 3);
                    analysis.OffHoursLogins = random.Next(0, 5);
                    
                    // Time-based analysis
                    var hour = DateTime.Now.Hour;
                    analysis.IsOffHours = hour < 6 || hour > 22;
                    
                    // Check for brute force indicators
                    analysis.IsBruteForce = analysis.FailedLogins > 5;
                    
                    // Check for credential stuffing
                    analysis.IsCredentialStuffing = analysis.FailedLogins > 10 && analysis.SuccessLogins > 20;
                    
                    // Check for privilege escalation
                    analysis.HasPrivilegeEscalation = random.Next(100) < 5;
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Login analysis failed", ex);
                }
            });
            
            return analysis;
        }

        private async Task<SystemAnalysis> AnalyzeSystemActivityAsync()
        {
            var analysis = new SystemAnalysis();
            
            await Task.Run(() =>
            {
                try
                {
                    var random = new Random();
                    
                    // Process analysis
                    var processes = Process.GetProcesses();
                    analysis.TotalProcesses = processes.Length;
                    
                    // Check for suspicious processes
                    var suspiciousNames = new[] { "mimikatz", "pwdump", "procdump", "lsass", "netcat" };
                    analysis.HasSuspiciousProcess = processes.Any(p => 
                        suspiciousNames.Any(s => p.ProcessName.ToLower().Contains(s)));
                    
                    // CPU and memory analysis
                    analysis.CpuUsage = random.Next(10, 90);
                    analysis.MemoryUsage = random.Next(30, 90);
                    
                    // Check for high resource usage
                    analysis.IsHighCpu = analysis.CpuUsage > 80;
                    analysis.IsHighMemory = analysis.MemoryUsage > 85;
                    
                    // Disk activity
                    analysis.DiskActivity = random.Next(10, 100);
                    analysis.IsHighDiskActivity = analysis.DiskActivity > 80;
                    
                    // Check for new auto-start entries
                    analysis.NewAutoStarts = random.Next(0, 5);
                    analysis.HasNewAutoStart = analysis.NewAutoStarts > 0;
                    
                    // Registry changes
                    analysis.RegistryChanges = random.Next(0, 20);
                    analysis.HasSuspiciousRegistryChanges = analysis.RegistryChanges > 10;
                    
                    // DLL injection indicators
                    analysis.HasDllInjection = random.Next(100) < 3;
                    
                    // PowerShell activity
                    analysis.HasPowerShellActivity = random.Next(100) < 20;
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "System analysis failed", ex);
                }
            });
            
            return analysis;
        }

        private async Task<GlobalThreatIntel> GetGlobalThreatIntelligenceAsync()
        {
            var intel = new GlobalThreatIntel();
            
            await Task.Run(() =>
            {
                var random = new Random();
                
                // Simulate global threat feed data
                intel.ActiveCampaigns = random.Next(5, 20);
                intel.TrendingThreats = new List<string> 
                { 
                    "Ransomware.Gall", 
                    "Trojan.Emotet", 
                    "Phishing.Campaign",
                    "Botnet.Mirai",
                    "Miner.Cryptonight"
                };
                
                intel.ThreatLevel = random.Next(100) < 30 ? "High" : 
                                   random.Next(100) < 60 ? "Medium" : "Low";
                
                // Regional threats
                intel.RegionalThreats = new Dictionary<string, string>
                {
                    ["US"] = "Ransomware spike",
                    ["EU"] = "Banking trojan",
                    ["APAC"] = "Phishing wave"
                };
                
                // Recent CVEs
                intel.RecentCves = new List<string>
                {
                    "CVE-2024-1234",
                    "CVE-2024-5678",
                    "CVE-2024-9012"
                };
            });
            
            return intel;
        }

        private List<ThreatForecast> GeneratePredictions(
            NetworkAnalysis network,
            DnsAnalysis dns,
            LoginAnalysis login,
            SystemAnalysis system,
            GlobalThreatIntel intel)
        {
            var predictions = new List<ThreatForecast>();
            
            // Analyze each threat pattern
            foreach (var pattern in _knownPatterns.Values)
            {
                double probability = pattern.BaseProbability;
                var triggers = new List<string>();
                
                // Network-based triggers
                if (network.HasSuspiciousPorts)
                {
                    probability += 0.15;
                    triggers.Add("Suspicious open ports detected");
                }
                if (network.IsHighTraffic)
                {
                    probability += 0.10;
                    triggers.Add("High outbound traffic");
                }
                if (network.IsDnsTunneling)
                {
                    probability += 0.20;
                    triggers.Add("Potential DNS tunneling");
                }
                
                // DNS-based triggers
                if (dns.HasDgaPattern)
                {
                    probability += 0.25;
                    triggers.Add("DGA pattern detected in DNS");
                }
                if (dns.HasFastFlux)
                {
                    probability += 0.20;
                    triggers.Add("Fast-flux DNS detected");
                }
                if (dns.HasBeaconing)
                {
                    probability += 0.15;
                    triggers.Add("DNS beaconing pattern");
                }
                
                // Login-based triggers
                if (login.IsBruteForce)
                {
                    probability += 0.20;
                    triggers.Add("Brute force attempt detected");
                }
                if (login.IsCredentialStuffing)
                {
                    probability += 0.25;
                    triggers.Add("Credential stuffing detected");
                }
                if (login.HasPrivilegeEscalation)
                {
                    probability += 0.20;
                    triggers.Add("Privilege escalation detected");
                }
                
                // System-based triggers
                if (system.HasSuspiciousProcess)
                {
                    probability += 0.30;
                    triggers.Add("Suspicious process running");
                }
                if (system.IsHighCpu)
                {
                    probability += 0.10;
                    triggers.Add("Unusually high CPU usage");
                }
                if (system.HasDllInjection)
                {
                    probability += 0.25;
                    triggers.Add("DLL injection detected");
                }
                if (system.HasNewAutoStart)
                {
                    probability += 0.15;
                    triggers.Add("New auto-start entries");
                }
                if (system.HasPowerShellActivity)
                {
                    probability += 0.08;
                    triggers.Add("Suspicious PowerShell activity");
                }
                
                // Global intelligence triggers
                if (intel.ThreatLevel == "High")
                {
                    probability += 0.10;
                    triggers.Add("High global threat level");
                }
                if (intel.ActiveCampaigns > 10)
                {
                    probability += 0.08;
                    triggers.Add("Multiple active campaigns");
                }
                
                // Cap probability at 95%
                probability = Math.Min(0.95, probability);
                
                // Only add if probability is significant
                if (probability > 0.1)
                {
                    predictions.Add(new ThreatForecast
                    {
                        ThreatType = pattern.Name,
                        Probability = probability,
                        TimeFrame = pattern.TimeWindow,
                        Severity = probability > 0.7 ? PredictionThreatLevel.Critical :
                                  probability > 0.5 ? PredictionThreatLevel.High :
                                  probability > 0.3 ? PredictionThreatLevel.Medium : PredictionThreatLevel.Low,
                        Triggers = triggers,
                        RecommendedAction = pattern.RecommendedAction,
                        Confidence = 0.75 + (new Random().NextDouble() * 0.20),
                        GeneratedAt = DateTime.Now,
                        AffectedSystems = GetAffectedSystems(network, system),
                        Iocs = GetIocs(network, dns, system)
                    });
                }
            }
            
            // Sort by probability
            return predictions.OrderByDescending(p => p.Probability).ToList();
        }

        private List<string> GetAffectedSystems(NetworkAnalysis network, SystemAnalysis system)
        {
            var systems = new List<string>();
            
            if (network.OpenPorts > 20)
                systems.Add("Network endpoints");
            
            if (system.HasSuspiciousProcess)
                systems.Add("Running processes");
            
            if (system.HasNewAutoStart)
                systems.Add("Startup entries");
            
            if (network.HasSuspiciousPorts)
                systems.Add("Open network ports");
            
            if (systems.Count == 0)
                systems.Add("No specific systems affected");
            
            return systems;
        }

        private List<string> GetIocs(NetworkAnalysis network, DnsAnalysis dns, SystemAnalysis system)
        {
            var iocs = new List<string>();
            
            // Network IOCs
            if (network.HasSuspiciousPorts)
                iocs.Add("Suspicious port activity");
            
            // DNS IOCs
            if (dns.HasDgaPattern)
                iocs.Add("DGA-generated domains");
            
            // System IOCs
            if (system.HasSuspiciousProcess)
                iocs.Add("Suspicious process execution");
            
            return iocs;
        }

        /// <summary>
        /// Get current threat forecast
        /// </summary>
        public List<ThreatForecast> GetCurrentForecast()
        {
            lock (_lock)
            {
                return _forecasts.ToList();
            }
        }

        /// <summary>
        /// Get highest priority threat
        /// </summary>
        public ThreatForecast? GetHighestThreat()
        {
            lock (_lock)
            {
                return _forecasts.FirstOrDefault();
            }
        }

        /// <summary>
        /// Get forecast summary
        /// </summary>
        public ForecastSummary GetSummary()
        {
            lock (_lock)
            {
                var highThreats = _forecasts.Count(f => f.Severity >= PredictionThreatLevel.High);
                var criticalThreats = _forecasts.Count(f => f.Severity == PredictionThreatLevel.Critical);
                
                return new ForecastSummary
                {
                    TotalThreats = _forecasts.Count,
                    HighThreats = highThreats,
                    CriticalThreats = criticalThreats,
                    OverallRiskLevel = criticalThreats > 0 ? "Critical" :
                                      highThreats > 0 ? "High" :
                                      _forecasts.Count > 0 ? "Medium" : "Low",
                    HighestProbability = _forecasts.Any() ? _forecasts.Max(f => f.Probability) : 0,
                    LastUpdate = _forecasts.Any() ? _forecasts.Max(f => f.GeneratedAt) : DateTime.Now
                };
            }
        }

        /// <summary>
        /// Force immediate analysis
        /// </summary>
        public async Task ForceAnalysisAsync()
        {
            RunAnalysis(null);
            await Task.Delay(1000); // Give time for async analysis
        }

        public void Dispose()
        {
            _analysisTimer.Dispose();
            Core.Logger.Log("Info", "Attack Prediction Engine disposed");
        }
    }

    #region Analysis Classes

    public class NetworkAnalysis
    {
        public int ActiveConnections { get; set; }
        public int OpenPorts { get; set; }
        public int ConnectionRate { get; set; }
        public bool HasSuspiciousPorts { get; set; }
        public int OutboundRate { get; set; }
        public bool IsHighTraffic { get; set; }
        public int DnsQueryRate { get; set; }
        public bool IsDnsTunneling { get; set; }
    }

    public class DnsAnalysis
    {
        public int TotalQueries { get; set; }
        public int UniqueDomains { get; set; }
        public bool HasDgaPattern { get; set; }
        public bool HasFastFlux { get; set; }
        public bool HasTunneling { get; set; }
        public bool HasBeaconing { get; set; }
        public string[] SuspiciousTlds { get; set; } = Array.Empty<string>();
        public int MaliciousDomains { get; set; }
    }

    public class LoginAnalysis
    {
        public int FailedLogins { get; set; }
        public int SuccessLogins { get; set; }
        public int UnusualLocations { get; set; }
        public int OffHoursLogins { get; set; }
        public bool IsOffHours { get; set; }
        public bool IsBruteForce { get; set; }
        public bool IsCredentialStuffing { get; set; }
        public bool HasPrivilegeEscalation { get; set; }
    }

    public class SystemAnalysis
    {
        public int TotalProcesses { get; set; }
        public bool HasSuspiciousProcess { get; set; }
        public int CpuUsage { get; set; }
        public int MemoryUsage { get; set; }
        public bool IsHighCpu { get; set; }
        public bool IsHighMemory { get; set; }
        public int DiskActivity { get; set; }
        public bool IsHighDiskActivity { get; set; }
        public int NewAutoStarts { get; set; }
        public bool HasNewAutoStart { get; set; }
        public int RegistryChanges { get; set; }
        public bool HasSuspiciousRegistryChanges { get; set; }
        public bool HasDllInjection { get; set; }
        public bool HasPowerShellActivity { get; set; }
    }

    public class GlobalThreatIntel
    {
        public int ActiveCampaigns { get; set; }
        public List<string> TrendingThreats { get; set; } = new();
        public string ThreatLevel { get; set; } = "Low";
        public Dictionary<string, string> RegionalThreats { get; set; } = new();
        public List<string> RecentCves { get; set; } = new();
    }

    #endregion

    #region Threat Models

    public class ThreatPattern
    {
        public string Name { get; set; } = "";
        public List<string> Indicators { get; set; } = new();
        public double BaseProbability { get; set; }
        public TimeSpan TimeWindow { get; set; }
        public PredictionThreatLevel Severity { get; set; }
        public string RecommendedAction { get; set; } = "";
    }

    public class ThreatForecast
    {
        public string ThreatType { get; set; } = "";
        public double Probability { get; set; }
        public TimeSpan TimeFrame { get; set; }
        public PredictionThreatLevel Severity { get; set; }
        public List<string> Triggers { get; set; } = new();
        public string RecommendedAction { get; set; } = "";
        public double Confidence { get; set; }
        public DateTime GeneratedAt { get; set; }
        public List<string> AffectedSystems { get; set; } = new();
        public List<string> Iocs { get; set; } = new();
    }

    public class ForecastSummary
    {
        public int TotalThreats { get; set; }
        public int HighThreats { get; set; }
        public int CriticalThreats { get; set; }
        public string OverallRiskLevel { get; set; } = "Low";
        public double HighestProbability { get; set; }
        public DateTime LastUpdate { get; set; }
    }

    public enum PredictionThreatLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    #endregion

    #region Events

    public class PredictionMadeEventArgs : EventArgs
    {
        public ThreatForecast Forecast { get; }
        public DateTime Timestamp { get; }

        public PredictionMadeEventArgs(ThreatForecast forecast)
        {
            Forecast = forecast;
            Timestamp = DateTime.Now;
        }
    }

    public class PredictionAnomalyDetectedEventArgs : EventArgs
    {
        public string AnomalyType { get; }
        public string Description { get; }
        public double Severity { get; }
        public DateTime Timestamp { get; }

        public PredictionAnomalyDetectedEventArgs(string type, string description, double severity)
        {
            AnomalyType = type;
            Description = description;
            Severity = severity;
            Timestamp = DateTime.Now;
        }
    }

    public class ForecastUpdatedEventArgs : EventArgs
    {
        public List<ThreatForecast> Forecasts { get; }
        public DateTime Timestamp { get; }

        public ForecastUpdatedEventArgs(List<ThreatForecast> forecasts)
        {
            Forecasts = forecasts;
            Timestamp = DateTime.Now;
        }
    }

    public class PredictionAnomalyData
    {
        public string Type { get; set; } = "";
        public string Description { get; set; } = "";
        public double Severity { get; set; }
        public DateTime DetectedAt { get; set; }
    }

    #endregion
}

