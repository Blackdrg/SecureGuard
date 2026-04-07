using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Linq;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Web Protection System - Blocks malicious websites, fake login pages, 
    /// scam downloads, and provides phishing protection
    /// </summary>
    public class WebProtection : IDisposable
    {
        private readonly string _blockedDomainsFile;
        private HashSet<string> _blockedDomains;
        private HashSet<string> _phishingDomains;
        private bool _isEnabled;
        
        // Known malicious URL patterns
        private static readonly string[] MaliciousPatterns = new[]
        {
            "login.verify", "secure.bank", "account.update", "password.reset",
            "signin.verify", "confirm.account", "verify.identity", "secure.login",
            "free.gift", "winner.selected", "claim.prize", "urgent.action",
            "update.required", "suspended.account", "unusual.activity",
            "support.help", "customer.service", "technical.support"
        };

        // Known legitimate domains that are often spoofed
        private static readonly string[] SpoofedDomains = new[]
        {
            "paypal", "amazon", "apple", "microsoft", "google", "facebook",
            "netflix", "bankofamerica", "wellsfargo", "chase", "citibank",
            "IRS", "socialsecurity", "amazonaws", "microsoftonline"
        };

        public event EventHandler<MaliciousUrlEventArgs>? MaliciousUrlDetected;
        public event EventHandler<PhishingAttemptEventArgs>? PhishingAttemptDetected;
        
        public bool IsEnabled => _isEnabled;
        public int BlockedCount { get; private set; }

        public WebProtection()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
            
            _blockedDomainsFile = Path.Combine(appDataPath, "blocked_domains.json");
            _blockedDomains = LoadBlockedDomains();
            _phishingDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            // Initialize with known malicious domains
            InitializeDefaultBlocklist();
        }

        private void InitializeDefaultBlocklist()
        {
            // Add common malware distribution domains
            var malwareDomains = new[]
            {
                "malware-example.com", "virus-download.net", "free-crack.com",
                "keygen-generator.com", "serial-key.org", "warez-download.net",
                "torrent-finder.com", "free-movie-stream.com", "adult-content.net",
                "phishing-test.com", "suspicious-download.net"
            };
            
            foreach (var domain in malwareDomains)
            {
                _blockedDomains.Add(domain.ToLower());
            }
        }

        private HashSet<string> LoadBlockedDomains()
        {
            try
            {
                if (File.Exists(_blockedDomainsFile))
                {
                    var json = File.ReadAllText(_blockedDomainsFile);
                    return new HashSet<string>(
                        Newtonsoft.Json.JsonConvert.DeserializeObject<string[]>(json) ?? Array.Empty<string>(),
                        StringComparer.OrdinalIgnoreCase
                    );
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load blocked domains", ex);
            }
            
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        private void SaveBlockedDomains()
        {
            try
            {
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(_blockedDomains.ToArray(), Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(_blockedDomainsFile, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save blocked domains", ex);
            }
        }

        public void Enable()
        {
            _isEnabled = true;
            Logger.Log("Info", "Web protection enabled");
        }

        public void Disable()
        {
            _isEnabled = false;
            Logger.Log("Info", "Web protection disabled");
        }

        /// <summary>
        /// Check if a URL is malicious
        /// </summary>
        public bool IsUrlMalicious(string url)
        {
            if (!_isEnabled || string.IsNullOrEmpty(url)) return false;
            
            try
            {
                var uri = new Uri(url);
                var host = uri.Host.ToLower();
                var path = uri.PathAndQuery.ToLower();
                
                // Check against blocked domains
                foreach (var blocked in _blockedDomains)
                {
                    if (host.Contains(blocked) || host.EndsWith("." + blocked))
                    {
                        Logger.Log("Warning", $"Blocked malicious domain: {host}");
                        BlockedCount++;
                        return true;
                    }
                }
                
                // Check for phishing patterns
                if (IsPhishingUrl(url))
                {
                    Logger.Log("Warning", $"Phishing URL detected: {url}");
                    BlockedCount++;
                    return true;
                }
                
                // Check malicious patterns in URL
                foreach (var pattern in MaliciousPatterns)
                {
                    if (path.Contains(pattern.Replace(".", "")))
                    {
                        Logger.Log("Warning", $"Malicious URL pattern detected: {pattern}");
                        BlockedCount++;
                        return true;
                    }
                }
                
                // Check for suspicious TLDs often used in malware/phishing
                var suspiciousTlds = new[] { ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work" };
                foreach (var tld in suspiciousTlds)
                {
                    if (host.EndsWith(tld))
                    {
                        // Additional checks for suspicious TLDs
                        if (host.Length > 30 || host.Contains("-"))
                        {
                            Logger.Log("Warning", $"Suspicious domain with TLD {tld}: {host}");
                            BlockedCount++;
                            return true;
                        }
                    }
                }
                
                // Check for IP address in URL (often malicious)
                if (IPAddress.TryParse(host, out _))
                {
                    Logger.Log("Warning", $"URL with IP address instead of domain: {url}");
                    BlockedCount++;
                    return true;
                }
                
                // Check for excessive subdomains
                var subdomainCount = host.Split('.').Length - 1;
                if (subdomainCount > 4)
                {
                    Logger.Log("Warning", $"Excessive subdomains detected: {host}");
                    BlockedCount++;
                    return true;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Error checking URL: {ex.Message}", ex);
            }
            
            return false;
        }

        /// <summary>
        /// Check if URL is a phishing attempt
        /// </summary>
        public bool IsPhishingUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var host = uri.Host.ToLower();
                var path = uri.PathAndQuery.ToLower();
                
                // Check if domain looks like a spoofed legitimate service
                foreach (var spoofed in SpoofedDomains)
                {
                    if (host.Contains(spoofed.ToLower()))
                    {
                        // Check if it's actually the legitimate domain
                        var legitimateDomains = new[]
                        {
                            "paypal.com", "amazon.com", "apple.com", "microsoft.com", 
                            "google.com", "facebook.com", "netflix.com", "bankofamerica.com",
                            "wellsfargo.com", "chase.com", "citibank.com", "irs.gov", "ssa.gov"
                        };
                        
                        bool isLegitimate = legitimateDomains.Any(legit => 
                            host == legit || host.EndsWith("." + legit));
                        
                        if (!isLegitimate)
                        {
                            // Check for common phishing indicators
                            var phishingIndicators = new[] { "login", "signin", "verify", "secure", 
                                "account", "update", "confirm", "password", "credential" };
                            
                            foreach (var indicator in phishingIndicators)
                            {
                                if (path.Contains(indicator))
                                {
                                    PhishingAttemptDetected?.Invoke(this, new PhishingAttemptEventArgs
                                    {
                                        Url = url,
                                        SpoofedBrand = spoofed,
                                        Indicator = indicator,
                                        Timestamp = DateTime.Now
                                    });
                                    return true;
                                }
                            }
                        }
                    }
                }
                
                // Check for login/auth related paths on unknown domains
                var authPaths = new[] { "/login", "/signin", "/auth", "/account", "/verify", 
                    "/password", "/reset", "/confirm", "/register", "/signup" };
                
                foreach (var authPath in authPaths)
                {
                    if (path.Contains(authPath))
                    {
                        // Additional verification needed
                        if (!_blockedDomains.Contains(host) && !IsKnownSafeDomain(host))
                        {
                            // Potentially suspicious - log for analysis
                            Logger.Log("Info", $"Potential phishing: {url}");
                        }
                    }
                }
            }
            catch { }
            
            return false;
        }

        private bool IsKnownSafeDomain(string host)
        {
            // In production, this would check against a larger safe list
            var safeDomains = new[]
            {
                "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
                "twitter.com", "linkedin.com", "github.com", "stackoverflow.com", "reddit.com"
            };
            
            return safeDomains.Any(safe => host == safe || host.EndsWith("." + safe));
        }

        /// <summary>
        /// Block a domain
        /// </summary>
        public void BlockDomain(string domain)
        {
            _blockedDomains.Add(domain.ToLower());
            SaveBlockedDomains();
            Logger.Log("Info", $"Domain blocked: {domain}");
        }

        /// <summary>
        /// Unblock a domain
        /// </summary>
        public void UnblockDomain(string domain)
        {
            _blockedDomains.Remove(domain.ToLower());
            SaveBlockedDomains();
            Logger.Log("Info", $"Domain unblocked: {domain}");
        }

        /// <summary>
        /// Get list of blocked domains
        /// </summary>
        public List<string> GetBlockedDomains()
        {
            return _blockedDomains.ToList();
        }

        /// <summary>
        /// Add domain to phishing list
        /// </summary>
        public void ReportPhishing(string domain)
        {
            _phishingDomains.Add(domain.ToLower());
            _blockedDomains.Add(domain.ToLower());
            SaveBlockedDomains();
            Logger.Log("Warning", $"Phishing domain reported: {domain}");
        }

        /// <summary>
        /// Get protection statistics
        /// </summary>
        public WebProtectionStats GetStats()
        {
            return new WebProtectionStats
            {
                IsEnabled = _isEnabled,
                BlockedCount = BlockedCount,
                BlockedDomainsCount = _blockedDomains.Count,
                PhishingDomainsCount = _phishingDomains.Count
            };
        }

        public void Dispose()
        {
            SaveBlockedDomains();
        }
    }

    public class MaliciousUrlEventArgs : EventArgs
    {
        public string Url { get; set; } = "";
        public string Domain { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class PhishingAttemptEventArgs : EventArgs
    {
        public string Url { get; set; } = "";
        public string SpoofedBrand { get; set; } = "";
        public string Indicator { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class WebProtectionStats
    {
        public bool IsEnabled { get; set; }
        public int BlockedCount { get; set; }
        public int BlockedDomainsCount { get; set; }
        public int PhishingDomainsCount { get; set; }
    }
}

