using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Level 3 - DNS Filtering
    /// Blocks malicious domains and provides safe DNS resolution
    /// </summary>
    public class DnsFilter : IDisposable
    {
        private readonly HashSet<string> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, IPAddress> _customMappings = new();
        private readonly object _lock = new();
        private bool _isRunning;
        private CancellationTokenSource? _cts;
        
        private static readonly string[] MaliciousPatterns = new[]
        {
            "malware", "phishing", "ransomware", "spyware", "trojan",
            "virus", "botnet", "c2", "commandandcontrol", "stealer"
        };

        public event EventHandler<DnsBlockedEventArgs>? DomainBlocked;
        public event EventHandler<DnsResolvedEventArgs>? DomainResolved;

        public DnsFilter()
        {
            LoadBlockedDomains();
        }

        private void LoadBlockedDomains()
        {
            _blockedDomains.Add("malware.example.com");
            _blockedDomains.Add("phishing.test.com");
            Logger.Log("Info", "DNS Filter initialized with blocked domains");
        }

        public void BlockDomain(string domain)
        {
            lock (_lock)
            {
                _blockedDomains.Add(domain);
                Logger.Log("Info", $"Domain blocked: {domain}");
            }
        }

        public void UnblockDomain(string domain)
        {
            lock (_lock)
            {
                _blockedDomains.Remove(domain);
                Logger.Log("Info", $"Domain unblocked: {domain}");
            }
        }

        public bool IsDomainBlocked(string domain)
        {
            lock (_lock)
            {
                if (_blockedDomains.Contains(domain)) return true;
                var domainLower = domain.ToLower();
                foreach (var pattern in MaliciousPatterns)
                {
                    if (domainLower.Contains(pattern)) return true;
                }
                return _customMappings.ContainsKey(domain);
            }
        }

        public async Task<IPAddress?> ResolveWithFilterAsync(string domain)
        {
            try
            {
                if (IsDomainBlocked(domain))
                {
                    DomainBlocked?.Invoke(this, new DnsBlockedEventArgs(domain, "Domain in blocklist"));
                    Logger.Log("Warning", $"DNS blocked: {domain}");
                    return null;
                }

                lock (_lock)
                {
                    if (_customMappings.TryGetValue(domain, out var mappedIp))
                    {
                        DomainResolved?.Invoke(this, new DnsResolvedEventArgs(domain, mappedIp, true));
                        return mappedIp;
                    }
                }

                var addresses = await Dns.GetHostAddressesAsync(domain);
                if (addresses.Length > 0)
                {
                    var ip = addresses[0];
                    DomainResolved?.Invoke(this, new DnsResolvedEventArgs(domain, ip, false));
                    return ip;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"DNS resolution failed for: {domain}", ex);
            }
            return null;
        }

        public void AddCustomMapping(string domain, IPAddress ipAddress)
        {
            lock (_lock)
            {
                _customMappings[domain] = ipAddress;
            }
        }

        public void RemoveCustomMapping(string domain)
        {
            lock (_lock)
            {
                _customMappings.Remove(domain);
            }
        }

        public IEnumerable<string> GetBlockedDomains()
        {
            lock (_lock)
            {
                return new List<string>(_blockedDomains);
            }
        }

        public void Start()
        {
            if (_isRunning) return;
            _cts = new CancellationTokenSource();
            _isRunning = true;
            Logger.Log("Info", "DNS Filter started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            Logger.Log("Info", "DNS Filter stopped");
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }

    public class DnsBlockedEventArgs : EventArgs
    {
        public string Domain { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public DnsBlockedEventArgs(string domain, string reason)
        {
            Domain = domain;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }

    public class DnsResolvedEventArgs : EventArgs
    {
        public string Domain { get; }
        public IPAddress Address { get; }
        public bool IsCustomMapping { get; }
        public DateTime Timestamp { get; }

        public DnsResolvedEventArgs(string domain, IPAddress address, bool isCustomMapping)
        {
            Domain = domain;
            Address = address;
            IsCustomMapping = isCustomMapping;
            Timestamp = DateTime.Now;
        }
    }
}

