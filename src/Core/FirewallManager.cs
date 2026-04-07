using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Firewall Manager - Advanced firewall panel with inbound/outbound rules and port blocking
    /// </summary>
    public class FirewallManager : IDisposable
    {
        private readonly string _appDataPath;
        private readonly string _rulesPath;
        private List<FirewallRule> _rules;
        private bool _isEnabled;
        
        // Common ports and their services
        private static readonly Dictionary<int, string> CommonPorts = new()
        {
            { 20, "FTP Data" }, { 21, "FTP Control" }, { 22, "SSH" }, { 23, "Telnet" },
            { 25, "SMTP" }, { 53, "DNS" }, { 80, "HTTP" }, { 110, "POP3" },
            { 143, "IMAP" }, { 443, "HTTPS" }, { 445, "SMB" }, { 993, "IMAPS" },
            { 995, "POP3S" }, { 1433, "MS SQL" }, { 3306, "MySQL" }, { 3389, "RDP" },
            { 5432, "PostgreSQL" }, { 5900, "VNC" }, { 8080, "HTTP Proxy" },
            { 8443, "HTTPS Alt" }, { 27017, "MongoDB" }
        };

        public event EventHandler<FirewallConnectionBlockedEventArgs>? ConnectionBlocked;
        public event EventHandler<FirewallRuleAddedEventArgs>? RuleAdded;
        
        public bool IsEnabled => _isEnabled;
        public int BlockedConnections { get; private set; }

        public FirewallManager()
        {
            _appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(_appDataPath);
            
            _rulesPath = Path.Combine(_appDataPath, "firewall_rules.json");
            _rules = new List<FirewallRule>();
            
            LoadRules();
            
            if (_rules.Count == 0)
            {
                InitializeDefaultRules();
            }
        }

        private void LoadRules()
        {
            try
            {
                if (File.Exists(_rulesPath))
                {
                    var json = File.ReadAllText(_rulesPath);
                    _rules = JsonSerializer.Deserialize<List<FirewallRule>>(json) ?? new List<FirewallRule>();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load firewall rules", ex);
            }
        }

        private void SaveRules()
        {
            try
            {
                var json = JsonSerializer.Serialize(_rules, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_rulesPath, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save firewall rules", ex);
            }
        }

        private void InitializeDefaultRules()
        {
            // Default rules
            _rules.AddRange(new[]
            {
                new FirewallRule
                {
                    Name = "Block All Incoming",
                    Direction = "Inbound",
                    Action = "Block",
                    Enabled = false,
                    Description = "Block all incoming connections"
                },
                new FirewallRule
                {
                    Name = "Allow HTTP/HTTPS",
                    Direction = "Outbound",
                    Action = "Allow",
                    Protocol = "TCP",
                    LocalPorts = "80,443",
                    Enabled = true,
                    Description = "Allow web traffic"
                },
                new FirewallRule
                {
                    Name = "Block Telnet",
                    Direction = "Outbound",
                    Action = "Block",
                    Protocol = "TCP",
                    RemotePort = 23,
                    Enabled = true,
                    Description = "Block insecure Telnet protocol"
                },
                new FirewallRule
                {
                    Name = "Block FTP",
                    Direction = "Both",
                    Action = "Block",
                    Protocol = "TCP",
                    RemotePorts = "20,21",
                    Enabled = true,
                    Description = "Block FTP connections"
                }
            });
            
            SaveRules();
        }

        public void Enable()
        {
            _isEnabled = true;
            Core.Logger.Log("Info", "Firewall enabled");
        }

        public void Disable()
        {
            _isEnabled = false;
            Core.Logger.Log("Info", "Firewall disabled");
        }

        /// <summary>
        /// Add a new firewall rule
        /// </summary>
        public void AddRule(FirewallRule rule)
        {
            rule.Id = Guid.NewGuid().ToString();
            rule.CreatedDate = DateTime.Now;
            
            _rules.Add(rule);
            SaveRules();
            
            Core.Logger.Log("Info", $"Firewall rule added: {rule.Name}");
            RuleAdded?.Invoke(this, new FirewallRuleAddedEventArgs { Rule = rule });
        }

        /// <summary>
        /// Remove a firewall rule
        /// </summary>
        public void RemoveRule(string ruleId)
        {
            var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule != null)
            {
                _rules.Remove(rule);
                SaveRules();
                Core.Logger.Log("Info", $"Firewall rule removed: {rule.Name}");
            }
        }

        /// <summary>
        /// Enable/disable a rule
        /// </summary>
        public void SetRuleEnabled(string ruleId, bool enabled)
        {
            var rule = _rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule != null)
            {
                rule.Enabled = enabled;
                SaveRules();
                Core.Logger.Log("Info", $"Firewall rule {(enabled ? "enabled" : "disabled")}: {rule.Name}");
            }
        }

        /// <summary>
        /// Check if a connection should be blocked
        /// </summary>
        public bool ShouldBlockConnection(string localIp, int localPort, string remoteIp, int remotePort, string direction)
        {
            if (!_isEnabled) return false;

            foreach (var rule in _rules.Where(r => r.Enabled))
            {
                // Check direction
                if (!string.IsNullOrEmpty(rule.Direction) && 
                    !rule.Direction.Equals("Both", StringComparison.OrdinalIgnoreCase) &&
                    !rule.Direction.Equals(direction, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Check protocol
                if (!string.IsNullOrEmpty(rule.Protocol))
                {
                    // Simplified - would need actual packet inspection
                }

                // Check remote port
                if (rule.RemotePort > 0 && rule.RemotePort == remotePort)
                {
                    if (rule.Action == "Block")
                    {
                        BlockedConnections++;
                        Core.Logger.Log("Warning", $"Connection blocked: {remoteIp}:{remotePort}");
                        ConnectionBlocked?.Invoke(this, new FirewallConnectionBlockedEventArgs
                        {
                            RemoteIp = remoteIp,
                            RemotePort = remotePort,
                            Rule = rule.Name,
                            Timestamp = DateTime.Now
                        });
                        return true;
                    }
                }

                // Check remote ports list
                if (!string.IsNullOrEmpty(rule.RemotePorts))
                {
                    var ports = rule.RemotePorts.Split(',').Select(p => int.TryParse(p.Trim(), out var port) ? port : 0);
                    if (ports.Contains(remotePort))
                    {
                        if (rule.Action == "Block")
                        {
                            BlockedConnections++;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Block a specific IP address
        /// </summary>
        public void BlockIpAddress(string ipAddress)
        {
            var rule = new FirewallRule
            {
                Name = $"Block {ipAddress}",
                Direction = "Both",
                Action = "Block",
                RemoteIp = ipAddress,
                Enabled = true,
                Description = $"Manually blocked IP: {ipAddress}",
                IsAutomatic = true
            };
            
            AddRule(rule);
        }

        /// <summary>
        /// Unblock an IP address
        /// </summary>
        public void UnblockIpAddress(string ipAddress)
        {
            var rule = _rules.FirstOrDefault(r => 
                r.RemoteIp == ipAddress && r.IsAutomatic);
            
            if (rule != null)
            {
                RemoveRule(rule.Id);
            }
        }

        /// <summary>
        /// Block a port
        /// </summary>
        public void BlockPort(int port, string direction = "Both")
        {
            var portName = CommonPorts.ContainsKey(port) ? CommonPorts[port] : port.ToString();
            var rule = new FirewallRule
            {
                Name = $"Block {portName} ({port})",
                Direction = direction,
                Action = "Block",
                Protocol = "TCP",
                RemotePort = port,
                Enabled = true,
                Description = $"Manually blocked port: {port}",
                IsAutomatic = true
            };
            
            AddRule(rule);
        }

        /// <summary>
        /// Get all firewall rules
        /// </summary>
        public List<FirewallRule> GetRules()
        {
            return _rules.ToList();
        }

        /// <summary>
        /// Get active network connections
        /// </summary>
        public async Task<List<NetworkConnection>> GetActiveConnectionsAsync()
        {
            var connections = new List<NetworkConnection>();
            
            await Task.Run(() =>
            {
                try
                {
                    var tcpConnections = IPGlobalProperties.GetIPGlobalProperties()
                        .GetActiveTcpConnections();
                    
                    foreach (var conn in tcpConnections)
                    {
                        var direction = conn.LocalEndPoint.Address == IPAddress.Loopback ? "Outbound" : "Inbound";
                        
                        connections.Add(new NetworkConnection
                        {
                            LocalAddress = conn.LocalEndPoint.Address.ToString(),
                            LocalPort = conn.LocalEndPoint.Port,
                            RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                            RemotePort = conn.RemoteEndPoint.Port,
                            State = conn.State.ToString(),
                            Direction = direction,
                            Protocol = "TCP"
                        });
                    }
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Failed to get active connections", ex);
                }
            });
            
            return connections;
        }

        /// <summary>
        /// Get firewall statistics
        /// </summary>
        public FirewallStats GetStats()
        {
            return new FirewallStats
            {
                IsEnabled = _isEnabled,
                TotalRules = _rules.Count,
                EnabledRules = _rules.Count(r => r.Enabled),
                BlockedConnections = BlockedConnections,
                InboundRules = _rules.Count(r => r.Direction == "Inbound"),
                OutboundRules = _rules.Count(r => r.Direction == "Outbound"),
                BlockedRules = _rules.Count(r => r.Action == "Block"),
                AllowedRules = _rules.Count(r => r.Action == "Allow")
            };
        }

        public void Dispose()
        {
            SaveRules();
        }
    }

    public class FirewallRule
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Direction { get; set; } = "Outbound"; // Inbound, Outbound, Both
        public string Action { get; set; } = "Allow"; // Allow, Block
        public string Protocol { get; set; } = "TCP"; // TCP, UDP, Any
        public string LocalIp { get; set; } = "";
        public int LocalPort { get; set; }
        public string LocalPorts { get; set; } = "";
        public string RemoteIp { get; set; } = "";
        public int RemotePort { get; set; }
        public string RemotePorts { get; set; } = "";
        public bool Enabled { get; set; } = true;
        public bool IsAutomatic { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
    }

    public class NetworkConnection
    {
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
        public string Direction { get; set; } = "";
        public string Protocol { get; set; } = "";
    }

    public class FirewallStats
    {
        public bool IsEnabled { get; set; }
        public int TotalRules { get; set; }
        public int EnabledRules { get; set; }
        public int BlockedConnections { get; set; }
        public int InboundRules { get; set; }
        public int OutboundRules { get; set; }
        public int BlockedRules { get; set; }
        public int AllowedRules { get; set; }
    }

    public class FirewallConnectionBlockedEventArgs : EventArgs
    {
        public string RemoteIp { get; set; } = "";
        public int RemotePort { get; set; }
        public string Rule { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class FirewallRuleAddedEventArgs : EventArgs
    {
        public FirewallRule Rule { get; set; } = null!;
    }
}

