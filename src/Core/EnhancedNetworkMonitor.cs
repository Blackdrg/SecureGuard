using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Enhanced Network Monitor - Real-time network traffic analysis
    /// Monitors active connections, DNS queries, and detects suspicious network activity
    /// </summary>
    public class EnhancedNetworkMonitor : IDisposable
    {
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;
        private bool _isRunning;
        
        // Known malicious IP ranges (simplified local database)
        private readonly List<(string ip, string threat)> _knownMaliciousIPs = new()
        {
            ("185.234.218.0/24", "C2 Server"),
            ("91.121.87.0/24", "Malware Hosting"),
            ("195.154.181.0/24", "Command & Control"),
            ("23.129.64.0/24", "Tor Exit Node"),
            ("103.253.145.0/24", "Suspicious"),
            ("45.33.32.0/24", "Known Malware"),
            ("104.16.0.0/12", "Cloudflare - Check reputation"),
            ("157.240.0.0/16", "Facebook"),
            ("140.82.112.0/20", "GitHub")
        };

        // Suspicious ports
        private readonly HashSet<int> _suspiciousPorts = new()
        {
            4444,  // Metasploit default
            5555,  // Android ADB
            6666,  // IRC Bot
            6667,  // IRC
            31337, // Back Orifice
            12345, // NetBus
            27374, // SubSeven
            1234,  // Malware
            9001,  // Tor
            9050,  // Tor
            1080,  // SOCKS Proxy
            3128,  // HTTP Proxy
            8080,  // HTTP Proxy
            3389,  // RDP
            5900,  // VNC
            22,    // SSH (brute force target)
            23     // Telnet (deprecated)
        };

        public event EventHandler<NetworkThreatDetectedEventArgs>? ThreatDetected;
        public event EventHandler<NetworkConnectionEventArgs>? ConnectionDetected;
        
        public bool IsRunning => _isRunning;
        
        public EnhancedNetworkMonitor()
        {
            Logger.Log("Info", "Enhanced Network Monitor initialized");
        }

        /// <summary>
        /// Start network monitoring
        /// </summary>
        public void Start()
        {
            if (_isRunning) return;
            
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorNetworkAsync(_cts.Token));
            _isRunning = true;
            Logger.Log("Info", "Enhanced Network Monitor started");
        }

        /// <summary>
        /// Stop network monitoring
        /// </summary>
        public void Stop()
        {
            _cts?.Cancel();
            _isRunning = false;
            Logger.Log("Info", "Enhanced Network Monitor stopped");
        }

        private async Task MonitorNetworkAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, token); // Check every 5 seconds
                    
                    // Monitor for suspicious activity
                    CheckNetworkConnections();
                    CheckDNSCache();
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Network monitoring error", ex);
                }
            }
        }

        private void CheckNetworkConnections()
        {
            try
            {
                var connections = GetActiveConnections();
                
                foreach (var conn in connections)
                {
                    // Check for suspicious ports
                    if (_suspiciousPorts.Contains(conn.RemotePort))
                    {
                        var threatName = GetPortThreatName(conn.RemotePort);
                        ThreatDetected?.Invoke(this, new NetworkThreatDetectedEventArgs(
                            conn.RemoteAddress,
                            conn.RemotePort,
                            threatName,
                            "Suspicious port activity",
                            ThreatSeverity.High
                        ));
                    }

                    // Check for suspicious IPs
                    foreach (var (ip, threat) in _knownMaliciousIPs)
                    {
                        if (conn.RemoteAddress.StartsWith(ip.Split('/')[0].Split('.')[0] + "."))
                        {
                            ThreatDetected?.Invoke(this, new NetworkThreatDetectedEventArgs(
                                conn.RemoteAddress,
                                conn.RemotePort,
                                threat,
                                "Known malicious IP",
                                ThreatSeverity.Critical
                            ));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error checking network connections", ex);
            }
        }

        private void CheckDNSCache()
        {
            try
            {
                // Read DNS cache from system
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ipconfig",
                        Arguments = "/displaydns",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                // Check for suspicious DNS entries (simplified)
                var suspiciousDomains = new[] { "malware", "virus", "ransomware", "cryptolocker" };
                foreach (var domain in suspiciousDomains)
                {
                    if (output.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        Logger.Log("Warning", $"Suspicious DNS entry: {domain}");
                    }
                }
            }
            catch
            {
                // DNS cache check is optional
            }
        }

        private string GetPortThreatName(int port)
        {
            return port switch
            {
                4444 => "Metasploit Default",
                5555 => "Android ADB Exploit",
                6666 => "IRC Bot",
                6667 => "IRC Command Channel",
                31337 => "Back Orifice",
                12345 => "NetBus Trojan",
                27374 => "SubSeven Trojan",
                1234 => "Malware Port",
                9001 or 9050 => "Tor Network",
                1080 or 3128 or 8080 => "Proxy/Exploit",
                3389 => "RDP Brute Force Risk",
                5900 => "VNC Exploit Risk",
                _ => "Suspicious Port"
            };
        }

        /// <summary>
        /// Get all active network connections
        /// </summary>
        public List<NetworkConnectionInfo> GetActiveConnections()
        {
            var connections = new List<NetworkConnectionInfo>();
            
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                
                // TCP connections
                var tcpConnections = properties.GetActiveTcpConnections();
                foreach (var conn in tcpConnections)
                {
                    connections.Add(new NetworkConnectionInfo
                    {
                        Protocol = "TCP",
                        LocalAddress = conn.LocalEndPoint.Address.ToString(),
                        LocalPort = conn.LocalEndPoint.Port,
                        RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                        RemotePort = conn.RemoteEndPoint.Port,
                        State = conn.State.ToString(),
                        ProcessId = GetProcessIdForConnection(conn),
                        ProcessName = GetProcessNameForPort(conn.LocalEndPoint.Port)
                    });
                }

                // UDP endpoints
                var udpListeners = properties.GetActiveUdpListeners();
                foreach (var listener in udpListeners)
                {
                    connections.Add(new NetworkConnectionInfo
                    {
                        Protocol = "UDP",
                        LocalAddress = listener.Address.ToString(),
                        LocalPort = listener.Port,
                        RemoteAddress = "*",
                        RemotePort = 0,
                        State = "Listening",
                        ProcessName = GetProcessNameForPort(listener.Port)
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error getting active connections", ex);
            }
            
            return connections;
        }

        /// <summary>
        /// Get network statistics for the system
        /// </summary>
        public NetworkStatistics GetNetworkStatistics()
        {
            var stats = new NetworkStatistics();
            
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                long totalBytesSent = 0;
                long totalBytesReceived = 0;
                long totalPacketsSent = 0;
                long totalPacketsReceived = 0;
                
                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        var ipStats = ni.GetIPStatistics();
                        totalBytesSent += ipStats.BytesSent;
                        totalBytesReceived += ipStats.BytesReceived;
                        totalPacketsSent += ipStats.UnicastPacketsSent;
                        totalPacketsReceived += ipStats.UnicastPacketsReceived;
                    }
                }
                
                stats.TotalBytesSent = totalBytesSent;
                stats.TotalBytesReceived = totalBytesReceived;
                stats.TotalPacketsSent = totalPacketsSent;
                stats.TotalPacketsReceived = totalPacketsReceived;
                stats.ActiveConnections = GetActiveConnections().Count;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error getting network statistics", ex);
            }
            
            return stats;
        }

        /// <summary>
        /// Get per-process network usage
        /// </summary>
        public List<ProcessNetworkUsage> GetProcessNetworkUsage()
        {
            var usage = new List<ProcessNetworkUsage>();
            
            try
            {
                // This is a simplified version - real implementation would use ETW
                var connections = GetActiveConnections();
                var processGroups = connections
                    .Where(c => !string.IsNullOrEmpty(c.ProcessName))
                    .GroupBy(c => c.ProcessName);
                
                foreach (var group in processGroups)
                {
                    usage.Add(new ProcessNetworkUsage
                    {
                        ProcessName = group.Key,
                        ConnectionCount = group.Count(),
                        LocalPorts = group.Select(c => c.LocalPort).Distinct().ToList()
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error getting process network usage", ex);
            }
            
            return usage;
        }

        private int GetProcessIdForConnection(TcpConnectionInformation conn)
        {
            // Simplified - would need more complex logic with netstat
            return 0;
        }

        private string GetProcessNameForPort(int port)
        {
            try
            {
                // Check common ports for process names
                return port switch
                {
                    80 => "HTTP",
                    443 => "HTTPS",
                    53 => "DNS",
                    25 => "SMTP",
                    110 => "POP3",
                    143 => "IMAP",
                    21 => "FTP",
                    22 => "SSH",
                    23 => "Telnet",
                    3389 => "RDP",
                    8080 => "HTTP-Proxy",
                    _ => "Unknown"
                };
            }
            catch
            {
                return "Unknown";
            }
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }

    public class NetworkConnectionInfo
    {
        public string Protocol { get; set; } = "";
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
    }

    public class NetworkStatistics
    {
        public long TotalBytesSent { get; set; }
        public long TotalBytesReceived { get; set; }
        public long TotalPacketsSent { get; set; }
        public long TotalPacketsReceived { get; set; }
        public int ActiveConnections { get; set; }
    }

    public class ProcessNetworkUsage
    {
        public string ProcessName { get; set; } = "";
        public int ConnectionCount { get; set; }
        public List<int> LocalPorts { get; set; } = new();
    }

    public class NetworkThreatDetectedEventArgs : EventArgs
    {
        public string IpAddress { get; }
        public int Port { get; }
        public string ThreatName { get; }
        public string Description { get; }
        public ThreatSeverity Severity { get; }
        public DateTime Timestamp { get; }

        public NetworkThreatDetectedEventArgs(string ipAddress, int port, string threatName, string description, ThreatSeverity severity)
        {
            IpAddress = ipAddress;
            Port = port;
            ThreatName = threatName;
            Description = description;
            Severity = severity;
            Timestamp = DateTime.Now;
        }
    }

    public class NetworkConnectionEventArgs : EventArgs
    {
        public NetworkConnectionInfo Connection { get; }

        public NetworkConnectionEventArgs(NetworkConnectionInfo connection)
        {
            Connection = connection;
        }
    }
}

