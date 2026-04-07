using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    public class NetworkMonitor : IDisposable
    {
        private bool _isRunning;
        private CancellationTokenSource? _cts;
        private readonly HashSet<string> _blockedIPs = new();
        private readonly Dictionary<string, int> _connectionCounts = new();
        private readonly object _lock = new();
        
        public event EventHandler<SuspiciousConnectionEventArgs>? SuspiciousConnectionDetected;
        public event EventHandler<ConnectionBlockedEventArgs>? ConnectionBlocked;
        public event EventHandler<OutboundConnectionEventArgs>? OutboundConnection;

        public NetworkMonitor()
        {
            LoadBlockedIPs();
        }

        private void LoadBlockedIPs()
        {
            _blockedIPs.Add("192.0.2.0");
            _blockedIPs.Add("198.51.100.0");
            _blockedIPs.Add("203.0.113.0");
            Logger.Log("Info", "Network Monitor initialized");
        }

        public void Start()
        {
            if (_isRunning) return;
            _cts = new CancellationTokenSource();
            _isRunning = true;
            Task.Run(() => MonitorConnections(_cts.Token));
            Logger.Log("Info", "Network Monitor started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            Logger.Log("Info", "Network Monitor stopped");
        }

        private async Task MonitorConnections(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    var properties = IPGlobalProperties.GetIPGlobalProperties();
                    var connections = properties.GetActiveTcpConnections();
                    
                    foreach (var conn in connections)
                    {
                        if (conn.State == TcpState.Established)
                        {
                            var remoteIP = conn.RemoteEndPoint.Address.ToString();
                            AnalyzeConnection(remoteIP, conn.RemoteEndPoint.Port);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Network monitoring error", ex);
                }
                
                await Task.Delay(5000, token);
            }
        }

        private void AnalyzeConnection(string remoteIP, int port)
        {
            if (_blockedIPs.Contains(remoteIP))
            {
                ConnectionBlocked?.Invoke(this, new ConnectionBlockedEventArgs(remoteIP, port, "IP in blocklist"));
                Logger.Log("Warning", $"Blocked connection to: {remoteIP}:{port}");
                return;
            }

            var suspiciousPorts = new[] { 4444, 5555, 6666, 31337, 12345 };
            if (Array.Exists(suspiciousPorts, p => p == port))
            {
                SuspiciousConnectionDetected?.Invoke(this, new SuspiciousConnectionEventArgs(remoteIP, port, "Suspicious C2 port"));
                Logger.Log("Warning", $"Suspicious connection to: {remoteIP}:{port}");
            }

            lock (_lock)
            {
                var key = $"{remoteIP}:{port}";
                if (!_connectionCounts.ContainsKey(key))
                    _connectionCounts[key] = 0;
                _connectionCounts[key]++;
                
                if (_connectionCounts[key] > 100)
                {
                    SuspiciousConnectionDetected?.Invoke(this, new SuspiciousConnectionEventArgs(remoteIP, port, "High connection frequency"));
                }
            }

            OutboundConnection?.Invoke(this, new OutboundConnectionEventArgs(remoteIP, port, "Established"));
        }

        public bool CheckIpReputation(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out var ip))
            {
                var bytes = ip.GetAddressBytes();
                if (bytes[0] == 10 || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31 || 
                    bytes[0] == 192 && bytes[1] == 168)
                {
                    return true;
                }
            }
            return !_blockedIPs.Contains(ipAddress);
        }

        public void BlockIP(string ipAddress)
        {
            lock (_lock)
            {
                _blockedIPs.Add(ipAddress);
                Logger.Log("Info", $"IP blocked: {ipAddress}");
            }
        }

        public void UnblockIP(string ipAddress)
        {
            lock (_lock)
            {
                _blockedIPs.Remove(ipAddress);
                Logger.Log("Info", $"IP unblocked: {ipAddress}");
            }
        }

        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }

    public class SuspiciousConnectionEventArgs : EventArgs
    {
        public string RemoteIP { get; }
        public int Port { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public SuspiciousConnectionEventArgs(string remoteIP, int port, string reason)
        {
            RemoteIP = remoteIP;
            Port = port;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }

    public class ConnectionBlockedEventArgs : EventArgs
    {
        public string RemoteIP { get; }
        public int Port { get; }
        public string Reason { get; }
        public DateTime Timestamp { get; }

        public ConnectionBlockedEventArgs(string remoteIP, int port, string reason)
        {
            RemoteIP = remoteIP;
            Port = port;
            Reason = reason;
            Timestamp = DateTime.Now;
        }
    }

    public class OutboundConnectionEventArgs : EventArgs
    {
        public string RemoteIP { get; }
        public int Port { get; }
        public string State { get; }
        public DateTime Timestamp { get; }

        public OutboundConnectionEventArgs(string remoteIP, int port, string state)
        {
            RemoteIP = remoteIP;
            Port = port;
            State = state;
            Timestamp = DateTime.Now;
        }
    }
}

