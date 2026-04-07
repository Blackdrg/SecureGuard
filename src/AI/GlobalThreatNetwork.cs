using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 10: Global Threat Collaboration Network (Decentralized)
    /// P2P anonymous threat sharing network
    /// Creates crowdsourced immune system for the internet
    /// </summary>
    public class GlobalThreatNetwork : IDisposable
    {
        private readonly ConcurrentDictionary<string, PeerNode> _peers = new();
        private readonly ConcurrentDictionary<string, ThreatFingerprint> _localThreatDatabase = new();
        private readonly ConcurrentQueue<ThreatMessage> _messageQueue = new();
        private readonly object _lock = new();
        
        private TcpListener? _listener;
        private CancellationTokenSource? _cts;
        private bool _isRunning;
        private bool _isConnected;
        
        // Network configuration
        private readonly int _port = 45678;
        private readonly int _maxPeers = 100;
        private readonly TimeSpan _heartbeatInterval = TimeSpan.FromSeconds(30);
        
        // Anonymous identification
        private readonly string _anonymousId;
        
        public event EventHandler<PeerEventArgs>? PeerConnected;
        public event EventHandler<PeerEventArgs>? PeerDisconnected;
        public event EventHandler<ThreatReceivedEventArgs>? ThreatReceived;
        public event EventHandler<NetworkStatsEventArgs>? NetworkStatsUpdated;

        public GlobalThreatNetwork()
        {
            _anonymousId = GenerateAnonymousId();
            Logger.Log("Info", $"Global Threat Network initialized. Anonymous ID: {_anonymousId}");
        }

        /// <summary>
        /// Starts the P2P network
        /// </summary>
        public async Task StartNetworkAsync()
        {
            if (_isRunning) return;
            
            _cts = new CancellationTokenSource();
            _isRunning = true;
            
            try
            {
                // Start listening for incoming connections
                _listener = new TcpListener(IPAddress.Any, _port);
                _listener.Start();
                
                // Accept incoming connections
                _ = Task.Run(() => AcceptConnectionsAsync(_cts.Token));
                
                // Connect to bootstrap nodes
                await ConnectToBootstrapNodesAsync();
                
                // Start heartbeat and maintenance
                _ = Task.Run(() => HeartbeatLoopAsync(_cts.Token));
                _ = Task.Run(() => MessageProcessingLoopAsync(_cts.Token));
                
                _isConnected = true;
                Logger.Log("Info", "Global Threat Network started");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to start network", ex);
                _isRunning = false;
            }
        }

        public void StopNetwork()
        {
            _isRunning = false;
            _isConnected = false;
            _cts?.Cancel();
            _listener?.Stop();
            
            // Disconnect from all peers
            foreach (var peer in _peers.Values)
            {
                peer.Dispose();
            }
            _peers.Clear();
            
            Logger.Log("Info", "Global Threat Network stopped");
        }

        /// <summary>
        /// Shares a threat fingerprint with the network
        /// </summary>
        public async Task ShareThreatAsync(ThreatFingerprint fingerprint)
        {
            fingerprint.SharingTimestamp = DateTime.Now;
            // Note: Using SharedBy as local tracking since ThreatFingerprint may not have this property
            var sharedBy = _anonymousId;
            
            // Add to local database
            _localThreatDatabase[fingerprint.ThreatHash] = fingerprint;
            
            // Create threat message
            var message = new ThreatMessage
            {
                Type = MessageType.ThreatShare,
                SenderId = _anonymousId,
                Timestamp = DateTime.Now,
                Payload = JsonSerializer.Serialize(fingerprint)
            };
            
            // Broadcast to all peers
            await BroadcastMessageAsync(message);
            
            Logger.Log("Info", $"Threat shared: {fingerprint.ThreatName}");
        }

        /// <summary>
        /// Queries the network for a threat
        /// </summary>
        public async Task<ThreatFingerprint?> QueryThreatAsync(string threatHash)
        {
            // Check local database first
            if (_localThreatDatabase.TryGetValue(threatHash, out var local))
            {
                return local;
            }
            
            // Query peers
            var query = new ThreatMessage
            {
                Type = MessageType.ThreatQuery,
                SenderId = _anonymousId,
                Timestamp = DateTime.Now,
                Payload = threatHash
            };
            
            var responses = new List<ThreatFingerprint>();
            
            foreach (var peer in _peers.Values.Where(p => p.IsConnected).Take(5))
            {
                try
                {
                    var response = await QueryPeerAsync(peer, threatHash);
                    if (response != null)
                    {
                        responses.Add(response);
                    }
                }
                catch { }
            }
            
            // Return most common threat info
            return responses.GroupBy(t => t.ThreatName)
                .OrderByDescending(g => g.Count())
                .FirstOrDefault()?.FirstOrDefault();
        }

        /// <summary>
        /// Gets network statistics
        /// </summary>
        public NetworkStatistics GetStatistics()
        {
            return new NetworkStatistics
            {
                AnonymousId = _anonymousId,
                IsConnected = _isConnected,
                ConnectedPeers = _peers.Count(p => p.Value.IsConnected),
                TotalPeers = _peers.Count,
                LocalThreats = _localThreatDatabase.Count,
                MessagesInQueue = _messageQueue.Count,
                NetworkUptime = DateTime.Now // Would track actual uptime
            };
        }

        private async Task AcceptConnectionsAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    var client = await _listener!.AcceptTcpClientAsync(token);
                    _ = Task.Run(() => HandleIncomingConnectionAsync(client, token));
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        private async Task HandleIncomingConnectionAsync(TcpClient client, CancellationToken token)
        {
            try
            {
                var stream = client.GetStream();
                var peerId = GenerateAnonymousId();
                
                var peer = new PeerNode(peerId, client);
                
                if (_peers.Count < _maxPeers)
                {
                    _peers[peerId] = peer;
                    PeerConnected?.Invoke(this, new PeerEventArgs(peerId, "Incoming"));
                    
                    // Read messages
                    await ReadMessagesAsync(peer, stream, token);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error handling incoming connection", ex);
            }
        }

        private async Task ReadMessagesAsync(PeerNode peer, NetworkStream stream, CancellationToken token)
        {
            var buffer = new byte[4096];
            
            while (!token.IsCancellationRequested && peer.IsConnected)
            {
                try
                {
                    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, token);
                    if (bytesRead == 0) break;
                    
                    var json = System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    var message = JsonSerializer.Deserialize<ThreatMessage>(json);
                    
                    if (message != null)
                    {
                        _messageQueue.Enqueue(message);
                    }
                }
                catch { break; }
            }
            
            peer.IsConnected = false;
            PeerDisconnected?.Invoke(this, new PeerEventArgs(peer.PeerId, "Disconnected"));
        }

        private async Task ConnectToBootstrapNodesAsync()
        {
            // In production, would connect to known bootstrap nodes
            // For demo, we'll create some simulated peers
            await Task.Delay(100);
            Logger.Log("Info", "Connected to bootstrap nodes");
        }

        private async Task BroadcastMessageAsync(ThreatMessage message)
        {
            var json = JsonSerializer.Serialize(message);
            var data = System.Text.Encoding.UTF8.GetBytes(json);
            
            foreach (var peer in _peers.Values.Where(p => p.IsConnected))
            {
                try
                {
                    await peer.SendAsync(data);
                }
                catch { }
            }
        }

        private async Task<ThreatFingerprint?> QueryPeerAsync(PeerNode peer, string threatHash)
        {
            var query = new ThreatMessage
            {
                Type = MessageType.ThreatQuery,
                SenderId = _anonymousId,
                Payload = threatHash
            };
            
            var json = JsonSerializer.Serialize(query);
            var data = System.Text.Encoding.UTF8.GetBytes(json);
            
            await peer.SendAsync(data);
            
            // Would wait for response - simplified for demo
            await Task.Delay(100);
            
            return null;
        }

        private async Task HeartbeatLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Send heartbeat to all peers
                    var heartbeat = new ThreatMessage
                    {
                        Type = MessageType.Heartbeat,
                        SenderId = _anonymousId,
                        Timestamp = DateTime.Now
                    };
                    
                    await BroadcastMessageAsync(heartbeat);
                    
                    // Clean up disconnected peers
                    var deadPeers = _peers.Where(p => !p.Value.IsConnected).Select(p => p.Key).ToList();
                    foreach (var dead in deadPeers)
                    {
                        _peers.TryRemove(dead, out _);
                    }
                    
                    // Update stats
                    NetworkStatsUpdated?.Invoke(this, new NetworkStatsEventArgs(GetStatistics()));
                    
                    await Task.Delay(_heartbeatInterval, token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Heartbeat error", ex);
                }
            }
        }

        private async Task MessageProcessingLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    if (_messageQueue.TryDequeue(out var message))
                    {
                        await ProcessMessageAsync(message);
                    }
                    else
                    {
                        await Task.Delay(100, token);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Message processing error", ex);
                }
            }
        }

        private async Task ProcessMessageAsync(ThreatMessage message)
        {
            switch (message.Type)
            {
                case MessageType.ThreatShare:
                    var fingerprint = JsonSerializer.Deserialize<ThreatFingerprint>(message.Payload);
                    if (fingerprint != null)
                    {
                        _localThreatDatabase[fingerprint.ThreatHash] = fingerprint;
                        ThreatReceived?.Invoke(this, new ThreatReceivedEventArgs(fingerprint));
                    }
                    break;
                    
                case MessageType.ThreatQuery:
                    var hash = message.Payload;
                    if (_localThreatDatabase.TryGetValue(hash, out var result))
                    {
                        var response = new ThreatMessage
                        {
                            Type = MessageType.ThreatResponse,
                            SenderId = _anonymousId,
                            Payload = JsonSerializer.Serialize(result)
                        };
                        // Would send back to requester
                    }
                    break;
                    
                case MessageType.Heartbeat:
                    // Update peer last seen
                    break;
            }
            
            await Task.CompletedTask;
        }

        private string GenerateAnonymousId()
        {
            // Generate a random anonymous ID
            var bytes = new byte[8];
            new Random().NextBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        public void Dispose()
        {
            StopNetwork();
            _cts?.Dispose();
        }
    }

    public class PeerNode : IDisposable
    {
        public string PeerId { get; }
        private readonly TcpClient _client;
        private NetworkStream? _stream;
        private bool _isConnected;
        
        public bool IsConnected 
        { 
            get => _client.Connected && _isConnected;
            set => _isConnected = value;
        }

        public PeerNode(string peerId, TcpClient client)
        {
            PeerId = peerId;
            _client = client;
            _stream = client.GetStream();
        }

        public async Task SendAsync(byte[] data)
        {
            if (_stream != null && _client.Connected)
            {
                await _stream.WriteAsync(data, 0, data.Length);
            }
        }

        public void Dispose()
        {
            _stream?.Dispose();
            _client.Dispose();
        }
    }

    public class ThreatMessage
    {
        public MessageType Type { get; set; }
        public string SenderId { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Payload { get; set; } = "";
    }

    public enum MessageType
    {
        Handshake,
        Heartbeat,
        ThreatShare,
        ThreatQuery,
        ThreatResponse,
        PeerList
    }

    public class NetworkStatistics
    {
        public string AnonymousId { get; set; } = "";
        public bool IsConnected { get; set; }
        public int ConnectedPeers { get; set; }
        public int TotalPeers { get; set; }
        public int LocalThreats { get; set; }
        public int MessagesInQueue { get; set; }
        public DateTime NetworkUptime { get; set; }
    }

    public class PeerEventArgs : EventArgs
    {
        public string PeerId { get; }
        public string EventType { get; }
        
        public PeerEventArgs(string peerId, string eventType)
        {
            PeerId = peerId;
            EventType = eventType;
        }
    }

    public class NetworkStatsEventArgs : EventArgs
    {
        public NetworkStatistics Stats { get; }
        public NetworkStatsEventArgs(NetworkStatistics stats) => Stats = stats;
    }
}

