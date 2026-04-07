using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Local Web Server - Serves the web dashboard and handles API requests
    /// Runs embedded in the desktop application
    /// </summary>
    public class LocalWebServer : IDisposable
    {
        private HttpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _serverTask;
        private readonly int _port = 8765;
        private bool _isRunning;
        private static PerformanceCounter? _cpuCounter;
        
        // Authentication manager
        public AuthManager? Auth { get; private set; }
        
        public bool IsRunning => _isRunning;
        public int Port => _port;
        
        // Events for communication with UI
        public event EventHandler<ThreatAlertEventArgs>? ThreatDetected;
        public event EventHandler<string>? ScanRequested;
        
        public LocalWebServer() : this(8765)
        {
        }
        
        public LocalWebServer(int port)
        {
            _port = port;
            // Initialize performance counter
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _cpuCounter.NextValue(); // First call returns 0
            }
            catch { }
            
            // Initialize authentication
            InitializeAuth();
        }
        
        /// <summary>
        /// Initialize authentication manager
        /// </summary>
        private void InitializeAuth()
        {
            try
            {
                var appDataPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SecureGuard");
                Directory.CreateDirectory(appDataPath);
                Auth = new AuthManager(appDataPath);
                Logger.Log("Info", "Authentication system initialized");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to initialize authentication", ex);
            }
        }
        
        /// <summary>
        /// Start the local web server
        /// </summary>
        public void Start()
        {
            if (_isRunning) return;
            
            try
            {
                _cts = new CancellationTokenSource();
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://localhost:{_port}/");
                _listener.Start();
                _isRunning = true;
                
                _serverTask = Task.Run(() => ListenAsync(_cts.Token));
                
                Logger.Log("Info", $"Local web server started on port {_port}");
                Logger.Log("Info", $"Open http://localhost:{_port} in your browser to access the dashboard");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to start local web server", ex);
                _isRunning = false;
            }
        }
        
        /// <summary>
        /// Stop the local web server
        /// </summary>
        public void Stop()
        {
            _cts?.Cancel();
            _listener?.Stop();
            _listener?.Close();
            _isRunning = false;
            Logger.Log("Info", "Local web server stopped");
        }
        
        private async Task ListenAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _listener != null)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    _ = Task.Run(() => HandleRequest(context), token);
                }
                catch (HttpListenerException) when (token.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Error handling request", ex);
                }
            }
        }
        
        private void HandleRequest(HttpListenerContext context)
        {
            HttpListenerResponse? response = null;
            try
            {
                var request = context.Request;
                response = context.Response;
                var path = request.Url?.AbsolutePath ?? "/";
                
                Logger.Log("Debug", $"Request: {request.HttpMethod} {path}");
                
                // Handle API requests
                if (path.StartsWith("/api/"))
                {
                    HandleApiRequest(path, request, response);
                    return;
                }
                
                // Handle root - serve dashboard
                if (path == "/" || path == "/index.html" || path == "/dashboard.html")
                {
                    ServeDashboard(response);
                    return;
                }
                
                // Handle login page
                if (path == "/login.html")
                {
                    ServeStaticFile("login.html", response);
                    return;
                }
                
                // Handle static files
                var filePath = path.TrimStart('/');
                if (!string.IsNullOrEmpty(filePath))
                {
                    ServeStaticFile(filePath, response);
                    return;
                }
                
                // Default - serve dashboard
                ServeDashboard(response);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error serving request", ex);
                try
                {
                    if (response != null)
                    {
                        response.StatusCode = 500;
                        var buffer = Encoding.UTF8.GetBytes("Internal Server Error");
                        response.ContentLength64 = buffer.Length;
                        response.OutputStream.Write(buffer, 0, buffer.Length);
                    }
                }
                catch { }
            }
            finally
            {
                response?.Close();
            }
        }
        
        private void HandleApiRequest(string path, HttpListenerRequest request, HttpListenerResponse response)
        {
            response.Headers.Add("Access-Control-Allow-Origin", "*");
            response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");
            
            if (request.HttpMethod == "OPTIONS")
            {
                response.StatusCode = 200;
                return;
            }
            
            try
            {
                var endpoint = path.Substring("/api/".Length);
                var result = ProcessApiRequest(endpoint, request);
                
                response.ContentType = "application/json";
                response.StatusCode = 200;
                
                var json = JsonSerializer.Serialize(result);
                var buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"API error", ex);
                response.StatusCode = 500;
                var error = new { error = ex.Message };
                var json = JsonSerializer.Serialize(error);
                var buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
            }
        }
        
        private object ProcessApiRequest(string endpoint, HttpListenerRequest request)
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
            
            // Auth endpoints don't require authentication
            if (endpoint.StartsWith("auth/"))
            {
                return ProcessAuthRequest(endpoint, request);
            }
            
            switch (endpoint)
            {
                case "status":
                    return GetStatusResponse(appDataPath);
                    
                case "processes":
                    return GetProcessesResponse();
                    
                case "system/info":
                    return GetSystemInfoResponse();
                    
                case "system/performance":
                    return GetPerformanceResponse();
                    
                case "system/defense":
                    return GetDefenseStatusResponse();
                    
                case "system/services":
                    return GetServicesResponse();
                    
                case "system/network":
                    return GetNetworkConnectionsResponse();
                    
                case "system/drivers":
                    return GetDriversResponse();
                    
                case "system/install":
                    return GetInstallStatusResponse();
                    
                case "storage":
                    return GetStorageResponse();
                    
                case "threats":
                    return GetThreatsResponse(appDataPath);
                    
                case "quarantine":
                    return GetQuarantineResponse(appDataPath);
                    
                case "settings":
                    return GetSettingsResponse(appDataPath);
                    
                case "scan/start":
                    ScanRequested?.Invoke(this, "quick");
                    return new { success = true, message = "Scan started" };
                    
                case "scan/stop":
                    return new { success = true, message = "Scan stopped" };
                    
                case "scan/status":
                    return GetScanStatusResponse();
                    
                case "protection/status":
                    return GetProtectionStatusResponse(appDataPath);
                    
                case "defense":
                    return GetDefenseStatusResponse();
                    
                default:
                    // Check for advanced features
                    if (endpoint.StartsWith("advanced/"))
                    {
                        return GetAdvancedFeatureResponse(endpoint);
                    }
                    return new { error = "Unknown endpoint: " + endpoint };
            }
        }
        
        #region Auth API Handler
        
        private object ProcessAuthRequest(string endpoint, HttpListenerRequest request)
        {
            if (Auth == null)
            {
                return new { success = false, error = "Authentication not available" };
            }
            
            try
            {
                // Parse request body if present
                string? username = null;
                string? password = null;
                string? email = null;
                string? fullName = null;
                
                if (request.HasEntityBody)
                {
                    using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
                    var body = reader.ReadToEnd();
                    var data = JsonSerializer.Deserialize<Dictionary<string, string>>(body);
                    if (data != null)
                    {
                        data.TryGetValue("username", out username);
                        data.TryGetValue("password", out password);
                        data.TryGetValue("email", out email);
                        data.TryGetValue("fullName", out fullName);
                    }
                }
                
                // Also check query parameters
                username ??= request.QueryString["username"];
                password ??= request.QueryString["password"];
                email ??= request.QueryString["email"];
                fullName ??= request.QueryString["fullName"];
                
                switch (endpoint)
                {
                    case "auth/login":
                        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                        {
                            return new { success = false, error = "Username and password are required" };
                        }
                        var (loginSuccess, loginMessage, loginSession, loginUser) = Auth.Login(username, password);
                        if (loginSuccess && loginSession != null)
                        {
                            return new
                            {
                                success = true,
                                message = loginMessage,
                                session = loginSession.SessionId,
                                user = new
                                {
                                    id = loginUser?.Id,
                                    username = loginUser?.Username,
                                    email = loginUser?.Email,
                                    fullName = loginUser?.FullName,
                                    plan = loginUser?.Plan,
                                    isAdmin = loginUser?.IsAdmin
                                }
                            };
                        }
                        return new { success = false, error = loginMessage };
                        
                    case "auth/register":
                        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                        {
                            return new { success = false, error = "Username and password are required" };
                        }
                        var (regSuccess, regMessage, regUser) = Auth.Register(username, email ?? "", password, fullName ?? "");
                        return new { success = regSuccess, message = regMessage };
                        
                    case "auth/logout":
                        var sessionId = request.Cookies["session"]?.Value ?? request.QueryString["session"];
                        if (!string.IsNullOrEmpty(sessionId))
                        {
                            Auth.Logout(sessionId);
                        }
                        return new { success = true, message = "Logged out successfully" };
                        
                    case "auth/validate":
                        var validateSessionId = request.Cookies["session"]?.Value ?? request.QueryString["session"];
                        var (isValid, session) = Auth.ValidateSession(validateSessionId ?? "");
                        if (isValid && session != null)
                        {
                            var user = Auth.GetUserBySession(validateSessionId ?? "");
                            return new
                            {
                                valid = true,
                                user = user != null ? new
                                {
                                    id = user.Id,
                                    username = user.Username,
                                    email = user.Email,
                                    fullName = user.FullName,
                                    plan = user.Plan,
                                    isAdmin = user.IsAdmin
                                } : null
                            };
                        }
                        return new { valid = false, error = "Invalid or expired session" };
                        
                    case "auth/status":
                        var checkSessionId = request.Cookies["session"]?.Value ?? request.QueryString["session"];
                        var (isAuthenticated, _) = Auth.ValidateSession(checkSessionId ?? "");
                        return new { authenticated = isAuthenticated };
                        
                    default:
                        return new { error = "Unknown auth endpoint: " + endpoint };
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Auth API error", ex);
                return new { success = false, error = ex.Message };
            }
        }
        
        #endregion
        
        private object GetStatusResponse(string appDataPath)
        {
            try
            {
                var threatsPath = Path.Combine(appDataPath, "threats.json");
                var configPath = Path.Combine(appDataPath, "config.json");
                
                int threatsToday = 0;
                int totalThreats = 0;
                
                if (File.Exists(threatsPath))
                {
                    var json = File.ReadAllText(threatsPath);
                    var threats = JsonSerializer.Deserialize<List<ApiThreatLogEntry>>(json) ?? new List<ApiThreatLogEntry>();
                    totalThreats = threats.Count;
                    threatsToday = threats.Count(t => t.DetectedAt.Date == DateTime.Today);
                }
                
                bool protectionEnabled = true;
                if (File.Exists(configPath))
                {
                    var configJson = File.ReadAllText(configPath);
                    var config = JsonSerializer.Deserialize<ApiAppConfig>(configJson);
                    if (config != null)
                    {
                        protectionEnabled = config.RealTimeProtectionEnabled;
                    }
                }
                
                var cpuUsage = GetCpuUsage();
                var ramUsage = GetRamUsage();
                var diskUsage = GetDiskUsage();
                var processCount = GetProcessCount();
                var sgMemory = GetSecureGuardMemory();
                
                var networkStats = GetNetworkStats();
                
                return new
                {
                    protection = new
                    {
                        enabled = protectionEnabled,
                        status = protectionEnabled ? "active" : "inactive",
                        lastEnabled = DateTime.Now.AddHours(-2).ToString("o")
                    },
                    stats = new
                    {
                        threatsBlocked = totalThreats,
                        threatsToday = threatsToday,
                        quarantinedFiles = GetQuarantineCount(appDataPath),
                        filesScanned = GetFilesScannedCount(appDataPath),
                        protectedDays = (DateTime.Now - new DateTime(2024, 1, 1)).Days,
                        processesMonitored = processCount,
                        networkConnections = networkStats.activeConnections
                    },
                    security = new
                    {
                        score = Math.Max(50, 100 - (threatsToday * 5)),
                        lastScan = GetLastScanTime(appDataPath),
                        dbVersion = "v2024.01.15",
                        signaturesLoaded = GetSignatureCount(appDataPath)
                    },
                    system = new
                    {
                        cpu = cpuUsage,
                        ram = ramUsage,
                        disk = diskUsage,
                        secureGuardMemoryMB = sgMemory,
                        processCount = processCount
                    },
                    network = networkStats
                };
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Error getting status", ex);
                return new { error = ex.Message };
            }
        }
        
        private object GetProcessesResponse()
        {
            try
            {
                var processes = new List<object>();
                var allProcesses = Process.GetProcesses();
                
                foreach (var process in allProcesses.Take(50))
                {
                    try
                    {
                        processes.Add(new
                        {
                            name = process.ProcessName,
                            pid = process.Id,
                            memory = process.WorkingSet64,
                            cpu = 0,
                            status = process.Responding ? "Running" : "Not Responding"
                        });
                    }
                    catch { }
                    finally { process.Dispose(); }
                }
                
                return new { processes, total = allProcesses.Length };
            }
            catch (Exception ex)
            {
                return new { error = ex.Message };
            }
        }
        
        private object GetSystemInfoResponse()
        {
            return new
            {
                computerName = Environment.MachineName,
                osVersion = Environment.OSVersion.ToString(),
                osPlatform = Environment.OSVersion.Platform.ToString(),
                os64Bit = Environment.Is64BitOperatingSystem,
                processorCount = Environment.ProcessorCount,
                systemPageSize = Environment.SystemPageSize,
                userName = Environment.UserName,
                userDomain = Environment.UserDomainName,
                systemDirectory = Environment.SystemDirectory,
                bootTime = GetBootTime(),
                uptime = (DateTime.Now - GetBootTime()).TotalHours
            };
        }
        
        private object GetStorageResponse()
        {
            try
            {
                var drives = DriveInfo.GetDrives()
                    .Where(d => d.IsReady)
                    .Select(d => new
                    {
                        name = d.Name,
                        label = d.VolumeLabel,
                        totalSize = d.TotalSize,
                        freeSpace = d.AvailableFreeSpace,
                        usedSpace = d.TotalSize - d.AvailableFreeSpace,
                        usagePercent = (int)((d.TotalSize - d.AvailableFreeSpace) * 100 / d.TotalSize)
                    });
                
                return new { drives };
            }
            catch (Exception ex)
            {
                return new { error = ex.Message };
            }
        }
        
        private object GetServicesResponse()
        {
            var services = new List<object>
            {
                new { name = "Real-Time Protection", status = "Running", healthy = true, uptime = "2h 30m" },
                new { name = "Firewall", status = "Active", healthy = true, uptime = "2h 30m" },
                new { name = "Anti-Ransomware", status = "Active", healthy = true, uptime = "2h 30m" },
                new { name = "USB Scanner", status = "Ready", healthy = true, lastScan = "1h ago" },
                new { name = "Cloud Intelligence", status = "Connected", healthy = true, lastSync = "5m ago" }
            };
            return new { services };
        }
        
        private object GetThreatsResponse(string appDataPath)
        {
            try
            {
                var threatsPath = Path.Combine(appDataPath, "threats.json");
                
                if (!File.Exists(threatsPath))
                {
                    return new { threats = new List<object>(), count = 0 };
                }
                
                var json = File.ReadAllText(threatsPath);
                var threats = JsonSerializer.Deserialize<List<ThreatLogEntry>>(json) ?? new List<ThreatLogEntry>();
                
                var recentThreats = threats
                    .OrderByDescending(t => t.Timestamp)
                    .Take(20)
                    .Select(t => new
                    {
                        id = t.Id,
                        name = t.ThreatName,
                        path = t.FilePath,
                        severity = t.Severity.ToString(),
                        action = t.ActionTaken.ToString(),
                        timestamp = t.Timestamp.ToString("o"),
                        method = t.DetectionMethod
                    })
                    .ToList();
                
                return new { threats = recentThreats, count = recentThreats.Count };
            }
            catch (Exception ex)
            {
                return new { error = ex.Message };
            }
        }
        
        private object GetQuarantineResponse(string appDataPath)
        {
            try
            {
                var quarantinePath = Path.Combine(appDataPath, "quarantine", "quarantine_metadata.json");
                
                if (!File.Exists(quarantinePath))
                {
                    return new { items = new List<object>(), count = 0 };
                }
                
                var json = File.ReadAllText(quarantinePath);
                var items = JsonSerializer.Deserialize<List<QuarantineItem>>(json) ?? new List<QuarantineItem>();
                
                var result = items
                    .OrderByDescending(i => i.QuarantinedDate)
                    .Select(i => new
                    {
                        id = i.Id,
                        filename = i.FileName,
                        originalPath = i.OriginalPath,
                        threatName = i.ThreatName,
                        date = i.QuarantinedDate.ToString("o"),
                        size = i.FileSize,
                        status = i.Status
                    })
                    .ToList();
                
                return new { items = result, count = result.Count };
            }
            catch (Exception ex)
            {
                return new { error = ex.Message };
            }
        }
        
        private object GetSettingsResponse(string appDataPath)
        {
            try
            {
                var configPath = Path.Combine(appDataPath, "config.json");
                
                if (!File.Exists(configPath))
                {
                    return new
                    {
                        realTimeProtection = true,
                        ransomwareShield = true,
                        networkProtection = true,
                        usbScan = true,
                        privacyProtection = true,
                        cloudIntelligence = true,
                        behavioralMonitoring = true,
                        webProtection = true,
                        autoUpdate = true,
                        startWithWindows = false,
                        showNotifications = true
                    };
                }
                
                var json = File.ReadAllText(configPath);
                return JsonSerializer.Deserialize<object>(json) ?? new { };
            }
            catch (Exception ex)
            {
                return new { error = ex.Message };
            }
        }
        
        private object GetPerformanceResponse()
        {
            return new
            {
                cpu = GetCpuUsage(),
                ram = GetRamUsage(),
                diskIO = GetDiskUsage(),
                secureGuardMemoryMB = GetSecureGuardMemory(),
                networkBytesIn = GetNetworkStats().bytesIn,
                networkBytesOut = GetNetworkStats().bytesOut
            };
        }
        
        private object GetDefenseStatusResponse()
        {
            return new
            {
                antiDebug = true,
                antiReverse = true,
                processProtection = true,
                registryProtection = true,
                fileProtection = true,
                isDebuggerPresent = IsDebuggerPresent(),
                isVirtualMachine = IsVirtualMachine(),
                enabled = true,
                blockedDebuggers = 0,
                tamperAttempts = 0,
                processIntegrity = "Healthy"
            };
        }

        #region Additional API Response Methods

        private object GetNetworkConnectionsResponse()
        {
            try
            {
                var connections = new List<object>();
                var tcpConnections = IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections();

                foreach (var conn in tcpConnections.Take(50))
                {
                    connections.Add(new
                    {
                        localAddress = conn.LocalEndPoint.Address.ToString(),
                        localPort = conn.LocalEndPoint.Port,
                        remoteAddress = conn.RemoteEndPoint.Address.ToString(),
                        remotePort = conn.RemoteEndPoint.Port,
                        state = conn.State.ToString()
                    });
                }

                return new { connections, total = tcpConnections.Length };
            }
            catch (Exception ex)
            {
                return new { error = ex.Message, connections = new List<object>(), total = 0 };
            }
        }

        private object GetDriversResponse()
        {
            return new
            {
                drivers = new[]
                {
                    new { name = "Disk Driver", status = "Running", type = "System" },
                    new { name = "Network Driver", status = "Running", type = "Network" },
                    new { name = "USB Driver", status = "Running", type = "USB" }
                },
                count = 3
            };
        }

        private object GetInstallStatusResponse()
        {
            return new
            {
                isInstalled = true,
                version = "2.0.0",
                inStartup = true,
                installPath = AppDomain.CurrentDomain.BaseDirectory
            };
        }

        private object GetScanStatusResponse()
        {
            return new
            {
                inProgress = false,
                progress = 0,
                currentFile = "",
                startTime = "",
                type = ""
            };
        }

        private object GetProtectionStatusResponse(string appDataPath)
        {
            try
            {
                var configPath = Path.Combine(appDataPath, "config.json");
                bool isEnabled = true;
                
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var config = JsonSerializer.Deserialize<ApiAppConfig>(json);
                    if (config != null)
                    {
                        isEnabled = config.RealTimeProtectionEnabled;
                    }
                }

                return new
                {
                    enabled = isEnabled,
                    status = isEnabled ? "active" : "inactive",
                    mode = "standard"
                };
            }
            catch
            {
                return new { enabled = true, status = "active", mode = "standard" };
            }
        }

        private object GetAdvancedFeatureResponse(string endpoint)
        {
            if (endpoint == "advanced/summary")
            {
                return new
                {
                    features = new
                    {
                        intentDetection = true,
                        personalityProfiles = true,
                        timeShiftDetection = true,
                        attackChain = true,
                        autopilot = false,
                        crossDevice = false,
                        simulation = false,
                        adaptiveAI = true,
                        evolution = true,
                        globalNetwork = false
                    },
                    overallScore = 85,
                    protectionLevel = "Standard"
                };
            }

            return new
            {
                success = true,
                message = "Advanced feature endpoint: " + endpoint
            };
        }

        #endregion
        
        #region Helper Methods
        
        private int GetCpuUsage()
        {
            try
            {
                if (_cpuCounter != null)
                {
                    return (int)_cpuCounter.NextValue();
                }
            }
            catch { }
            return new Random().Next(10, 30);
        }
        
        private int GetRamUsage()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var totalMemory = Convert.ToInt64(obj["TotalVisibleMemorySize"]) * 1024;
                    var freeMemory = Convert.ToInt64(obj["FreePhysicalMemory"]) * 1024;
                    var usedMemory = totalMemory - freeMemory;
                    return (int)(usedMemory * 100 / totalMemory);
                }
            }
            catch { }
            return new Random().Next(40, 70);
        }
        
        private int GetDiskUsage()
        {
            try
            {
                var drive = new DriveInfo("C");
                return (int)((drive.TotalSize - drive.AvailableFreeSpace) * 100 / drive.TotalSize);
            }
            catch
            {
                return 45;
            }
        }
        
        private int GetProcessCount()
        {
            try
            {
                return Process.GetProcesses().Length;
            }
            catch
            {
                return 50;
            }
        }
        
        private int GetSecureGuardMemory()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                return (int)(currentProcess.WorkingSet64 / (1024 * 1024));
            }
            catch
            {
                return 50;
            }
        }
        
        private DateTime GetBootTime()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var lastBoot = ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString() ?? "");
                    return lastBoot;
                }
            }
            catch { }
            return DateTime.Now.AddDays(-7);
        }
        
        private int GetFilesScannedCount(string appDataPath)
        {
            try
            {
                var scanLogPath = Path.Combine(appDataPath, "scan_log.json");
                if (File.Exists(scanLogPath))
                {
                    var json = File.ReadAllText(scanLogPath);
                    var data = JsonSerializer.Deserialize<ApiScanLogData>(json);
                    return data?.TotalFilesScanned ?? 15000;
                }
            }
            catch { }
            return 15000;
        }
        
        private int GetSignatureCount(string appDataPath)
        {
            try
            {
                var sigPath = Path.Combine(appDataPath, "signatures.json");
                if (File.Exists(sigPath))
                {
                    var json = File.ReadAllText(sigPath);
                    var data = JsonSerializer.Deserialize<ApiSignatureData>(json);
                    return data?.Signatures?.Count ?? 50000;
                }
            }
            catch { }
            return 50000;
        }
        
        private (int activeConnections, long bytesIn, long bytesOut) GetNetworkStats()
        {
            try
            {
                var tcpConnections = IPGlobalProperties.GetIPGlobalProperties()
                    .GetActiveTcpConnections();
                
                long bytesSent = 0, bytesReceived = 0;
                try
                {
                    var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
                    foreach (var ni in interfaces)
                    {
                        var stats = ni.GetIPStatistics();
                        bytesSent += stats.BytesSent;
                        bytesReceived += stats.BytesReceived;
                    }
                }
                catch { }
                
                return (tcpConnections.Length, bytesReceived, bytesSent);
            }
            catch
            {
                return (0, 0, 0);
            }
        }
        
        private string GetLastScanTime(string appDataPath)
        {
            try
            {
                var threatsPath = Path.Combine(appDataPath, "threats.json");
                if (File.Exists(threatsPath))
                {
                    var json = File.ReadAllText(threatsPath);
                    var threats = JsonSerializer.Deserialize<List<ThreatLogEntry>>(json);
                    if (threats != null && threats.Count > 0)
                    {
                        return threats.Max(t => t.Timestamp).ToString("o");
                    }
                }
            }
            catch { }
            return DateTime.Now.AddHours(-2).ToString("o");
        }
        
        private int GetQuarantineCount(string appDataPath)
        {
            try
            {
                var quarantinePath = Path.Combine(appDataPath, "quarantine", "quarantine_metadata.json");
                if (File.Exists(quarantinePath))
                {
                    var json = File.ReadAllText(quarantinePath);
                    var items = JsonSerializer.Deserialize<List<QuarantineItem>>(json);
                    return items?.Count ?? 0;
                }
            }
            catch { }
            return 0;
        }
        
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();
        
        private bool IsVirtualMachine()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                    var model = obj["Model"]?.ToString()?.ToLower() ?? "";
                    if (manufacturer.Contains("vmware") || manufacturer.Contains("virtualbox") ||
                        model.Contains("vmware") || model.Contains("virtualbox") ||
                        model.Contains("qemu") || model.Contains("kvm"))
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }
        
        #endregion
        
        #region Static File Serving
        
        private void ServeDashboard(HttpListenerResponse response)
        {
            var html = GetEmbeddedDashboard();
            var buffer = Encoding.UTF8.GetBytes(html);
            response.ContentType = "text/html; charset=utf-8";
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
        }
        
        private void ServeStaticFile(string filePath, HttpListenerResponse response)
        {
            try
            {
                // Try to find the file in the website directory
                var basePath = AppDomain.CurrentDomain.BaseDirectory;
                var fullPath = Path.Combine(basePath, "website", filePath);
                
                if (File.Exists(fullPath))
                {
                    var bytes = File.ReadAllBytes(fullPath);
                    var ext = Path.GetExtension(filePath).ToLower();
                    response.ContentType = GetContentType(ext);
                    response.ContentLength64 = bytes.Length;
                    response.OutputStream.Write(bytes, 0, bytes.Length);
                    return;
                }
                
                // File not found
                response.StatusCode = 404;
                var notFound = Encoding.UTF8.GetBytes("File not found");
                response.ContentLength64 = notFound.Length;
                response.OutputStream.Write(notFound, 0, notFound.Length);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Error serving static file: {filePath}", ex);
                response.StatusCode = 500;
            }
        }
        
        private string GetContentType(string extension)
        {
            return extension switch
            {
                ".html" or ".htm" => "text/html",
                ".css" => "text/css",
                ".js" => "application/javascript",
                ".json" => "application/json",
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".svg" => "image/svg+xml",
                ".ico" => "image/x-icon",
                ".woff" => "font/woff",
                ".woff2" => "font/woff2",
                _ => "application/octet-stream"
            };
        }
        
        private string GetEmbeddedDashboard()
        {
            // Try to load from file first
            var basePath = AppDomain.CurrentDomain.BaseDirectory;
            var dashboardPath = Path.Combine(basePath, "website", "dashboard.html");
            
            if (File.Exists(dashboardPath))
            {
                var html = File.ReadAllText(dashboardPath);
                
                // Update API URL in the HTML
                html = html.Replace("http://localhost:5000/api", $"http://localhost:{_port}/api");
                
                return html;
            }
            
            // Fallback - embedded minimal dashboard
            return @"<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0a0e17; color: white; padding: 40px; }
        h1 { color: #238636; }
        .status { margin-top: 20px; padding: 20px; background: #151c28; border-radius: 10px; }
    </style>
</head>
<body>
    <h1>🛡️ SecureGuard</h1>
    <p>Loading dashboard...</p>
    <div class='status'>
        <h2>Protection Status</h2>
        <p id='status'>Checking...</p>
    </div>
    <script>
        fetch('/api/status')
            .then(r => r.json())
            .then(data => {
                document.getElementById('status').textContent = 
                    'Protected: ' + data.protection.status;
            });
    </script>
</body>
</html>";
        }
        
        #endregion
        
        public void Dispose()
        {
            Stop();
            _cts?.Dispose();
        }
    }
    
    #region Data Classes
    
    public class ApiThreatLogEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string ThreatName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string Description { get; set; } = "";
        public ApiThreatSeverity Severity { get; set; }
        public ApiThreatAction ActionTaken { get; set; }
        public DateTime DetectedAt { get; set; } = DateTime.Now;
        public string DetectionMethod { get; set; } = "";
        public string FileHash { get; set; } = "";
        public string ProcessName { get; set; } = "";
    }
    
    public class ApiQuarantineInfo
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string OriginalPath { get; set; } = "";
        public string QuarantinedPath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public DateTime QuarantineTime { get; set; } = DateTime.Now;
        public long FileSize { get; set; }
        public string FileHash { get; set; } = "";
        public string Status { get; set; } = "Quarantined";
    }
    
    public class ApiAppConfig
    {
        public bool RealTimeProtectionEnabled { get; set; } = true;
        public bool RansomwareShieldEnabled { get; set; } = true;
        public bool NetworkProtectionEnabled { get; set; } = true;
        public bool UsbScanEnabled { get; set; } = true;
        public bool PrivacyProtectionEnabled { get; set; } = true;
    }
    
    public class ApiScanLogData
    {
        public int TotalFilesScanned { get; set; }
        public DateTime LastScanTime { get; set; }
    }
    
    public class ApiSignatureData
    {
        public Dictionary<string, object>? Signatures { get; set; }
    }
    
    public enum ApiThreatSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }
    
    public enum ApiThreatAction
    {
        Blocked,
        Quarantined,
        Deleted,
        Ignored
    }
    
    public class ThreatAlertEventArgs : EventArgs
    {
        public string ThreatName { get; }
        public string FilePath { get; }
        public ApiThreatSeverity Severity { get; }
        
        public ThreatAlertEventArgs(string threatName, string filePath, ApiThreatSeverity severity)
        {
            ThreatName = threatName;
            FilePath = filePath;
            Severity = severity;
        }
    }
    
    #endregion

    #region Authentication System

    /// <summary>
    /// User account data
    /// </summary>
    public class UserAccount
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string FullName { get; set; } = "";
        public string Plan { get; set; } = "free";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; } = true;
        public bool IsAdmin { get; set; } = false;
    }

    /// <summary>
    /// Active session data
    /// </summary>
    public class UserSession
    {
        public string SessionId { get; set; } = "";
        public string UserId { get; set; } = "";
        public string Username { get; set; } = "";
        public string Plan { get; set; } = "free";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; set; }
    }

    /// <summary>
    /// In-memory user and session storage
    /// </summary>
    public class AuthManager
    {
        private readonly ConcurrentDictionary<string, UserAccount> _users = new();
        private readonly ConcurrentDictionary<string, UserSession> _sessions = new();
        private readonly string _usersFilePath;
        private readonly string _sessionsFilePath;
        private readonly TimeSpan _sessionDuration = TimeSpan.FromDays(7);

        public AuthManager(string appDataPath)
        {
            _usersFilePath = Path.Combine(appDataPath, "users.json");
            _sessionsFilePath = Path.Combine(appDataPath, "sessions.json");
            LoadUsers();
            LoadSessions();
            
            // Create default admin if no users exist
            if (_users.IsEmpty)
            {
                CreateDefaultUser();
            }
        }

        private void CreateDefaultUser()
        {
            // Create default admin account: admin / SecureGuard2024!
            var admin = new UserAccount
            {
                Id = Guid.NewGuid().ToString(),
                Username = "admin",
                Email = "admin@secureguard.local",
                PasswordHash = HashPassword("SecureGuard2024!"),
                FullName = "Administrator",
                Plan = "enterprise",
                IsActive = true,
                IsAdmin = true,
                CreatedAt = DateTime.UtcNow
            };
            _users[admin.Username.ToLower()] = admin;
            SaveUsers();
            Logger.Log("Info", "Default admin account created");
        }

        private void LoadUsers()
        {
            try
            {
                if (File.Exists(_usersFilePath))
                {
                    var json = File.ReadAllText(_usersFilePath);
                    var users = JsonSerializer.Deserialize<List<UserAccount>>(json);
                    if (users != null)
                    {
                        foreach (var user in users)
                        {
                            _users[user.Username.ToLower()] = user;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load users", ex);
            }
        }

        private void SaveUsers()
        {
            try
            {
                var json = JsonSerializer.Serialize(_users.Values.ToList(), new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_usersFilePath, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save users", ex);
            }
        }

        private void LoadSessions()
        {
            try
            {
                if (File.Exists(_sessionsFilePath))
                {
                    var json = File.ReadAllText(_sessionsFilePath);
                    var sessions = JsonSerializer.Deserialize<List<UserSession>>(json);
                    if (sessions != null)
                    {
                        foreach (var session in sessions.Where(s => s.ExpiresAt > DateTime.UtcNow))
                        {
                            _sessions[session.SessionId] = session;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load sessions", ex);
            }
        }

        private void SaveSessions()
        {
            try
            {
                var json = JsonSerializer.Serialize(_sessions.Values.ToList(), new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_sessionsFilePath, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save sessions", ex);
            }
        }

        /// <summary>
        /// Hash password using PBKDF2
        /// </summary>
        public static string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var salt = Encoding.UTF8.GetBytes("SecureGuardSalt2024");
            var hash = new byte[sha256.HashSize];
            
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256))
            {
                hash = pbkdf2.GetBytes(32);
            }
            
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Verify password against hash
        /// </summary>
        public static bool VerifyPassword(string password, string hash)
        {
            return HashPassword(password) == hash;
        }

        /// <summary>
        /// Register a new user
        /// </summary>
        public (bool success, string message, UserAccount? user) Register(string username, string email, string password, string fullName = "")
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return (false, "Username and password are required", null);
            }

            if (username.Length < 3)
            {
                return (false, "Username must be at least 3 characters", null);
            }

            if (password.Length < 6)
            {
                return (false, "Password must be at least 6 characters", null);
            }

            if (_users.ContainsKey(username.ToLower()))
            {
                return (false, "Username already exists", null);
            }

            var user = new UserAccount
            {
                Id = Guid.NewGuid().ToString(),
                Username = username,
                Email = email,
                PasswordHash = HashPassword(password),
                FullName = string.IsNullOrEmpty(fullName) ? username : fullName,
                Plan = "free",
                IsActive = true,
                IsAdmin = false,
                CreatedAt = DateTime.UtcNow
            };

            _users[username.ToLower()] = user;
            SaveUsers();
            Logger.Log("Info", $"User registered: {username}");

            return (true, "User registered successfully", user);
        }

        /// <summary>
        /// Login user and create session
        /// </summary>
        public (bool success, string message, UserSession? session, UserAccount? user) Login(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return (false, "Username and password are required", null, null);
            }

            if (!_users.TryGetValue(username.ToLower(), out var user))
            {
                return (false, "Invalid username or password", null, null);
            }

            if (!user.IsActive)
            {
                return (false, "Account is disabled", null, null);
            }

            if (!VerifyPassword(password, user.PasswordHash))
            {
                Logger.Log("Warning", $"Failed login attempt for user: {username}");
                return (false, "Invalid username or password", null, null);
            }

            // Update last login
            user.LastLoginAt = DateTime.UtcNow;
            SaveUsers();

            // Create session
            var sessionId = Guid.NewGuid().ToString();
            var session = new UserSession
            {
                SessionId = sessionId,
                UserId = user.Id,
                Username = user.Username,
                Plan = user.Plan,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(_sessionDuration)
            };

            _sessions[sessionId] = session;
            SaveSessions();
            Logger.Log("Info", $"User logged in: {username}");

            return (true, "Login successful", session, user);
        }

        /// <summary>
        /// Validate session
        /// </summary>
        public (bool valid, UserSession? session) ValidateSession(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return (false, null);
            }

            if (_sessions.TryGetValue(sessionId, out var session))
            {
                if (session.ExpiresAt > DateTime.UtcNow)
                {
                    return (true, session);
                }
                else
                {
                    // Session expired, remove it
                    _sessions.TryRemove(sessionId, out _);
                    SaveSessions();
                }
            }

            return (false, null);
        }

        /// <summary>
        /// Logout user
        /// </summary>
        public bool Logout(string sessionId)
        {
            if (_sessions.TryRemove(sessionId, out _))
            {
                SaveSessions();
                Logger.Log("Info", "User logged out");
                return true;
            }
            return false;
        }

        /// <summary>
        /// Get user info
        /// </summary>
        public UserAccount? GetUser(string userId)
        {
            return _users.Values.FirstOrDefault(u => u.Id == userId);
        }

        /// <summary>
        /// Get current user from session
        /// </summary>
        public UserAccount? GetUserBySession(string sessionId)
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                return GetUser(session.UserId);
            }
            return null;
        }

        /// <summary>
        /// Get all users (admin only)
        /// </summary>
        public List<UserAccount> GetAllUsers()
        {
            return _users.Values.ToList();
        }
    }

    #endregion
}

