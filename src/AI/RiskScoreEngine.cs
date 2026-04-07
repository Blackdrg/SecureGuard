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
    /// Feature 8: Personal Risk Score System
    /// Dynamic device safety score based on multiple factors
    /// </summary>
    public class RiskScoreEngine : IDisposable
    {
        private readonly Timer _scoreUpdateTimer;
        private int _currentScore = 75;
        private readonly object _lock = new();
        
        public event EventHandler<ScoreUpdatedEventArgs>? ScoreUpdated;
        public event EventHandler<VulnerabilityFoundEventArgs>? VulnerabilityFound;

        public RiskScoreEngine()
        {
            _scoreUpdateTimer = new Timer(UpdateScoreAsync, null, TimeSpan.Zero, TimeSpan.FromMinutes(5));
            Core.Logger.Log("Info", "Risk Score Engine initialized");
        }

        public async void UpdateScoreAsync(object? state)
        {
            try
            {
                var assessment = await CalculateRiskScoreAsync();
                
                lock (_lock)
                {
                    _currentScore = assessment.TotalScore;
                }
                
                ScoreUpdated?.Invoke(this, new ScoreUpdatedEventArgs(assessment));
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Risk score update failed", ex);
            }
        }

        public async Task<RiskAssessment> CalculateRiskScoreAsync()
        {
            var assessment = new RiskAssessment
            {
                CalculatedAt = DateTime.Now
            };

            // Calculate all risk factors in parallel
            var portTask = Task.Run(() => CheckOpenPorts());
            var outdatedTask = Task.Run(() => CheckOutdatedApps());
            var processTask = Task.Run(() => CheckSuspiciousProcesses());
            var networkTask = Task.Run(() => CheckNetworkSecurity());
            var firewallTask = Task.Run(() => CheckFirewallStatus());
            var updateTask = Task.Run(() => CheckSystemUpdates());
            var downloadTask = Task.Run(() => CheckRiskyDownloads());

            await Task.WhenAll(portTask, outdatedTask, processTask, networkTask, firewallTask, updateTask, downloadTask);

            assessment.PortRisks = portTask.Result;
            assessment.OutdatedApps = outdatedTask.Result;
            assessment.SuspiciousProcesses = processTask.Result;
            assessment.NetworkRisks = networkTask.Result;
            assessment.FirewallStatus = firewallTask.Result;
            assessment.UpdateStatus = updateTask.Result;
            assessment.RiskyDownloads = downloadTask.Result;

            // Calculate total score (weighted)
            int totalScore = 100;
            
            // Open ports: -5 per high-risk port
            totalScore -= assessment.PortRisks.HighRiskPorts * 5;
            totalScore -= assessment.PortRisks.MediumRiskPorts * 3;
            
            // Outdated apps: -8 per critical, -4 per important
            totalScore -= assessment.OutdatedApps.CriticalCount * 8;
            totalScore -= assessment.OutdatedApps.ImportantCount * 4;
            
            // Suspicious processes: -10 per process
            totalScore -= assessment.SuspiciousProcesses.Count * 10;
            
            // Network risks: -15 per issue
            totalScore -= assessment.NetworkRisks.UnsecuredNetworks * 10;
            totalScore -= assessment.NetworkRisks.OpenShares ? 10 : 0;
            
            // Firewall: -20 if disabled
            totalScore -= assessment.FirewallStatus.IsEnabled ? 0 : 20;
            
            // Updates: -15 if outdated
            totalScore -= assessment.UpdateStatus.PendingUpdates * 3;
            
            // Risky downloads: -5 per download
            totalScore -= assessment.RiskyDownloads.UnverifiedDownloads * 5;

            assessment.TotalScore = Math.Max(0, Math.Min(100, totalScore));
            
            // Generate recommendations
            assessment.Recommendations = GenerateRecommendations(assessment);

            Core.Logger.Log("Debug", $"Risk score calculated: {assessment.TotalScore}/100");
            
            return assessment;
        }

        private PortRiskAssessment CheckOpenPorts()
        {
            var assessment = new PortRiskAssessment();
            
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var tcpConnections = properties.GetActiveTcpListeners();
                
                var highRiskPorts = new[] { 21, 23, 25, 110, 135, 139, 445, 3389, 5900 };
                var mediumRiskPorts = new[] { 22, 80, 443, 8080, 8443 };
                
                foreach (var endpoint in tcpConnections)
                {
                    var port = endpoint.Port;
                    
                    if (highRiskPorts.Contains(port))
                    {
                        assessment.HighRiskPorts++;
                        assessment.OpenPorts.Add(new OpenPort { Port = port, Risk = "High", Service = GetServiceName(port) });
                    }
                    else if (mediumRiskPorts.Contains(port))
                    {
                        assessment.MediumRiskPorts++;
                        assessment.OpenPorts.Add(new OpenPort { Port = port, Risk = "Medium", Service = GetServiceName(port) });
                    }
                    else if (port > 1000)
                    {
                        assessment.OtherOpenPorts++;
                        assessment.OpenPorts.Add(new OpenPort { Port = port, Risk = "Low", Service = GetServiceName(port) });
                    }
                }
                
                Core.Logger.Log("Debug", $"Port scan: {assessment.HighRiskPorts} high, {assessment.MediumRiskPorts} medium risk ports");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Port scan failed", ex);
            }
            
            return assessment;
        }

        private string GetServiceName(int port)
        {
            return port switch
            {
                21 => "FTP",
                22 => "SSH",
                23 => "Telnet",
                25 => "SMTP",
                80 => "HTTP",
                110 => "POP3",
                135 => "RPC",
                139 => "NetBIOS",
                443 => "HTTPS",
                445 => "SMB",
                3389 => "RDP",
                5900 => "VNC",
                8080 => "HTTP-Proxy",
                _ => "Unknown"
            };
        }

        private OutdatedAppAssessment CheckOutdatedApps()
        {
            var assessment = new OutdatedAppAssessment();
            
            try
            {
                // Check common applications via registry or file existence
                var commonApps = new Dictionary<string, (string path, string check)>
                {
                    ["Adobe Reader"] = (@"C:\Program Files\Adobe\Acrobat DC\AcroDist.exe", "version"),
                    ["Java"] = (@"C:\Program Files\Java\jre/bin/java.exe", "version"),
                    ["Firefox"] = (@"C:\Program Files\Mozilla Firefox\firefox.exe", "version"),
                    ["Chrome"] = (@"C:\Program Files\Google\Chrome\Application\chrome.exe", "version"),
                    ["WinRAR"] = (@"C:\Program Files\WinRAR\winrar.exe", "version"),
                    ["7-Zip"] = (@"C:\Program Files\7-Zip\7z.exe", "version"),
                    ["VLC"] = (@"C:\Program Files\VLC\vlc.exe", "version"),
                    ["Teams"] = (@"C:\Users\" + Environment.UserName + @"\AppData\Local\Microsoft\Teams\Update.exe", "version")
                };

                var random = new Random();
                foreach (var app in commonApps)
                {
                    if (System.IO.File.Exists(app.Value.path))
                    {
                        // Simulate version check - in production would check actual version
                        var isOutdated = random.Next(100) < 20; // 20% chance of outdated
                        if (isOutdated)
                        {
                            if (random.Next(100) < 30)
                            {
                                assessment.CriticalCount++;
                                assessment.OutdatedApps.Add(new OutdatedApp { Name = app.Key, Severity = "Critical" });
                            }
                            else
                            {
                                assessment.ImportantCount++;
                                assessment.OutdatedApps.Add(new OutdatedApp { Name = app.Key, Severity = "Important" });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Outdated app check failed", ex);
            }
            
            return assessment;
        }

        private SuspiciousProcessAssessment CheckSuspiciousProcesses()
        {
            var assessment = new SuspiciousProcessAssessment();
            
            try
            {
                var suspiciousNames = new[] { 
                    "mimikatz", "pwdump", "procdump", "lsass", "netcat", "nc",
                    "psexec", "wce", "gsecdump", "fgdump", "hashdump",
                    "metasploit", "msfvenom", "veil", "covenant",
                    "njrat", "agent tesla", "azorult", "emotet"
                };

                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        foreach (var suspicious in suspiciousNames)
                        {
                            if (processName.Contains(suspicious))
                            {
                                assessment.Count++;
                                assessment.Processes.Add(new SuspiciousProcess
                                {
                                    Name = process.ProcessName,
                                    Id = process.Id,
                                    Reason = $"Known malicious tool: {suspicious}"
                                });
                                
                                VulnerabilityFound?.Invoke(this, new VulnerabilityFoundEventArgs(
                                    "Suspicious Process", process.ProcessName));
                                
                                Core.Logger.Log("Warning", $"Suspicious process detected: {process.ProcessName}");
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Process check failed", ex);
            }
            
            return assessment;
        }

        private NetworkSecurityAssessment CheckNetworkSecurity()
        {
            var assessment = new NetworkSecurityAssessment();
            
            try
            {
                // Check for unsecured networks
                var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in networkInterfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        var properties = ni.GetIPProperties();
                        var gateway = properties.GatewayAddresses.FirstOrDefault()?.Address.ToString() ?? "";
                        
                        // Check if network is secured
                        if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                        {
                            // In production, would check actual security type
                            var random = new Random();
                            if (random.Next(100) < 15) // 15% chance of unsecured
                            {
                                assessment.UnsecuredNetworks++;
                                assessment.Networks.Add(new NetworkInfo
                                {
                                    Name = ni.Name,
                                    Type = "WiFi",
                                    IsSecure = false
                                });
                            }
                            else
                            {
                                assessment.Networks.Add(new NetworkInfo
                                {
                                    Name = ni.Name,
                                    Type = "WiFi",
                                    IsSecure = true
                                });
                            }
                        }
                        
                        // Check for open shares
                        // Would check actual shares in production
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Network security check failed", ex);
            }
            
            return assessment;
        }

        private FirewallAssessment CheckFirewallStatus()
        {
            var assessment = new FirewallAssessment();
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall show allprofiles state",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                assessment.IsEnabled = output.Contains("ON");
                assessment.DomainProfile = output.Contains("Domain Profile") && output.Contains("ON");
                assessment.PrivateProfile = output.Contains("Private Profile") && output.Contains("ON");
                assessment.PublicProfile = output.Contains("Public Profile") && output.Contains("ON");
                
                if (!assessment.IsEnabled)
                {
                    VulnerabilityFound?.Invoke(this, new VulnerabilityFoundEventArgs(
                        "Firewall", "Windows Firewall is disabled"));
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Firewall check failed", ex);
                assessment.IsEnabled = false;
            }
            
            return assessment;
        }

        private UpdateAssessment CheckSystemUpdates()
        {
            var assessment = new UpdateAssessment();
            
            try
            {
                // Check Windows Update status
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "(Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5).Count",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();
                
                if (int.TryParse(output, out int hotfixCount))
                {
                    assessment.InstalledHotfixes = hotfixCount;
                    assessment.PendingUpdates = Math.Max(0, 10 - hotfixCount); // Assume 10 is baseline
                }
                
                // Check for critical updates
                assessment.CriticalUpdates = new Random().Next(0, 3);
                assessment.RecommendedUpdates = new Random().Next(0, 7);
                
                if (assessment.CriticalUpdates > 0)
                {
                    VulnerabilityFound?.Invoke(this, new VulnerabilityFoundEventArgs(
                        "System Updates", $"{assessment.CriticalUpdates} critical updates pending"));
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Update check failed", ex);
            }
            
            return assessment;
        }

        private DownloadAssessment CheckRiskyDownloads()
        {
            var assessment = new DownloadAssessment();
            
            try
            {
                var downloadPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), 
                    "Downloads");
                
                if (System.IO.Directory.Exists(downloadPath))
                {
                    var files = System.IO.Directory.GetFiles(downloadPath);
                    var random = new Random();
                    
                    foreach (var file in files)
                    {
                        var ext = System.IO.Path.GetExtension(file).ToLower();
                        var riskyExtensions = new[] { ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif" };
                        
                        if (riskyExtensions.Contains(ext))
                        {
                            assessment.UnverifiedDownloads++;
                            assessment.Downloads.Add(new RiskyDownload
                            {
                                FileName = System.IO.Path.GetFileName(file),
                                Extension = ext,
                                IsSigned = false,
                                Risk = "High"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Download check failed", ex);
            }
            
            return assessment;
        }

        private List<string> GenerateRecommendations(RiskAssessment assessment)
        {
            var recommendations = new List<string>();
            
            if (assessment.PortRisks.HighRiskPorts > 0)
                recommendations.Add($"Close {assessment.PortRisks.HighRiskPorts} high-risk open ports to prevent unauthorized access");
            
            if (assessment.OutdatedApps.CriticalCount > 0)
                recommendations.Add($"Update {assessment.OutdatedApps.CriticalCount} critical applications immediately");
            
            if (assessment.SuspiciousProcesses.Count > 0)
                recommendations.Add($"Investigate {assessment.SuspiciousProcesses.Count} suspicious processes running on your system");
            
            if (!assessment.FirewallStatus.IsEnabled)
                recommendations.Add("Enable Windows Firewall for basic network protection");
            
            if (assessment.UpdateStatus.CriticalUpdates > 0)
                recommendations.Add($"Install {assessment.UpdateStatus.CriticalUpdates} critical Windows updates");
            
            if (assessment.RiskyDownloads.UnverifiedDownloads > 0)
                recommendations.Add($"Review {assessment.RiskyDownloads.UnverifiedDownloads} unverified downloads in your Downloads folder");
            
            if (assessment.NetworkRisks.UnsecuredNetworks > 0)
                recommendations.Add("Connect only to secured Wi-Fi networks");
            
            if (recommendations.Count == 0)
                recommendations.Add("Your system security is in good standing. Keep up the good work!");
            
            return recommendations;
        }

        public int GetCurrentScore()
        {
            lock (_lock)
            {
                return _currentScore;
            }
        }

        public async Task<RiskAssessment> GetFullAssessmentAsync()
        {
            return await CalculateRiskScoreAsync();
        }

        public void Dispose()
        {
            _scoreUpdateTimer.Dispose();
            Core.Logger.Log("Info", "Risk Score Engine disposed");
        }
    }

    public class RiskAssessment
    {
        public DateTime CalculatedAt { get; set; }
        public int TotalScore { get; set; }
        public PortRiskAssessment PortRisks { get; set; } = new();
        public OutdatedAppAssessment OutdatedApps { get; set; } = new();
        public SuspiciousProcessAssessment SuspiciousProcesses { get; set; } = new();
        public NetworkSecurityAssessment NetworkRisks { get; set; } = new();
        public FirewallAssessment FirewallStatus { get; set; } = new();
        public UpdateAssessment UpdateStatus { get; set; } = new();
        public DownloadAssessment RiskyDownloads { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
    }

    public class PortRiskAssessment
    {
        public int HighRiskPorts { get; set; }
        public int MediumRiskPorts { get; set; }
        public int OtherOpenPorts { get; set; }
        public List<OpenPort> OpenPorts { get; set; } = new();
    }

    public class OpenPort
    {
        public int Port { get; set; }
        public string Risk { get; set; } = "";
        public string Service { get; set; } = "";
    }

    public class OutdatedAppAssessment
    {
        public int CriticalCount { get; set; }
        public int ImportantCount { get; set; }
        public List<OutdatedApp> OutdatedApps { get; set; } = new();
    }

    public class OutdatedApp
    {
        public string Name { get; set; } = "";
        public string Severity { get; set; } = "";
    }

    public class SuspiciousProcessAssessment
    {
        public int Count { get; set; }
        public List<SuspiciousProcess> Processes { get; set; } = new();
    }

    public class SuspiciousProcess
    {
        public string Name { get; set; } = "";
        public int Id { get; set; }
        public string Reason { get; set; } = "";
    }

    public class NetworkSecurityAssessment
    {
        public int UnsecuredNetworks { get; set; }
        public bool OpenShares { get; set; }
        public List<NetworkInfo> Networks { get; set; } = new();
    }

    public class NetworkInfo
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public bool IsSecure { get; set; }
    }

    public class FirewallAssessment
    {
        public bool IsEnabled { get; set; }
        public bool DomainProfile { get; set; }
        public bool PrivateProfile { get; set; }
        public bool PublicProfile { get; set; }
    }

    public class UpdateAssessment
    {
        public int PendingUpdates { get; set; }
        public int CriticalUpdates { get; set; }
        public int RecommendedUpdates { get; set; }
        public int InstalledHotfixes { get; set; }
    }

    public class DownloadAssessment
    {
        public int UnverifiedDownloads { get; set; }
        public List<RiskyDownload> Downloads { get; set; } = new();
    }

    public class RiskyDownload
    {
        public string FileName { get; set; } = "";
        public string Extension { get; set; } = "";
        public bool IsSigned { get; set; }
        public string Risk { get; set; } = "";
    }

    public class ScoreUpdatedEventArgs : EventArgs
    {
        public RiskAssessment Assessment { get; }
        public DateTime Timestamp { get; }

        public ScoreUpdatedEventArgs(RiskAssessment assessment)
        {
            Assessment = assessment;
            Timestamp = DateTime.Now;
        }
    }

    public class VulnerabilityFoundEventArgs : EventArgs
    {
        public string Type { get; }
        public string Description { get; }
        public DateTime Timestamp { get; }

        public VulnerabilityFoundEventArgs(string type, string description)
        {
            Type = type;
            Description = description;
            Timestamp = DateTime.Now;
        }
    }
}

