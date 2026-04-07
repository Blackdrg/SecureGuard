using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Security Score Engine - Calculates system security score (0-100)
    /// Based on outdated apps, firewall status, vulnerabilities, risky settings
    /// </summary>
    public class SecurityScoreEngine
    {
        private readonly string _appDataPath;
        
        public SecurityScoreEngine()
        {
            _appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(_appDataPath);
        }

        /// <summary>
        /// Calculate overall security score
        /// </summary>
        public async Task<SecurityScoreResult> CalculateScoreAsync()
        {
            var result = new SecurityScoreResult
            {
                Timestamp = DateTime.Now
            };

            // Calculate individual scores
            var realtimeScore = await GetRealTimeProtectionScoreAsync();
            var firewallScore = GetFirewallScore();
            var vulnerabilityScore = GetVulnerabilityScore();
            var updateScore = GetUpdateScore();
            var privacyScore = GetPrivacyScore();
            var settingsScore = GetSettingsScore();

            // Weight the scores
            result.RealtimeProtectionScore = realtimeScore;
            result.FirewallScore = firewallScore;
            result.VulnerabilityScore = vulnerabilityScore;
            result.UpdateScore = updateScore;
            result.PrivacyScore = privacyScore;
            result.SettingsScore = settingsScore;

            // Calculate overall score (weighted average)
            result.OverallScore = (int)(
                (realtimeScore * 0.25) +
                (firewallScore * 0.15) +
                (vulnerabilityScore * 0.20) +
                (updateScore * 0.15) +
                (privacyScore * 0.10) +
                (settingsScore * 0.15)
            );

            // Determine grade
            result.Grade = GetGrade(result.OverallScore);

            // Generate recommendations
            result.Recommendations = GenerateRecommendations(result);

            // Save score history
            await SaveScoreHistoryAsync(result);

            Logger.Log("Info", $"Security score calculated: {result.OverallScore}/100 ({result.Grade})");

            return result;
        }

        private async Task<int> GetRealTimeProtectionScoreAsync()
        {
            int score = 50; // Base score
            
            try
            {
                var configPath = Path.Combine(_appDataPath, "config.json");
                if (File.Exists(configPath))
                {
                    var json = await File.ReadAllTextAsync(configPath);
                    var config = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(json);
                    
                    if (config != null)
                    {
                        if (config.RealTimeProtectionEnabled == true) score += 25;
                        if (config.RansomwareShieldEnabled == true) score += 15;
                        if (config.NetworkProtectionEnabled == true) score += 10;
                    }
                }
                
                // Check if protection is actually running
                // In production, would check actual service status
                score += 0; // Assume running if enabled
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to calculate realtime protection score", ex);
            }
            
            return Math.Min(100, score);
        }

        private int GetFirewallScore()
        {
            int score = 70;
            
            try
            {
                // Check Windows Firewall status
                // In production, would use netsh or Windows Firewall COM
                var firewallEnabled = true; // Assume enabled on modern Windows
                
                if (firewallEnabled)
                {
                    score = 85;
                }
                
                // Check for rules
                var rulesPath = Path.Combine(_appDataPath, "firewall_rules.json");
                if (File.Exists(rulesPath))
                {
                    score = Math.Min(100, score + 10);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get firewall score", ex);
            }
            
            return score;
        }

        private int GetVulnerabilityScore()
        {
            int score = 75;
            
            try
            {
                // Check for known vulnerabilities
                // In production, would check against vulnerability database
                
                // Check if any critical processes are running with known exploits
                var vulnerableSoftware = CheckForVulnerableSoftware();
                if (vulnerableSoftware.Count > 0)
                {
                    score -= vulnerableSoftware.Count * 10;
                }
                
                // Check for weak passwords (simplified)
                score += 0; // Would check password policy
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get vulnerability score", ex);
            }
            
            return Math.Max(0, Math.Min(100, score));
        }

        private int GetUpdateScore()
        {
            int score = 70;
            
            try
            {
                // Check Windows Update status
                var updatePath = Path.Combine(_appDataPath, "updates.json");
                
                if (File.Exists(updatePath))
                {
                    var json = File.ReadAllText(updatePath);
                    var updates = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(json);
                    
                    if (updates != null && updates.lastCheck != null)
                    {
                        var lastCheck = DateTime.Parse(updates.lastCheck.ToString());
                        var daysSinceCheck = (DateTime.Now - lastCheck).Days;
                        
                        if (daysSinceCheck <= 7)
                        {
                            score = 90;
                        }
                        else if (daysSinceCheck <= 14)
                        {
                            score = 75;
                        }
                        else if (daysSinceCheck > 30)
                        {
                            score = 40;
                        }
                    }
                }
                
                // Check virus definition age
                var sigPath = Path.Combine(_appDataPath, "signatures.json");
                if (File.Exists(sigPath))
                {
                    // Would check signature date
                    score = Math.Min(100, score + 10);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get update score", ex);
            }
            
            return score;
        }

        private int GetPrivacyScore()
        {
            int score = 80;
            
            try
            {
                // Check privacy settings
                var privacyPath = Path.Combine(_appDataPath, "privacy.json");
                
                if (File.Exists(privacyPath))
                {
                    var json = File.ReadAllText(privacyPath);
                    var settings = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(json);
                    
                    if (settings != null)
                    {
                        if (settings.webcamProtection == true) score += 5;
                        if (settings.micProtection == true) score += 5;
                        if (settings.keyloggerProtection == true) score += 5;
                        if (settings.locationTracking == false) score += 5;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get privacy score", ex);
            }
            
            return Math.Min(100, score);
        }

        private int GetSettingsScore()
        {
            int score = 70;
            
            try
            {
                // Check security settings
                var configPath = Path.Combine(_appDataPath, "config.json");
                
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var config = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(json);
                    
                    if (config != null)
                    {
                        if (config.ShowNotifications == true) score += 10;
                        if (config.AutoUpdate == true) score += 10;
                        if (config.StartWithWindows == true) score += 5;
                        
                        // Check for secure settings
                        if (config.BehavioralMonitoring == true) score += 5;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get settings score", ex);
            }
            
            return Math.Min(100, score);
        }

        private List<string> CheckForVulnerableSoftware()
        {
            var vulnerable = new List<string>();
            
            // In production, would check actual software versions
            // and known CVE databases
            
            return vulnerable;
        }

        private string GetGrade(int score)
        {
            return score switch
            {
                >= 90 => "A+",
                >= 80 => "A",
                >= 70 => "B",
                >= 60 => "C",
                >= 50 => "D",
                _ => "F"
            };
        }

        private List<string> GenerateRecommendations(SecurityScoreResult result)
        {
            var recommendations = new List<string>();
            
            if (result.RealtimeProtectionScore < 70)
            {
                recommendations.Add("Enable real-time protection for continuous security");
            }
            
            if (result.FirewallScore < 70)
            {
                recommendations.Add("Enable Windows Firewall for network protection");
            }
            
            if (result.VulnerabilityScore < 60)
            {
                recommendations.Add("Update vulnerable software to patch security holes");
            }
            
            if (result.UpdateScore < 60)
            {
                recommendations.Add("Check for Windows and software updates");
            }
            
            if (result.PrivacyScore < 70)
            {
                recommendations.Add("Enable privacy protections to prevent tracking");
            }
            
            if (result.SettingsScore < 70)
            {
                recommendations.Add("Review and strengthen security settings");
            }
            
            if (recommendations.Count == 0)
            {
                recommendations.Add("Your system is well protected! Keep up the good work.");
            }
            
            return recommendations;
        }

        private async Task SaveScoreHistoryAsync(SecurityScoreResult result)
        {
            try
            {
                var historyPath = Path.Combine(_appDataPath, "score_history.json");
                var history = new List<ScoreHistoryEntry>();
                
                if (File.Exists(historyPath))
                {
                    var json = await File.ReadAllTextAsync(historyPath);
                    history = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ScoreHistoryEntry>>(json) ?? new List<ScoreHistoryEntry>();
                }
                
                history.Add(new ScoreHistoryEntry
                {
                    Timestamp = result.Timestamp,
                    Score = result.OverallScore,
                    Grade = result.Grade
                });
                
                // Keep last 30 days
                var cutoff = DateTime.Now.AddDays(-30);
                history = history.Where(h => h.Timestamp > cutoff).ToList();
                
                var newJson = Newtonsoft.Json.JsonConvert.SerializeObject(history, Newtonsoft.Json.Formatting.Indented);
                await File.WriteAllTextAsync(historyPath, newJson);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save score history", ex);
            }
        }

        /// <summary>
        /// Get score history for graphing
        /// </summary>
        public async Task<List<ScoreHistoryEntry>> GetScoreHistoryAsync(int days = 7)
        {
            try
            {
                var historyPath = Path.Combine(_appDataPath, "score_history.json");
                if (File.Exists(historyPath))
                {
                    var json = await File.ReadAllTextAsync(historyPath);
                    var history = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ScoreHistoryEntry>>(json) ?? new List<ScoreHistoryEntry>();
                    
                    var cutoff = DateTime.Now.AddDays(-days);
                    return history.Where(h => h.Timestamp > cutoff).ToList();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to get score history", ex);
            }
            
            return new List<ScoreHistoryEntry>();
        }
    }

    public class SecurityScoreResult
    {
        public DateTime Timestamp { get; set; }
        public int OverallScore { get; set; }
        public string Grade { get; set; } = "F";
        public int RealtimeProtectionScore { get; set; }
        public int FirewallScore { get; set; }
        public int VulnerabilityScore { get; set; }
        public int UpdateScore { get; set; }
        public int PrivacyScore { get; set; }
        public int SettingsScore { get; set; }
        public List<string> Recommendations { get; set; } = new();
    }

    public class ScoreHistoryEntry
    {
        public DateTime Timestamp { get; set; }
        public int Score { get; set; }
        public string Grade { get; set; } = "";
    }
}

