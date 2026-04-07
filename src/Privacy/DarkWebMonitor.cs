using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace SecureGuard.Privacy
{
    /// <summary>
    /// Dark Web Monitoring - Checks if user's email/password has been leaked online
    /// Uses the Have I Been Pwned API pattern (simulated for demo)
    /// </summary>
    public class DarkWebMonitor : IDisposable
    {
        private readonly string _appDataPath;
        private readonly string _monitoredEmailsFile;
        private List<string> _monitoredEmails;
        private List<BreachRecord> _breachHistory;
        
        // Known major breaches for simulation
        private static readonly BreachInfo[] KnownBreaches = new[]
        {
            new BreachInfo { Name = "Adobe", Domain = "adobe.com", Description = "Adobe systems breach", BreachDate = new DateTime(2013, 10, 4) },
            new BreachInfo { Name = "LinkedIn", Domain = "linkedin.com", Description = "LinkedIn data breach", BreachDate = new DateTime(2012, 5, 5) },
            new BreachInfo { Name = "Dropbox", Domain = "dropbox.com", Description = "Dropbox user data breach", BreachDate = new DateTime(2012, 7, 1) },
            new BreachInfo { Name = "MySpace", Domain = "myspace.com", Description = "MySpace data breach", BreachDate = new DateTime(2008, 7, 1) },
            new BreachInfo { Name = "Twitter", Domain = "twitter.com", Description = "Twitter data leak", BreachDate = new DateTime(2023, 1, 4) },
            new BreachInfo { Name = "Facebook", Domain = "facebook.com", Description = "Facebook data breach", BreachDate = new DateTime(2021, 4, 3) },
            new BreachInfo { Name = "T-Mobile", Domain = "t-mobile.com", Description = "T-Mobile data breach", BreachDate = new DateTime(2021, 8, 16) },
            new BreachInfo { Name = "SolarWinds", Domain = "solarwinds.com", Description = "Supply chain attack", BreachDate = new DateTime(2020, 12, 13) },
            new BreachInfo { Name = "Marriott", Domain = "marriott.com", Description = "Starwood guest database", BreachDate = new DateTime(2018, 9, 10) },
            new BreachInfo { Name = "Equifax", Domain = "equifax.com", Description = "Consumer data breach", BreachDate = new DateTime(2017, 5, 13) }
        };

        public event EventHandler<BreachDetectedEventArgs>? BreachDetected;
        
        public DarkWebMonitor()
        {
            _appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
                "SecureGuard");
            Directory.CreateDirectory(_appDataPath);
            
            _monitoredEmailsFile = Path.Combine(_appDataPath, "monitored_emails.json");
            _monitoredEmails = LoadMonitoredEmails();
            _breachHistory = LoadBreachHistory();
        }

        private List<string> LoadMonitoredEmails()
        {
            try
            {
                if (File.Exists(_monitoredEmailsFile))
                {
                    var json = File.ReadAllText(_monitoredEmailsFile);
                    return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load monitored emails", ex);
            }
            return new List<string>();
        }

        private void SaveMonitoredEmails()
        {
            try
            {
                var json = JsonSerializer.Serialize(_monitoredEmails, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_monitoredEmailsFile, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save monitored emails", ex);
            }
        }

        private List<BreachRecord> LoadBreachHistory()
        {
            try
            {
                var historyFile = Path.Combine(_appDataPath, "breach_history.json");
                if (File.Exists(historyFile))
                {
                    var json = File.ReadAllText(historyFile);
                    return JsonSerializer.Deserialize<List<BreachRecord>>(json) ?? new List<BreachRecord>();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load breach history", ex);
            }
            return new List<BreachRecord>();
        }

        private void SaveBreachHistory()
        {
            try
            {
                var historyFile = Path.Combine(_appDataPath, "breach_history.json");
                var json = JsonSerializer.Serialize(_breachHistory, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(historyFile, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save breach history", ex);
            }
        }

        /// <summary>
        /// Add an email to monitor
        /// </summary>
        public void AddEmailToMonitor(string email)
        {
            if (!_monitoredEmails.Contains(email, StringComparer.OrdinalIgnoreCase))
            {
                _monitoredEmails.Add(email.ToLower());
                SaveMonitoredEmails();
                Core.Logger.Log("Info", $"Added email to dark web monitoring: {email}");
                
                // Immediately check for breaches
                Task.Run(() => CheckEmailForBreaches(email));
            }
        }

        /// <summary>
        /// Remove an email from monitoring
        /// </summary>
        public void RemoveEmailFromMonitor(string email)
        {
            _monitoredEmails.Remove(email.ToLower());
            SaveMonitoredEmails();
            Core.Logger.Log("Info", $"Removed email from dark web monitoring: {email}");
        }

        /// <summary>
        /// Check if email has been in any breaches (simulated)
        /// </summary>
        public async Task<List<BreachRecord>> CheckEmailForBreaches(string email)
        {
            var breaches = new List<BreachRecord>();
            
            try
            {
                // Simulate API call delay
                await Task.Delay(500);
                
                // Simulate breach detection based on email domain
                // In production, this would use the Have I Been Pwned API or similar
                var emailLower = email.ToLower();
                var domain = emailLower.Split('@').LastOrDefault() ?? "";
                
                // Simulate some random breaches for demonstration
                var random = new Random(emailLower.GetHashCode());
                
                foreach (var breach in KnownBreaches)
                {
                    // Simulate breach detection (in reality, this would check actual data)
                    if (random.Next(10) < 3) // 30% chance of being in each breach
                    {
                        var record = new BreachRecord
                        {
                            Email = email,
                            BreachName = breach.Name,
                            Domain = breach.Domain,
                            Description = breach.Description,
                            BreachDate = breach.BreachDate,
                            DataTypes = GetDataTypesForBreach(breach.Name),
                            DetectedDate = DateTime.Now
                        };
                        
                        breaches.Add(record);
                        _breachHistory.Add(record);
                        
                        BreachDetected?.Invoke(this, new BreachDetectedEventArgs
                        {
                            Email = email,
                            BreachName = breach.Name,
                            BreachDate = breach.BreachDate,
                            DataTypes = record.DataTypes
                        });
                        
                        Core.Logger.Log("Warning", $"Breach detected for {email}: {breach.Name}");
                    }
                }
                
                if (breaches.Count > 0)
                {
                    SaveBreachHistory();
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Error checking breaches for {email}", ex);
            }
            
            return breaches;
        }

        private List<string> GetDataTypesForBreach(string breachName)
        {
            // Return simulated data types based on breach
            return breachName.ToLower() switch
            {
                "adobe" => new List<string> { "Email addresses", "Passwords", "Password hints" },
                "linkedin" => new List<string> { "Email addresses", "Passwords" },
                "dropbox" => new List<string> { "Email addresses", "Passwords" },
                "twitter" => new List<string> { "Email addresses", "Usernames" },
                "facebook" => new List<string> { "Email addresses", "Phone numbers", "Locations" },
                "t-mobile" => new List<string> { "Email addresses", "Phone numbers", "IMEI numbers" },
                "equifax" => new List<string> { "Social security numbers", "Birth dates", "Addresses" },
                "marriott" => new List<string> { "Email addresses", "Passport numbers", "Phone numbers" },
                _ => new List<string> { "Email addresses", "Passwords", "Personal information" }
            };
        }

        /// <summary>
        /// Check all monitored emails
        /// </summary>
        public async Task CheckAllEmailsAsync()
        {
            foreach (var email in _monitoredEmails.ToList())
            {
                await CheckEmailForBreaches(email);
            }
        }

        /// <summary>
        /// Get breach history for all monitored emails
        /// </summary>
        public List<BreachRecord> GetBreachHistory()
        {
            return _breachHistory.OrderByDescending(b => b.BreachDate).ToList();
        }

        /// <summary>
        /// Get monitored emails
        /// </summary>
        public List<string> GetMonitoredEmails()
        {
            return _monitoredEmails.ToList();
        }

        /// <summary>
        /// Get breach statistics
        /// </summary>
        public DarkWebStats GetStats()
        {
            return new DarkWebStats
            {
                MonitoredEmailsCount = _monitoredEmails.Count,
                TotalBreaches = _breachHistory.Count,
                UniqueBreachedSites = _breachHistory.Select(b => b.Domain).Distinct().Count(),
                LastCheck = _breachHistory.Max(b => b.DetectedDate),
                RiskLevel = CalculateRiskLevel()
            };
        }

        private string CalculateRiskLevel()
        {
            if (_breachHistory.Count == 0) return "Low";
            if (_breachHistory.Count <= 2) return "Medium";
            if (_breachHistory.Count <= 5) return "High";
            return "Critical";
        }

        /// <summary>
        /// Clear breach history
        /// </summary>
        public void ClearHistory()
        {
            _breachHistory.Clear();
            SaveBreachHistory();
            Core.Logger.Log("Info", "Breach history cleared");
        }

        public void Dispose()
        {
            SaveMonitoredEmails();
            SaveBreachHistory();
        }
    }

    public class BreachInfo
    {
        public string Name { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime BreachDate { get; set; }
    }

    public class BreachRecord
    {
        public string Email { get; set; } = "";
        public string BreachName { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime BreachDate { get; set; }
        public List<string> DataTypes { get; set; } = new();
        public DateTime DetectedDate { get; set; }
    }

    public class BreachDetectedEventArgs : EventArgs
    {
        public string Email { get; set; } = "";
        public string BreachName { get; set; } = "";
        public DateTime BreachDate { get; set; }
        public List<string> DataTypes { get; set; } = new();
    }

    public class DarkWebStats
    {
        public int MonitoredEmailsCount { get; set; }
        public int TotalBreaches { get; set; }
        public int UniqueBreachedSites { get; set; }
        public DateTime? LastCheck { get; set; }
        public string RiskLevel { get; set; } = "Low";
    }
}

