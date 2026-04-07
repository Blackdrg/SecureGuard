using System;
using System.Collections.Generic;
using System.Linq;
using System.Timers;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 3: Global Threat Radar Map
    /// Real-time visualization dashboard showing active attacks worldwide
    /// </summary>
    public class GlobalThreatRadar : IDisposable
    {
        private readonly Timer _updateTimer;
        private readonly List<LiveAttack> _activeAttacks;
        private readonly Dictionary<string, CountryStats> _countryStats;
        private readonly object _lock = new();
        
        public event EventHandler<AttackUpdateEventArgs>? AttackUpdated;
        public event EventHandler<CountryUpdateEventArgs>? CountryStatsUpdated;

        public GlobalThreatRadar()
        {
            _activeAttacks = new List<LiveAttack>();
            _countryStats = new Dictionary<string, CountryStats>();
            
            _updateTimer = new Timer(5000);
            _updateTimer.Elapsed += OnUpdateTimer;
            
            InitializeMockData();
            Core.Logger.Log("Info", "Global Threat Radar initialized");
        }

        private void InitializeMockData()
        {
            // Initialize country statistics with realistic data
            var countries = new Dictionary<string, (double lat, double lon, int threats)>
            {
                ["US"] = (37.0902, -95.7129, 15420),
                ["CN"] = (35.8617, 104.1954, 8930),
                ["RU"] = (61.5240, 105.3188, 7620),
                ["BR"] = (-14.2350, -51.9253, 5230),
                ["IN"] = (20.5937, 78.9629, 4890),
                ["DE"] = (51.1657, 10.4515, 3240),
                ["UK"] = (55.3781, -3.4360, 2980),
                ["FR"] = (46.2276, 2.2137, 2650),
                ["JP"] = (36.2048, 138.2529, 2340),
                ["KR"] = (35.9078, 127.7669, 1890),
                ["AU"] = (-25.2744, 133.7751, 1560),
                ["CA"] = (56.1304, -106.3468, 1420),
                ["NL"] = (52.1326, 5.2913, 1280),
                ["UA"] = (48.3794, 31.1656, 2150),
                ["IR"] = (32.4279, 53.6880, 1890)
            };

            foreach (var country in countries)
            {
                _countryStats[country.Key] = new CountryStats
                {
                    CountryCode = country.Key,
                    Latitude = country.Value.lat,
                    Longitude = country.Value.lon,
                    ThreatCount = country.Value.threats,
                    AttackTypes = GetAttackTypeDistribution(country.Value.threats),
                    RiskLevel = country.Value.threats > 5000 ? "High" : country.Value.threats > 2000 ? "Medium" : "Low"
                };
            }

            // Initialize some live attacks
            var attackTypes = new[] { "Ransomware", "Phishing", "DDoS", "Malware", "Botnet", "Exploit" };
            var targets = new[] { "Financial", "Healthcare", "Government", "Retail", "Technology", "Energy" };
            
            var random = new Random();
            for (int i = 0; i < 15; i++)
            {
                var country = countries.ElementAt(random.Next(countries.Count));
                _activeAttacks.Add(new LiveAttack
                {
                    Id = $"attack_{i + 1}",
                    Type = attackTypes[random.Next(attackTypes.Length)],
                    Target = targets[random.Next(targets.Length)],
                    CountryCode = country.Key,
                    Latitude = country.Value.lat + (random.NextDouble() - 0.5) * 10,
                    Longitude = country.Value.lon + (random.NextDouble() - 0.5) * 10,
                    Timestamp = DateTime.Now.AddMinutes(-random.Next(120)),
                    Severity = random.Next(1, 10) > 7 ? "Critical" : random.Next(1, 10) > 4 ? "High" : "Medium",
                    Status = "Active"
                });
            }
        }

        private Dictionary<string, int> GetAttackTypeDistribution(int totalThreats)
        {
            var random = new Random(totalThreats);
            return new Dictionary<string, int>
            {
                ["Ransomware"] = random.Next(10, 30),
                ["Phishing"] = random.Next(20, 40),
                ["Malware"] = random.Next(15, 35),
                ["DDoS"] = random.Next(5, 20),
                ["Botnet"] = random.Next(5, 15),
                ["Exploit"] = random.Next(5, 15)
            };
        }

        public void Start()
        {
            _updateTimer.Start();
            Core.Logger.Log("Info", "Global Threat Radar started");
        }

        public void Stop()
        {
            _updateTimer.Stop();
            Core.Logger.Log("Info", "Global Threat Radar stopped");
        }

        private void OnUpdateTimer(object? sender, ElapsedEventArgs e)
        {
            UpdateThreatData();
        }

        private void UpdateThreatData()
        {
            lock (_lock)
            {
                var random = new Random();
                
                // Update country stats with new threats
                foreach (var country in _countryStats.Values)
                {
                    var increase = random.Next(0, 5);
                    country.ThreatCount += increase;
                    if (increase > 0)
                    {
                        var attackTypes = new[] { "Ransomware", "Phishing", "Malware", "DDoS", "Botnet" };
                        var attackType = attackTypes[random.Next(attackTypes.Length)];
                        if (country.AttackTypes.ContainsKey(attackType))
                            country.AttackTypes[attackType] += increase;
                    }
                }

                // Update attack statuses
                foreach (var attack in _activeAttacks)
                {
                    if (attack.Status == "Active" && random.Next(100) < 10)
                    {
                        attack.Status = random.Next(2) == 0 ? "Contained" : "Blocked";
                        attack.EndTime = DateTime.Now;
                    }
                }

                // Add new attacks occasionally
                if (random.Next(100) < 20)
                {
                    var countries = _countryStats.Keys.ToList();
                    var newAttack = new LiveAttack
                    {
                        Id = $"attack_{DateTime.Now.Ticks}",
                        Type = GetRandomAttackType(),
                        Target = GetRandomTarget(),
                        CountryCode = countries[random.Next(countries.Count)],
                        Latitude = _countryStats.Values.First(c => c.CountryCode == countries[random.Next(countries.Count)]).Latitude,
                        Longitude = _countryStats.Values.First(c => c.CountryCode == countries[random.Next(countries.Count)]).Longitude,
                        Timestamp = DateTime.Now,
                        Severity = random.Next(1, 10) > 6 ? "Critical" : random.Next(1, 10) > 3 ? "High" : "Medium",
                        Status = "Active"
                    };
                    _activeAttacks.Add(newAttack);
                    
                    // Keep only last 50 attacks
                    if (_activeAttacks.Count > 50)
                        _activeAttacks.RemoveAt(0);
                }

                AttackUpdated?.Invoke(this, new AttackUpdateEventArgs(_activeAttacks.Count, GetTotalThreats()));
                CountryStatsUpdated?.Invoke(this, new CountryUpdateEventArgs(_countryStats.Values.ToList()));
            }
        }

        private string GetRandomAttackType()
        {
            var types = new[] { "Ransomware", "Phishing", "DDoS", "Malware", "Botnet", "Exploit", "Spyware", "Adware" };
            return types[new Random().Next(types.Length)];
        }

        private string GetRandomTarget()
        {
            var targets = new[] { "Financial", "Healthcare", "Government", "Retail", "Technology", "Energy", "Education", "Manufacturing" };
            return targets[new Random().Next(targets.Length)];
        }

        public RadarData GetRadarData()
        {
            lock (_lock)
            {
                return new RadarData
                {
                    ActiveAttacks = _activeAttacks.ToList(),
                    CountryStats = _countryStats.Values.ToList(),
                    TotalThreats = GetTotalThreats(),
                    AttacksBlocked = _activeAttacks.Count(a => a.Status == "Blocked" || a.Status == "Contained"),
                    ActiveCount = _activeAttacks.Count(a => a.Status == "Active"),
                    LastUpdated = DateTime.Now
                };
            }
        }

        private int GetTotalThreats()
        {
            return _countryStats.Values.Sum(c => c.ThreatCount);
        }

        public void Dispose()
        {
            Stop();
            _updateTimer.Dispose();
        }
    }

    public class LiveAttack
    {
        public string Id { get; set; } = "";
        public string Type { get; set; } = "";
        public string Target { get; set; } = "";
        public string CountryCode { get; set; } = "";
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public DateTime Timestamp { get; set; }
        public DateTime? EndTime { get; set; }
        public string Severity { get; set; } = "";
        public string Status { get; set; } = "";
    }

    public class CountryStats
    {
        public string CountryCode { get; set; } = "";
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public int ThreatCount { get; set; }
        public Dictionary<string, int> AttackTypes { get; set; } = new();
        public string RiskLevel { get; set; } = "";
    }

    public class RadarData
    {
        public List<LiveAttack> ActiveAttacks { get; set; } = new();
        public List<CountryStats> CountryStats { get; set; } = new();
        public int TotalThreats { get; set; }
        public int AttacksBlocked { get; set; }
        public int ActiveCount { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class AttackUpdateEventArgs : EventArgs
    {
        public int ActiveAttacks { get; }
        public int TotalThreats { get; }
        public DateTime Timestamp { get; }

        public AttackUpdateEventArgs(int activeAttacks, int totalThreats)
        {
            ActiveAttacks = activeAttacks;
            TotalThreats = totalThreats;
            Timestamp = DateTime.Now;
        }
    }

    public class CountryUpdateEventArgs : EventArgs
    {
        public List<CountryStats> Countries { get; }
        public DateTime Timestamp { get; }

        public CountryUpdateEventArgs(List<CountryStats> countries)
        {
            Countries = countries;
            Timestamp = DateTime.Now;
        }
    }
}

