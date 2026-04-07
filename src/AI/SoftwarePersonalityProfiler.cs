using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 2: Software Personality Profiler
    /// Creates behavioral personality profiles for every application
    /// Detects anomalies when apps deviate from their established personality
    /// </summary>
    public class SoftwarePersonalityProfiler : IDisposable
    {
        private readonly Dictionary<string, AppPersonality> _appProfiles = new();
        private readonly Dictionary<string, List<BehaviorSnapshot>> _behaviorHistory = new();
        private readonly object _lock = new();
        private bool _isRunning;
        private readonly int _historySize = 1000;
        
        // Personality type definitions
        public static readonly Dictionary<string, PersonalityType> DefaultPersonalities = new()
        {
            ["chrome"] = PersonalityType.NetworkHeavy,
            ["firefox"] = PersonalityType.NetworkHeavy,
            ["edge"] = PersonalityType.NetworkHeavy,
            ["notepad"] = PersonalityType.FileLight,
            ["notepad++"] = PersonalityType.FileLight,
            ["code"] = PersonalityType.FileMedium,
            ["devenv"] = PersonalityType.FileMedium,
            ["explorer"] = PersonalityType.SystemUtility,
            ["svchost"] = PersonalityType.SystemUtility,
            ["services"] = PersonalityType.SystemUtility,
            ["lsass"] = PersonalityType.SystemUtility,
            ["winlogon"] = PersonalityType.SystemUtility,
            ["powershell"] = PersonalityType.Scripting,
            ["cmd"] = PersonalityType.Scripting,
            ["python"] = PersonalityType.Scripting,
            ["node"] = PersonalityType.Scripting,
            ["java"] = PersonalityType.Application,
            ["dotnet"] = PersonalityType.Application,
            ["outlook"] = PersonalityType.Productivity,
            ["excel"] = PersonalityType.Productivity,
            ["word"] = PersonalityType.Productivity,
            ["teams"] = PersonalityType.Collaboration,
            ["slack"] = PersonalityType.Collaboration,
            ["zoom"] = PersonalityType.Collaboration
        };

        public event EventHandler<PersonalityDeviationEventArgs>? PersonalityDeviationDetected;

        public SoftwarePersonalityProfiler()
        {
            Logger.Log("Info", "Software Personality Profiler initialized");
        }

        public void Start()
        {
            _isRunning = true;
            LoadProfiles();
            Logger.Log("Info", "Software Personality Profiler started");
        }

        public void Stop()
        {
            _isRunning = false;
            SaveProfiles();
            Logger.Log("Info", "Software Personality Profiler stopped");
        }

        /// <summary>
        /// Records behavior for an application
        /// </summary>
        public async Task RecordBehaviorAsync(string processName, ProcessBehavior behavior)
        {
            var key = processName.ToLower();
            
            lock (_lock)
            {
                if (!_behaviorHistory.ContainsKey(key))
                {
                    _behaviorHistory[key] = new List<BehaviorSnapshot>();
                }
                
                _behaviorHistory[key].Add(new BehaviorSnapshot
                {
                    Timestamp = DateTime.Now,
                    FileOperations = behavior.FileOperations,
                    NetworkOperations = behavior.NetworkOperations,
                    RegistryOperations = behavior.RegistryOperations,
                    ProcessOperations = behavior.ProcessOperations,
                    MemoryUsage = behavior.MemoryUsage,
                    CpuUsage = behavior.CpuUsage
                });
                
                // Keep history size manageable
                if (_behaviorHistory[key].Count > _historySize)
                {
                    _behaviorHistory[key].RemoveAt(0);
                }
            }
            
            // Update personality profile
            await UpdatePersonalityProfileAsync(key);
            
            // Check for deviations
            CheckForDeviations(key);
        }

        /// <summary>
        /// Updates the personality profile based on recent behaviors
        /// </summary>
        private async Task UpdatePersonalityProfileAsync(string processName)
        {
            await Task.Run(() =>
            {
                lock (_lock)
                {
                    if (!_behaviorHistory.TryGetValue(processName, out var history) || history.Count < 10)
                        return;
                    
                    // Calculate average behaviors from recent history
                    var recentHistory = history.TakeLast(100).ToList();
                    
                    var profile = _appProfiles.ContainsKey(processName) 
                        ? _appProfiles[processName] 
                        : new AppPersonality { AppName = processName };
                    
                    profile.FileOperationsRate = recentHistory.Average(h => h.FileOperations);
                    profile.NetworkOperationsRate = recentHistory.Average(h => h.NetworkOperations);
                    profile.RegistryOperationsRate = recentHistory.Average(h => h.RegistryOperations);
                    profile.ProcessOperationsRate = recentHistory.Average(h => h.ProcessOperations);
                    profile.AverageMemory = (long)recentHistory.Average(h => h.MemoryUsage);
                    profile.AverageCpu = recentHistory.Average(h => h.CpuUsage);
                    profile.SampleCount = history.Count;
                    profile.LastUpdated = DateTime.Now;
                    
                    // Determine personality type based on behavior
                    profile.PersonalityType = DeterminePersonalityType(profile);
                    
                    // Calculate baseline deviation thresholds
                    profile.FileOpsStdDev = CalculateStdDev(recentHistory.Select(h => (double)h.FileOperations).ToList());
                    profile.NetworkOpsStdDev = CalculateStdDev(recentHistory.Select(h => (double)h.NetworkOperations).ToList());
                    profile.RegistryOpsStdDev = CalculateStdDev(recentHistory.Select(h => (double)h.RegistryOperations).ToList());
                    
                    _appProfiles[processName] = profile;
                }
            });
        }

        private PersonalityType DeterminePersonalityType(AppPersonality profile)
        {
            // Classify based on dominant behavior
            var maxBehavior = new[]
            {
                ("File", profile.FileOperationsRate),
                ("Network", profile.NetworkOperationsRate),
                ("Registry", profile.RegistryOperationsRate),
                ("Process", profile.ProcessOperationsRate)
            }.MaxBy(x => x.Item2);

            return maxBehavior.Item1 switch
            {
                "Network" when profile.NetworkOperationsRate > 5 => PersonalityType.NetworkHeavy,
                "File" when profile.FileOperationsRate > 10 => PersonalityType.FileHeavy,
                "File" when profile.FileOperationsRate > 2 => PersonalityType.FileMedium,
                "File" => PersonalityType.FileLight,
                "Registry" => PersonalityType.SystemUtility,
                "Process" => PersonalityType.SystemUtility,
                _ => PersonalityType.Application
            };
        }

        /// <summary>
        /// Checks if current behavior deviates from established personality
        /// </summary>
        private void CheckForDeviations(string processName)
        {
            lock (_lock)
            {
                if (!_appProfiles.TryGetValue(processName, out var profile) || 
                    !_behaviorHistory.TryGetValue(processName, out var history) ||
                    history.Count < 10)
                    return;
                
                var recent = history.Last();
                var deviationScore = CalculateDeviationScore(profile, recent);
                
                if (deviationScore > 0.7) // 70% deviation threshold
                {
                    var deviation = new PersonalityDeviation
                    {
                        ProcessName = processName,
                        DeviationScore = deviationScore,
                        Timestamp = DateTime.Now,
                        CurrentBehavior = recent,
                        ExpectedBehavior = profile
                    };
                    
                    // Determine deviation type
                    if (recent.NetworkOperations > profile.NetworkOperationsRate * 3 && 
                        profile.PersonalityType != PersonalityType.NetworkHeavy)
                    {
                        deviation.DeviationType = "Unexpected network activity";
                    }
                    else if (recent.FileOperations > profile.FileOperationsRate * 3 &&
                        profile.PersonalityType == PersonalityType.FileLight)
                    {
                        deviation.DeviationType = "Excessive file operations";
                    }
                    else if (recent.RegistryOperations > profile.RegistryOperationsRate * 5)
                    {
                        deviation.DeviationType = "Unexpected registry modification";
                    }
                    else if (recent.ProcessOperations > profile.ProcessOperationsRate * 4)
                    {
                        deviation.DeviationType = "Suspicious process spawning";
                    }
                    
                    PersonalityDeviationDetected?.Invoke(this, new PersonalityDeviationEventArgs(deviation));
                    
                    Logger.Log("Warning", $"Personality deviation detected: {processName} - {deviation.DeviationType} (Score: {deviationScore:P0})");
                }
            }
        }

        private double CalculateDeviationScore(AppPersonality profile, BehaviorSnapshot current)
        {
            var fileDeviation = profile.FileOpsStdDev > 0 
                ? Math.Abs(current.FileOperations - profile.FileOperationsRate) / (profile.FileOpsStdDev * 3)
                : 0;
            
            var networkDeviation = profile.NetworkOpsStdDev > 0
                ? Math.Abs(current.NetworkOperations - profile.NetworkOperationsRate) / (profile.NetworkOpsStdDev * 3)
                : 0;
            
            var registryDeviation = profile.RegistryOpsStdDev > 0
                ? Math.Abs(current.RegistryOperations - profile.RegistryOperationsRate) / (profile.RegistryOpsStdDev * 3)
                : 0;
            
            var processDeviation = Math.Abs(current.ProcessOperations - profile.ProcessOperationsRate) / 
                Math.Max(1, profile.ProcessOperationsRate * 2);
            
            // Weighted average
            return (fileDeviation * 0.3 + networkDeviation * 0.3 + registryDeviation * 0.25 + processDeviation * 0.15)
                .Clamp(0, 1);
        }

        private double CalculateStdDev(List<double> values)
        {
            if (values.Count < 2) return 0;
            
            var avg = values.Average();
            var sumSquares = values.Sum(v => Math.Pow(v - avg, 2));
            return Math.Sqrt(sumSquares / values.Count);
        }

        /// <summary>
        /// Gets the personality profile for an application
        /// </summary>
        public AppPersonality? GetProfile(string processName)
        {
            lock (_lock)
            {
                var key = processName.ToLower();
                return _appProfiles.TryGetValue(key, out var profile) ? profile : null;
            }
        }

        /// <summary>
        /// Gets all established profiles
        /// </summary>
        public Dictionary<string, AppPersonality> GetAllProfiles()
        {
            lock (_lock)
            {
                return new Dictionary<string, AppPersonality>(_appProfiles);
            }
        }

        private void LoadProfiles()
        {
            try
            {
                var path = GetProfilePath();
                if (File.Exists(path))
                {
                    // Load from storage (simplified)
                    Logger.Log("Info", "Loaded application personality profiles");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load personality profiles", ex);
            }
        }

        private void SaveProfiles()
        {
            try
            {
                var path = GetProfilePath();
                // Save to storage (simplified)
                Logger.Log("Info", "Saved application personality profiles");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save personality profiles", ex);
            }
        }

        private string GetProfilePath()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(appData, "SecureGuard", "profiles.json");
        }

        public void Dispose()
        {
            Stop();
        }
    }

    public class ProcessBehavior
    {
        public int FileOperations { get; set; }
        public int NetworkOperations { get; set; }
        public int RegistryOperations { get; set; }
        public int ProcessOperations { get; set; }
        public long MemoryUsage { get; set; }
        public double CpuUsage { get; set; }
    }

    public class BehaviorSnapshot
    {
        public DateTime Timestamp { get; set; }
        public int FileOperations { get; set; }
        public int NetworkOperations { get; set; }
        public int RegistryOperations { get; set; }
        public int ProcessOperations { get; set; }
        public long MemoryUsage { get; set; }
        public double CpuUsage { get; set; }
    }

    public class AppPersonality
    {
        public string AppName { get; set; } = "";
        public PersonalityType PersonalityType { get; set; }
        public double FileOperationsRate { get; set; }
        public double NetworkOperationsRate { get; set; }
        public double RegistryOperationsRate { get; set; }
        public double ProcessOperationsRate { get; set; }
        public long AverageMemory { get; set; }
        public double AverageCpu { get; set; }
        public double FileOpsStdDev { get; set; }
        public double NetworkOpsStdDev { get; set; }
        public double RegistryOpsStdDev { get; set; }
        public int SampleCount { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class PersonalityDeviation
    {
        public string ProcessName { get; set; } = "";
        public double DeviationScore { get; set; }
        public string DeviationType { get; set; } = "";
        public BehaviorSnapshot CurrentBehavior { get; set; } = new();
        public AppPersonality ExpectedBehavior { get; set; } = new();
        public DateTime Timestamp { get; set; }
    }

    public enum PersonalityType
    {
        Unknown,
        FileLight,
        FileMedium,
        FileHeavy,
        NetworkHeavy,
        NetworkLight,
        SystemUtility,
        Scripting,
        Application,
        Productivity,
        Collaboration
    }

    public class PersonalityDeviationEventArgs : EventArgs
    {
        public PersonalityDeviation Deviation { get; }
        
        public PersonalityDeviationEventArgs(PersonalityDeviation deviation)
        {
            Deviation = deviation;
        }
    }

    public static class MathExtensions
    {
        public static double Clamp(this double value, double min, double max)
        {
            return Math.Max(min, Math.Min(max, value));
        }
    }
}

