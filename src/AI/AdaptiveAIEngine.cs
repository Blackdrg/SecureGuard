using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 8: Adaptive AI That Evolves Per User
    /// Trains locally on user behavior to detect anomalies specific to each user
    /// Learns: user habits, normal apps, schedule, workflow
    /// </summary>
    public class AdaptiveAIEngine : IDisposable
    {
        private readonly string _modelPath;
        private UserBehaviorModel _model = new();
        private readonly Dictionary<string, List<UserActivity>> _activityHistory = new();
        private readonly object _lock = new();
        private bool _isLearning;
        private bool _isRunning;
        
        // Learning parameters
        private readonly int _minSamplesForPattern = 50;
        private readonly double _anomalyThreshold = 0.75;
        private readonly TimeSpan _learningWindow = TimeSpan.FromDays(7);

        public event EventHandler<AnomalyDetectedEventArgs>? AnomalyDetected;
        public event EventHandler<PatternLearnedEventArgs>? PatternLearned;
        public event EventHandler<ModelUpdatedEventArgs>? ModelUpdated;

        public AdaptiveAIEngine()
        {
            _modelPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "adaptive_model.json");
            
            LoadModel();
            Logger.Log("Info", "Adaptive AI Engine initialized");
        }

        public void Start()
        {
            _isRunning = true;
            _isLearning = true;
            
            // Start background learning
            Task.Run(() => BackgroundLearningLoop());
            
            Logger.Log("Info", "Adaptive AI Engine started - Learning enabled");
        }

        public void Stop()
        {
            _isRunning = false;
            SaveModel();
            Logger.Log("Info", "Adaptive AI Engine stopped");
        }

        /// <summary>
        /// Records user activity for learning
        /// </summary>
        public void RecordActivity(string activityType, string target, Dictionary<string, object>? metadata = null)
        {
            var activity = new UserActivity
            {
                Id = Guid.NewGuid().ToString(),
                ActivityType = activityType,
                Target = target,
                Timestamp = DateTime.Now,
                HourOfDay = DateTime.Now.Hour,
                DayOfWeek = (int)DateTime.Now.DayOfWeek,
                Metadata = metadata ?? new Dictionary<string, object>()
            };
            
            var key = activityType;
            
            lock (_lock)
            {
                if (!_activityHistory.ContainsKey(key))
                {
                    _activityHistory[key] = new List<UserActivity>();
                }
                
                _activityHistory[key].Add(activity);
                
                // Keep history manageable
                var cutoff = DateTime.Now - _learningWindow;
                _activityHistory[key].RemoveAll(a => a.Timestamp < cutoff);
            }
            
            // Check for anomalies in real-time
            CheckForAnomalies(activity);
        }

        /// <summary>
        /// Records application usage
        /// </summary>
        public void RecordAppUsage(string appName, TimeSpan duration)
        {
            RecordActivity("app_usage", appName, new Dictionary<string, object>
            {
                ["duration"] = duration.TotalMinutes
            });
        }

        /// <summary>
        /// Records file access
        /// </summary>
        public void RecordFileAccess(string filePath, string accessType)
        {
            RecordActivity("file_access", filePath, new Dictionary<string, object>
            {
                ["access_type"] = accessType
            });
        }

        /// <summary>
        /// Records network activity
        /// </summary>
        public void RecordNetworkActivity(string destination, long bytesSent, long bytesReceived)
        {
            RecordActivity("network", destination, new Dictionary<string, object>
            {
                ["bytes_sent"] = bytesSent,
                ["bytes_received"] = bytesReceived
            });
        }

        /// <summary>
        /// Checks if current activity is anomalous
        /// </summary>
        private void CheckForAnomalies(UserActivity activity)
        {
            if (!_isLearning || _activityHistory.Count < _minSamplesForPattern) return;
            
            var anomalyScore = CalculateAnomalyScore(activity);
            
            if (anomalyScore > _anomalyThreshold)
            {
                var anomaly = new UserAnomaly
                {
                    Activity = activity,
                    AnomalyScore = anomalyScore,
                    AnomalyType = DetermineAnomalyType(activity),
                    Description = GenerateAnomalyDescription(activity, anomalyScore),
                    Timestamp = DateTime.Now
                };
                
                AnomalyDetected?.Invoke(this, new AnomalyDetectedEventArgs(anomaly));
                
                Logger.Log("Warning", $"User anomaly detected: {anomaly.Description} (Score: {anomalyScore:P0})");
            }
        }

        /// <summary>
        /// Calculates anomaly score for an activity
        /// </summary>
        private double CalculateAnomalyScore(UserActivity activity)
        {
            var score = 0.0;
            var factors = 0;
            
            // Check time-based anomalies
            var timeScore = CalculateTimeAnomalyScore(activity);
            if (timeScore > 0)
            {
                score += timeScore * 0.3;
                factors++;
            }
            
            // Check activity-based anomalies
            var activityScore = CalculateActivityAnomalyScore(activity);
            if (activityScore > 0)
            {
                score += activityScore * 0.4;
                factors++;
            }
            
            // Check target-based anomalies
            var targetScore = CalculateTargetAnomalyScore(activity);
            if (targetScore > 0)
            {
                score += targetScore * 0.3;
                factors++;
            }
            
            return factors > 0 ? score / factors : 0;
        }

        private double CalculateTimeAnomalyScore(UserActivity activity)
        {
            // Check if activity time is unusual for this user
            var hourKey = $"hour_{activity.HourOfDay}";
            var typicalHours = _model.TypicalScheduleHours;
            
            if (!typicalHours.Contains(activity.HourOfDay))
            {
                // Check how unusual this hour is
                var unusualness = typicalHours.Count > 0 
                    ? 1.0 - ((double)typicalHours.Count / 24)
                    : 0.5;
                return unusualness;
            }
            
            return 0;
        }

        private double CalculateActivityAnomalyScore(UserActivity activity)
        {
            var key = activity.ActivityType;
            
            lock (_lock)
            {
                if (!_activityHistory.TryGetValue(key, out var history) || history.Count < 10)
                    return 0;
                
                // Check frequency anomaly
                var recentCount = history.Count(h => 
                    h.Timestamp > DateTime.Now.AddHours(-1));
                var avgCount = history.Count / 168.0; // Per hour over a week
                
                if (recentCount > avgCount * 3)
                {
                    return Math.Min(1.0, recentCount / (avgCount * 5));
                }
            }
            
            return 0;
        }

        private double CalculateTargetAnomalyScore(UserActivity activity)
        {
            lock (_lock)
            {
                foreach (var kvp in _activityHistory)
                {
                    var matches = kvp.Value.Count(a => a.Target == activity.Target);
                    var total = kvp.Value.Count;
                    
                    if (total > 0 && matches == 0)
                    {
                        // New target - could be suspicious
                        return 0.8;
                    }
                    
                    if (total > 10)
                    {
                        var frequency = (double)matches / total;
                        if (frequency < 0.01) // Very rare
                        {
                            return 0.6;
                        }
                    }
                }
            }
            
            return 0;
        }

        private string DetermineAnomalyType(UserActivity activity)
        {
            return activity.ActivityType switch
            {
                "app_usage" => "Unusual Application",
                "file_access" => "Unusual File Access",
                "network" => "Unusual Network Activity",
                "process" => "Unusual Process",
                _ => "Unknown Anomaly"
            };
        }

        private string GenerateAnomalyDescription(UserActivity activity, double score)
        {
            return $"Unusual {activity.ActivityType} detected: {activity.Target} " +
                   $"(Time: {activity.Timestamp:HH:mm}, Score: {score:P0})";
        }

        /// <summary>
        /// Background learning loop
        /// </summary>
        private async Task BackgroundLearningLoop()
        {
            while (_isRunning)
            {
                try
                {
                    if (_isLearning)
                    {
                        LearnPatterns();
                    }
                    
                    await Task.Delay(TimeSpan.FromMinutes(30));
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Background learning error", ex);
                }
            }
        }

        /// <summary>
        /// Learns patterns from activity history
        /// </summary>
        private void LearnPatterns()
        {
            lock (_lock)
            {
                // Learn typical hours
                var allActivities = _activityHistory.Values.SelectMany(a => a).ToList();
                if (allActivities.Count >= _minSamplesForPattern)
                {
                    var hourGroups = allActivities
                        .GroupBy(a => a.HourOfDay)
                        .Where(g => g.Count() >= allActivities.Count * 0.05)
                        .Select(g => g.Key)
                        .ToList();
                    
                    if (hourGroups.Count > 0)
                    {
                        _model.TypicalScheduleHours = hourGroups;
                    }
                    
                    // Learn typical apps
                    if (_activityHistory.TryGetValue("app_usage", out var appActivities))
                    {
                        _model.TypicalApplications = appActivities
                            .GroupBy(a => a.Target)
                            .OrderByDescending(g => g.Count())
                            .Take(20)
                            .Select(g => g.Key)
                            .ToList();
                    }
                    
                    // Learn typical files
                    if (_activityHistory.TryGetValue("file_access", out var fileActivities))
                    {
                        _model.TypicalFilePaths = fileActivities
                            .GroupBy(a => Path.GetDirectoryName(a.Target))
                            .OrderByDescending(g => g.Count())
                            .Take(10)
                            .Select(g => g.Key ?? "")
                            .Where(p => !string.IsNullOrEmpty(p))
                            .ToList();
                    }
                    
                    // Learn typical network destinations
                    if (_activityHistory.TryGetValue("network", out var netActivities))
                    {
                        _model.TypicalNetworkDestinations = netActivities
                            .GroupBy(a => a.Target)
                            .OrderByDescending(g => g.Count())
                            .Take(10)
                            .Select(g => g.Key)
                            .ToList();
                    }
                    
                    _model.LastTrainingTime = DateTime.Now;
                    _model.SampleCount = allActivities.Count;
                    
                    PatternLearned?.Invoke(this, new PatternLearnedEventArgs(
                        $"Learned {allActivities.Count} samples, {hourGroups.Count} typical hours"));
                    
                    SaveModel();
                }
            }
        }

        /// <summary>
        /// Gets current user model
        /// </summary>
        public UserBehaviorModel GetModel()
        {
            lock (_lock)
            {
                return _model;
            }
        }

        /// <summary>
        /// Gets personalized threat assessment based on user behavior
        /// </summary>
        public PersonalizedRiskAssessment GetPersonalizedRiskAssessment()
        {
            var assessment = new PersonalizedRiskAssessment
            {
                AssessmentTime = DateTime.Now,
                UserModel = _model
            };
            
            lock (_lock)
            {
                var totalActivities = _activityHistory.Values.Sum(a => a.Count);
                assessment.TotalSamples = totalActivities;
                
                // Calculate normalcy score
                if (totalActivities > 0)
                {
                    var currentHour = DateTime.Now.Hour;
                    var isTypicalHour = _model.TypicalScheduleHours.Contains(currentHour);
                    assessment.NormalcyScore = isTypicalHour ? 0.9 : 0.5;
                }
            }
            
            return assessment;
        }

        private void LoadModel()
        {
            try
            {
                if (File.Exists(_modelPath))
                {
                    var json = File.ReadAllText(_modelPath);
                    _model = JsonSerializer.Deserialize<UserBehaviorModel>(json) ?? new UserBehaviorModel();
                    Logger.Log("Info", $"Loaded adaptive model with {_model.SampleCount} samples");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load adaptive model", ex);
                _model = new UserBehaviorModel();
            }
        }

        private void SaveModel()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_modelPath)!);
                var json = JsonSerializer.Serialize(_model, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_modelPath, json);
                
                ModelUpdated?.Invoke(this, new ModelUpdatedEventArgs(DateTime.Now));
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save adaptive model", ex);
            }
        }

        public bool IsLearning => _isLearning;
        public void EnableLearning() => _isLearning = true;
        public void DisableLearning() => _isLearning = false;

        public void Dispose()
        {
            Stop();
        }
    }

    public class UserActivity
    {
        public string Id { get; set; } = "";
        public string ActivityType { get; set; } = "";
        public string Target { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public int HourOfDay { get; set; }
        public int DayOfWeek { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class UserBehaviorModel
    {
        public List<int> TypicalScheduleHours { get; set; } = new();
        public List<string> TypicalApplications { get; set; } = new();
        public List<string> TypicalFilePaths { get; set; } = new();
        public List<string> TypicalNetworkDestinations { get; set; } = new();
        public DateTime LastTrainingTime { get; set; }
        public int SampleCount { get; set; }
    }

    public class UserAnomaly
    {
        public UserActivity Activity { get; set; } = new();
        public double AnomalyScore { get; set; }
        public string AnomalyType { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime Timestamp { get; set; }
    }

    public class PersonalizedRiskAssessment
    {
        public DateTime AssessmentTime { get; set; }
        public UserBehaviorModel UserModel { get; set; } = new();
        public int TotalSamples { get; set; }
        public double NormalcyScore { get; set; }
    }

    public class AnomalyDetectedEventArgs : EventArgs
    {
        public UserAnomaly Anomaly { get; }
        public AnomalyDetectedEventArgs(UserAnomaly anomaly) => Anomaly = anomaly;
    }

    public class PatternLearnedEventArgs : EventArgs
    {
        public string Message { get; }
        public PatternLearnedEventArgs(string message) => Message = message;
    }

    public class ModelUpdatedEventArgs : EventArgs
    {
        public DateTime UpdateTime { get; }
        public ModelUpdatedEventArgs(DateTime updateTime) => UpdateTime = updateTime;
    }
}

