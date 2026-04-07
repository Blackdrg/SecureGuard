using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 3: Time-Shift Attack Detection
    /// Detects delayed malware activation (sleeper malware, logic bombs, delayed ransomware)
    /// Monitors programs over long timelines and detects activation patterns
    /// </summary>
    public class TimeShiftDetectionEngine : IDisposable
    {
        private readonly Dictionary<string, ProgramTimeline> _programTimelines = new();
        private readonly Dictionary<string, DelayedActivationPattern> _knownPatterns = new();
        private readonly object _lock = new();
        private bool _isRunning;
        private CancellationTokenSource? _cts;
        
        // Configuration
        private readonly TimeSpan _analysisWindow = TimeSpan.FromDays(7); // Monitor for 7 days
        private readonly TimeSpan _minDelay = TimeSpan.FromMinutes(30);   // Minimum delay to consider
        private readonly TimeSpan _maxDelay = TimeSpan.FromDays(30);      // Maximum delay to track
        private readonly int _activationThreshold = 3;                     // Activations before alert
        
        public event EventHandler<DelayedAttackDetectedEventArgs>? DelayedAttackDetected;
        public event EventHandler<ActivationPatternEventArgs>? ActivationPatternDetected;

        public TimeShiftDetectionEngine()
        {
            InitializeKnownPatterns();
            Logger.Log("Info", "Time-Shift Attack Detection Engine initialized");
        }

        private void InitializeKnownPatterns()
        {
            // Known delayed attack patterns
            _knownPatterns["scheduled_execution"] = new DelayedActivationPattern
            {
                Name = "Scheduled Execution",
                Indicators = new[] { "scheduled_task", "at_job", "timer", "wait" },
                TimeDistribution = ActivationTimeDistribution.HumanHours,
                TypicalDelay = TimeSpan.FromHours(1),
                Severity = ThreatSeverity.High
            };
            
            _knownPatterns["time_bomb"] = new DelayedActivationPattern
            {
                Name = "Time Bomb",
                Indicators = new[] { "date_check", "time_check", "get_systemtime", "nt_query" },
                TimeDistribution = ActivationTimeDistribution.SpecificTime,
                TypicalDelay = TimeSpan.FromDays(1),
                Severity = ThreatSeverity.Critical
            };
            
            _knownPatterns["logic_bomb"] = new DelayedActivationPattern
            {
                Name = "Logic Bomb",
                Indicators = new[] { "counter", "trigger", "condition", "event_log" },
                TimeDistribution = ActivationTimeDistribution.EventBased,
                TypicalDelay = TimeSpan.FromMinutes(30),
                Severity = ThreatSeverity.Critical
            };
            
            _knownPatterns["sleeper"] = new DelayedActivationPattern
            {
                Name = "Sleeper Malware",
                Indicators = new[] { "sleep", "wait", "delay", "timeout" },
                TimeDistribution = ActivationTimeDistribution.Random,
                TypicalDelay = TimeSpan.FromHours(2),
                Severity = ThreatSeverity.High
            };
            
            _knownPatterns["cron_job"] = new DelayedActivationPattern
            {
                Name = "Scheduled Cron Job",
                Indicators = new[] { "cron", "schedule", "recurring", "periodic" },
                TimeDistribution = ActivationTimeDistribution.Regular,
                TypicalDelay = TimeSpan.FromDays(1),
                Severity = ThreatSeverity.Medium
            };
            
            Logger.Log("Info", $"Loaded {_knownPatterns.Count} delayed attack patterns");
        }

        public void Start()
        {
            if (_isRunning) return;
            
            _cts = new CancellationTokenSource();
            _isRunning = true;
            
            // Start background analysis task
            Task.Run(() => BackgroundAnalysisLoop(_cts.Token));
            
            Logger.Log("Info", "Time-Shift Attack Detection started");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
            
            Logger.Log("Info", "Time-Shift Attack Detection stopped");
        }

        /// <summary>
        /// Records an event for a program
        /// </summary>
        public void RecordEvent(string programPath, ProgramEvent evt)
        {
            var key = GetProgramKey(programPath);
            
            lock (_lock)
            {
                if (!_programTimelines.ContainsKey(key))
                {
                    _programTimelines[key] = new ProgramTimeline
                    {
                        ProgramPath = programPath,
                        ProgramName = Path.GetFileName(programPath)
                    };
                }
                
                _programTimelines[key].Events.Add(evt);
                _programTimelines[key].LastEventTime = evt.Timestamp;
                
                // Clean old events outside analysis window
                var cutoff = DateTime.Now - _analysisWindow;
                _programTimelines[key].Events.RemoveAll(e => e.Timestamp < cutoff);
            }
        }

        /// <summary>
        /// Analyzes a program for delayed activation patterns
        /// </summary>
        public async Task<DelayedAttackAnalysis> AnalyzeForDelayedAttacksAsync(string programPath)
        {
            var result = new DelayedAttackAnalysis
            {
                ProgramPath = programPath,
                AnalysisTime = DateTime.Now
            };

            await Task.Run(() =>
            {
                var key = GetProgramKey(programPath);
                
                lock (_lock)
                {
                    if (!_programTimelines.TryGetValue(key, out var timeline) || timeline.Events.Count < 2)
                    {
                        result.IsAnalyzed = false;
                        return;
                    }
                    
                    result.EventCount = timeline.Events.Count;
                    result.TimeSpan = timeline.Events.Last().Timestamp - timeline.Events.First().Timestamp;
                    result.Events = timeline.Events.OrderBy(e => e.Timestamp).ToList();
                    
                    // Analyze activation patterns
                    result.Patterns = DetectActivationPatterns(timeline);
                    
                    // Check for specific attack types
                    foreach (var pattern in _knownPatterns.Values)
                    {
                        if (MatchesPattern(timeline, pattern))
                        {
                            result.MatchedPatterns.Add(pattern.Name);
                            result.Severity = (ThreatSeverity)Math.Max((int)result.Severity, (int)pattern.Severity);
                            result.Confidence += 0.3;
                        }
                    }
                    
                    // Check for timing anomalies
                    result.TimingAnomalies = DetectTimingAnomalies(timeline);
                    
                    // Determine if this is likely a delayed attack
                    result.IsDelayedAttack = result.MatchedPatterns.Count > 0 || 
                                           result.TimingAnomalies.Count > 0;
                    
                    result.IsAnalyzed = true;
                    result.Confidence = Math.Min(1.0, result.Confidence);
                }
            });

            if (result.IsDelayedAttack)
            {
                DelayedAttackDetected?.Invoke(this, new DelayedAttackDetectedEventArgs(
                    programPath, result.Severity, result.MatchedPatterns, result.Confidence));
            }

            return result;
        }

        private List<string> DetectActivationPatterns(ProgramTimeline timeline)
        {
            var patterns = new List<string>();
            var events = timeline.Events.OrderBy(e => e.Timestamp).ToList();
            
            if (events.Count < 2) return patterns;
            
            // Check for regular intervals
            var intervals = new List<TimeSpan>();
            for (int i = 1; i < events.Count; i++)
            {
                intervals.Add(events[i].Timestamp - events[i-1].Timestamp);
            }
            
            var avgInterval = TimeSpan.FromTicks((long)intervals.Average(i => i.Ticks));
            var variance = intervals.Sum(i => Math.Pow((i - avgInterval).TotalSeconds, 2)) / intervals.Count;
            var stdDev = Math.Sqrt(variance);
            
            // Regular pattern (low variance)
            if (stdDev < avgInterval.TotalSeconds * 0.1 && intervals.Count > 2)
            {
                patterns.Add("Regular Execution Pattern");
            }
            
            // Check for long delays
            var longDelays = intervals.Count(i => i > _minDelay);
            if (longDelays > 0)
            {
                patterns.Add($"Long Delay Detected ({longDelays} instances)");
            }
            
            // Check for specific times (human working hours)
            var humanHourEvents = events.Count(e => e.Timestamp.Hour >= 9 && e.Timestamp.Hour <= 17);
            if (humanHourEvents > events.Count * 0.7)
            {
                patterns.Add("Human-Hours Activation Pattern");
            }
            
            // Check for event-triggered (spikes after system events)
            var eventSpikes = DetectEventCorrelations(events);
            if (eventSpikes > 0)
            {
                patterns.Add($"Event-Triggered Activation ({eventSpikes} correlations)");
            }
            
            return patterns;
        }

        private int DetectEventCorrelations(List<ProgramEvent> events)
        {
            // Check if events correlate with system events
            var correlations = 0;
            
            // After boot
            var bootTimes = GetKnownBootTimes();
            foreach (var bootTime in bootTimes)
            {
                var eventsAfterBoot = events.Count(e => e.Timestamp > bootTime && 
                    e.Timestamp < bootTime.Add(TimeSpan.FromMinutes(5)));
                if (eventsAfterBoot > 0) correlations++;
            }
            
            // After user login
            var loginTimes = GetKnownLoginTimes();
            foreach (var loginTime in loginTimes)
            {
                var eventsAfterLogin = events.Count(e => e.Timestamp > loginTime &&
                    e.Timestamp < loginTime.Add(TimeSpan.FromMinutes(10)));
                if (eventsAfterLogin > 0) correlations++;
            }
            
            return correlations;
        }

        private List<string> DetectTimingAnomalies(ProgramTimeline timeline)
        {
            var anomalies = new List<string>();
            var events = timeline.Events.OrderBy(e => e.Timestamp).ToList();
            
            if (events.Count < 2) return anomalies;
            
            // First event delay (initial delay before any activity)
            var firstEventDelay = events[0].Timestamp - timeline.FirstSeenTime;
            if (firstEventDelay > TimeSpan.FromHours(1))
            {
                anomalies.Add($"Large initial delay: {firstEventDelay.TotalHours:F1} hours");
            }
            
            // Sudden burst of activity
            for (int i = 1; i < events.Count; i++)
            {
                var gap = events[i].Timestamp - events[i-1].Timestamp;
                if (gap > TimeSpan.FromHours(6))
                {
                    anomalies.Add($"Long gap before: {events[i].EventType}");
                }
            }
            
            // Check for exponential backoff patterns
            var intervals = new List<TimeSpan>();
            for (int i = 1; i < events.Count; i++)
            {
                intervals.Add(events[i].Timestamp - events[i-1].Timestamp);
            }
            
            bool increasing = true;
            for (int i = 1; i < intervals.Count; i++)
            {
                if (intervals[i] <= intervals[i-1])
                {
                    increasing = false;
                    break;
                }
            }
            
            if (increasing && intervals.Count > 2)
            {
                anomalies.Add("Exponential delay pattern (increasing delays)");
            }
            
            return anomalies;
        }

        private bool MatchesPattern(ProgramTimeline timeline, DelayedActivationPattern pattern)
        {
            var events = timeline.Events.Select(e => e.EventType.ToLower()).ToList();
            
            foreach (var indicator in pattern.Indicators)
            {
                if (events.Any(e => e.Contains(indicator.ToLower())))
                {
                    return true;
                }
            }
            
            return false;
        }

        private async Task BackgroundAnalysisLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _isRunning)
            {
                try
                {
                    // Analyze programs with enough events
                    var programsToAnalyze = new List<string>();
                    
                    lock (_lock)
                    {
                        programsToAnalyze = _programTimelines
                            .Where(kvp => kvp.Value.Events.Count >= 3)
                            .Select(kvp => kvp.Key)
                            .ToList();
                    }
                    
                    foreach (var program in programsToAnalyze)
                    {
                        if (token.IsCancellationRequested) break;
                        
                        try
                        {
                            await AnalyzeForDelayedAttacksAsync(program);
                        }
                        catch { }
                    }
                    
                    await Task.Delay(TimeSpan.FromMinutes(30), token);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Log("Error", "Background analysis error", ex);
                }
            }
        }

        private List<DateTime> GetKnownBootTimes()
        {
            // Would query system event log
            return new List<DateTime>();
        }

        private List<DateTime> GetKnownLoginTimes()
        {
            // Would query security event log
            return new List<DateTime>();
        }

        private string GetProgramKey(string programPath)
        {
            return programPath.ToLower();
        }

        public ProgramTimeline? GetTimeline(string programPath)
        {
            lock (_lock)
            {
                var key = GetProgramKey(programPath);
                return _programTimelines.TryGetValue(key, out var timeline) ? timeline : null;
            }
        }

        public Dictionary<string, ProgramTimeline> GetAllTimelines()
        {
            lock (_lock)
            {
                return new Dictionary<string, ProgramTimeline>(_programTimelines);
            }
        }

        public void Dispose()
        {
            Stop();
        }
    }

    public class ProgramEvent
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; } = "";
        public string Details { get; set; } = "";
        public string Source { get; set; } = "";
    }

    public class ProgramTimeline
    {
        public string ProgramPath { get; set; } = "";
        public string ProgramName { get; set; } = "";
        public DateTime FirstSeenTime { get; set; } = DateTime.Now;
        public DateTime LastEventTime { get; set; }
        public List<ProgramEvent> Events { get; set; } = new();
    }

    public class DelayedActivationPattern
    {
        public string Name { get; set; } = "";
        public string[] Indicators { get; set; } = Array.Empty<string>();
        public ActivationTimeDistribution TimeDistribution { get; set; }
        public TimeSpan TypicalDelay { get; set; }
        public ThreatSeverity Severity { get; set; }
    }

    public enum ActivationTimeDistribution
    {
        Random,
        Regular,
        HumanHours,
        SpecificTime,
        EventBased
    }

    public class DelayedAttackAnalysis
    {
        public string ProgramPath { get; set; } = "";
        public bool IsAnalyzed { get; set; }
        public bool IsDelayedAttack { get; set; }
        public int EventCount { get; set; }
        public TimeSpan TimeSpan { get; set; }
        public List<ProgramEvent> Events { get; set; } = new();
        public List<string> Patterns { get; set; } = new();
        public List<string> MatchedPatterns { get; set; } = new();
        public List<string> TimingAnomalies { get; set; } = new();
        public ThreatSeverity Severity { get; set; }
        public double Confidence { get; set; }
        public DateTime AnalysisTime { get; set; }
    }

    public class DelayedAttackDetectedEventArgs : EventArgs
    {
        public string ProgramPath { get; }
        public ThreatSeverity Severity { get; }
        public List<string> Patterns { get; }
        public double Confidence { get; }
        public DateTime Timestamp { get; }

        public DelayedAttackDetectedEventArgs(string programPath, ThreatSeverity severity, 
            List<string> patterns, double confidence)
        {
            ProgramPath = programPath;
            Severity = severity;
            Patterns = patterns;
            Confidence = confidence;
            Timestamp = DateTime.Now;
        }
    }

    public class ActivationPatternEventArgs : EventArgs
    {
        public string ProgramPath { get; }
        public string Pattern { get; }
        public DateTime Timestamp { get; }

        public ActivationPatternEventArgs(string programPath, string pattern)
        {
            ProgramPath = programPath;
            Pattern = pattern;
            Timestamp = DateTime.Now;
        }
    }
}

