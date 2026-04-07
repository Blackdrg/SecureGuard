using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Cloud;
using SecureGuard.ML;

namespace SecureGuard.Core
{
    /// <summary>
    /// Enhanced Detection Engine - Unified multi-layer malware detection
    /// Combines: Signature, YARA, Binary Patterns, ML, and Cloud Reputation
    /// </summary>
    public class EnhancedDetectionEngine
    {
        private readonly MalwareSignatureDatabase _signatureDb;
        private readonly YaraScanner _yaraScanner;
        private readonly BinaryPatternDatabase _binaryPatternDb;
        private readonly LocalMLEngine _mlEngine;
        private readonly ThreatIntelligenceClient _threatIntel;

        public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

        public int SignatureCount => _signatureDb.Count;
        public int YaraRuleCount => _yaraScanner.RuleCount;
        public int BinaryPatternCount => _binaryPatternDb.SignatureCount;

        public EnhancedDetectionEngine()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard");

            // Initialize all detection engines
            _signatureDb = new MalwareSignatureDatabase(
                Path.Combine(appDataPath, "malware_signatures.json"));
            
            _yaraScanner = new YaraScanner();
            
            _binaryPatternDb = new BinaryPatternDatabase(
                Path.Combine(appDataPath, "binary_patterns.json"));
            
            _mlEngine = new LocalMLEngine();
            
            _threatIntel = new ThreatIntelligenceClient();

            Logger.Log("Info", $"Enhanced Detection Engine initialized: {SignatureCount} signatures, {YaraRuleCount} YARA rules, {BinaryPatternCount} binary patterns");
        }

        /// <summary>
        /// Comprehensive scan of a file using all detection methods
        /// </summary>
        public async Task<EnhancedScanResult> ScanFileAsync(string filePath)
        {
            var result = new EnhancedScanResult
            {
                FilePath = filePath,
                ScanStartTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "File not found";
                    return result;
                }

                // Get file hash
                result.FileHash = Hashing.ComputeSHA256(filePath);
                result.FileSize = new FileInfo(filePath).Length;

                // Layer 1: Signature-based detection
                var signatureResult = await ScanSignatureAsync(filePath);
                result.SignatureResult = signatureResult;
                if (signatureResult.IsThreat)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("Signature");
                    result.ThreatName = signatureResult.ThreatName;
                    result.Confidence += 95;
                }

                // Layer 2: YARA rules
                var yaraResult = await ScanYaraAsync(filePath);
                result.YaraResult = yaraResult;
                if (yaraResult.Matches.Count > 0)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("YARA");
                    if (string.IsNullOrEmpty(result.ThreatName))
                        result.ThreatName = yaraResult.Matches.First().Family;
                    result.Confidence += yaraResult.Matches.First().Severity switch
                    {
                        ThreatSeverity.Critical => 90,
                        ThreatSeverity.High => 75,
                        ThreatSeverity.Medium => 50,
                        ThreatSeverity.Low => 25,
                        _ => 30
                    };
                }

                // Layer 3: Binary pattern analysis
                var binaryResult = await ScanBinaryPatternsAsync(filePath);
                result.BinaryPatternResult = binaryResult;
                if (binaryResult.IsSuspicious)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("Binary");
                    result.Confidence += binaryResult.ThreatScore * 50;
                    if (binaryResult.Analysis != null)
                    {
                        result.Details.AddRange(binaryResult.Analysis.SuspiciousIndicators);
                    }
                }

                // Layer 4: ML-based detection
                var mlResult = await ScanMLAsync(filePath);
                result.MLResult = mlResult;
                if (mlResult.IsThreat)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("ML");
                    result.Confidence += mlResult.Confidence * 40;
                    if (!string.IsNullOrEmpty(result.ThreatName))
                        result.ThreatName += " + ML";
                    else
                        result.ThreatName = mlResult.Classification;
                }

                // Layer 5: Cloud reputation check
                var cloudResult = await CheckCloudReputationAsync(result.FileHash);
                result.CloudResult = cloudResult;
                if (cloudResult.IsMalicious)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("Cloud");
                    result.Confidence += cloudResult.ConfidenceScore;
                    if (!string.IsNullOrEmpty(result.ThreatName))
                        result.ThreatName += " + Cloud";
                }

                // Calculate final confidence
                result.Confidence = Math.Min(100, result.Confidence);
                
                // Determine final threat level
                result.ThreatLevel = result.Confidence switch
                {
                    >= 80 => ThreatSeverity.Critical,
                    >= 60 => ThreatSeverity.High,
                    >= 40 => ThreatSeverity.Medium,
                    >= 20 => ThreatSeverity.Low,
                    _ => ThreatSeverity.Low
                };

                // Fire event if threat detected
                if (result.ThreatDetected)
                {
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(
                        filePath, result.ThreatName ?? "Unknown", result.ThreatLevel, result.Confidence));
                }

                result.ScanEndTime = DateTime.Now;
                Logger.Log("Info", $"Enhanced scan complete: {filePath} - Threat: {result.ThreatDetected}, Confidence: {result.Confidence:F1}%");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Enhanced scan failed for {filePath}", ex);
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Quick scan - signature + YARA only (faster)
        /// </summary>
        public async Task<EnhancedScanResult> QuickScanAsync(string filePath)
        {
            var result = new EnhancedScanResult
            {
                FilePath = filePath,
                ScanStartTime = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "File not found";
                    return result;
                }

                result.FileHash = Hashing.ComputeSHA256(filePath);

                // Quick signature check
                var signatureResult = await ScanSignatureAsync(filePath);
                result.SignatureResult = signatureResult;
                if (signatureResult.IsThreat)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("Signature");
                    result.ThreatName = signatureResult.ThreatName;
                    result.Confidence += 95;
                }

                // Quick YARA check
                var yaraResult = await ScanYaraAsync(filePath);
                result.YaraResult = yaraResult;
                if (yaraResult.Matches.Count > 0)
                {
                    result.ThreatDetected = true;
                    result.DetectionLayers.Add("YARA");
                    result.Confidence += 50;
                }

                result.Confidence = Math.Min(100, result.Confidence);
                result.ThreatLevel = result.Confidence >= 50 ? ThreatSeverity.High : ThreatSeverity.None;
                result.ScanEndTime = DateTime.Now;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Deep scan - all methods (slower but more thorough)
        /// </summary>
        public async Task<EnhancedScanResult> DeepScanAsync(string filePath)
        {
            return await ScanFileAsync(filePath);
        }

        #region Individual Scan Methods

        private async Task<SignatureScanResult> ScanSignatureAsync(string filePath)
        {
            return await Task.Run(() =>
            {
                var result = new SignatureScanResult();
                
                try
                {
                    var hash = Hashing.ComputeSHA256(filePath);
                    result.Hash = hash;
                    result.IsThreat = _signatureDb.IsThreat(hash);
                    
                    if (result.IsThreat)
                    {
                        var sig = _signatureDb.GetSignature(hash);
                        if (sig != null)
                        {
                            result.ThreatName = sig.Name;
                            result.ThreatFamily = sig.Family;
                            result.Severity = sig.Severity;
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Error = ex.Message;
                }

                return result;
            });
        }

        private async Task<YaraScanResult> ScanYaraAsync(string filePath)
        {
            var result = new YaraScanResult();
            
            try
            {
                var matches = await _yaraScanner.ScanFileAsync(filePath);
                result.Matches = matches;
                result.ThreatCount = matches.Count;
                
                if (matches.Count > 0)
                {
                    // Get the highest severity
                    result.HighestSeverity = matches.Max(m => m.Severity);
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task<BinaryScanResult> ScanBinaryPatternsAsync(string filePath)
        {
            var result = new BinaryScanResult();
            
            try
            {
                var analysis = await _binaryPatternDb.AnalyzeFileAsync(filePath);
                result.Analysis = analysis;
                result.IsSuspicious = analysis.IsSuspicious;
                result.ThreatScore = analysis.OverallScore;
                result.MatchedPatterns = analysis.MatchedPatterns.Select(p => p.Name).ToList();
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task<MLScanResult> ScanMLAsync(string filePath)
        {
            var result = new MLScanResult();
            
            try
            {
                var mlResult = await _mlEngine.AnalyzeFileAsync(filePath);
                result.Analysis = mlResult;
                result.IsThreat = mlResult.IsThreat;
                result.ThreatScore = mlResult.ThreatScore;
                result.Confidence = mlResult.Confidence;
                result.Classification = mlResult.Classification;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task<CloudScanResult> CheckCloudReputationAsync(string hash)
        {
            var result = new CloudScanResult();
            
            try
            {
                var cloudResult = await _threatIntel.CheckFileHashAsync(hash);
                result.IsMalicious = cloudResult.IsMalicious;
                result.DetectionCount = cloudResult.DetectionCount;
                result.TotalEngines = cloudResult.TotalEngines;
                result.ConfidenceScore = cloudResult.ConfidenceScore;
                result.ThreatNames = cloudResult.ThreatNames;
                result.Sources = cloudResult.Sources;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        #endregion

        /// <summary>
        /// Get detection statistics
        /// </summary>
        public DetectionStatistics GetStatistics()
        {
            return new DetectionStatistics
            {
                SignatureCount = SignatureCount,
                YaraRuleCount = YaraRuleCount,
                BinaryPatternCount = BinaryPatternCount,
                YaraFamilies = _yaraScanner.GetAllFamilies(),
                YaraStats = _yaraScanner.GetStatistics()
            };
        }

        /// <summary>
        /// Scan a directory recursively
        /// </summary>
        public async Task<List<EnhancedScanResult>> ScanDirectoryAsync(string directoryPath, bool recursive = true)
        {
            var results = new List<EnhancedScanResult>();

            if (!Directory.Exists(directoryPath))
            {
                Logger.Log("Warning", $"Directory not found: {directoryPath}");
                return results;
            }

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, "*.*", searchOption)
                .Where(f => !IsExcludedForScan(f))
                .Take(10000);

            foreach (var file in files)
            {
                try
                {
                    var result = await QuickScanAsync(file);
                    if (result.ThreatDetected)
                    {
                        results.Add(result);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Failed to scan {file}", ex);
                }
            }

            return results;
        }

        private bool IsExcludedForScan(string path)
        {
            var exclusions = new[] { ".tmp", ".log", ".bak", ".cache", "thumbs.db", ".ds_store" };
            var lower = path.ToLower();
            return exclusions.Any(e => lower.EndsWith(e));
        }
    }

    #region Result Classes

    public class EnhancedScanResult
    {
        public string FilePath { get; set; } = "";
        public string FileHash { get; set; } = "";
        public long FileSize { get; set; }
        public bool ThreatDetected { get; set; }
        public ThreatSeverity ThreatLevel { get; set; }
        public double Confidence { get; set; }
        public string? ThreatName { get; set; }
        public List<string> DetectionLayers { get; set; } = new();
        public List<string> Details { get; set; } = new();
        public DateTime ScanStartTime { get; set; }
        public DateTime ScanEndTime { get; set; }
        public string? Error { get; set; }

        // Individual layer results
        public SignatureScanResult? SignatureResult { get; set; }
        public YaraScanResult? YaraResult { get; set; }
        public BinaryScanResult? BinaryPatternResult { get; set; }
        public MLScanResult? MLResult { get; set; }
        public CloudScanResult? CloudResult { get; set; }

        public TimeSpan ScanDuration => ScanEndTime - ScanStartTime;
    }

    public class SignatureScanResult
    {
        public string Hash { get; set; } = "";
        public bool IsThreat { get; set; }
        public string? ThreatName { get; set; }
        public string? ThreatFamily { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string? Error { get; set; }
    }

    public class YaraScanResult
    {
        public List<YaraMatch> Matches { get; set; } = new();
        public int ThreatCount { get; set; }
        public ThreatSeverity HighestSeverity { get; set; }
        public string? Error { get; set; }
    }

    public class BinaryScanResult
    {
        public bool IsSuspicious { get; set; }
        public double ThreatScore { get; set; }
        public List<string> MatchedPatterns { get; set; } = new();
        public BinaryAnalysisResult? Analysis { get; set; }
        public string? Error { get; set; }
    }

    public class MLScanResult
    {
        public bool IsThreat { get; set; }
        public double ThreatScore { get; set; }
        public double Confidence { get; set; }
        public string Classification { get; set; } = "";
        public MLAnalysisResult? Analysis { get; set; }
        public string? Error { get; set; }
    }

    public class CloudScanResult
    {
        public bool IsMalicious { get; set; }
        public int DetectionCount { get; set; }
        public int TotalEngines { get; set; }
        public int ConfidenceScore { get; set; }
        public List<string> ThreatNames { get; set; } = new();
        public List<string> Sources { get; set; } = new();
        public string? Error { get; set; }
    }

    public class DetectionStatistics
    {
        public int SignatureCount { get; set; }
        public int YaraRuleCount { get; set; }
        public int BinaryPatternCount { get; set; }
        public List<string> YaraFamilies { get; set; } = new();
        public Dictionary<string, int> YaraStats { get; set; } = new();
    }

    #endregion

    #region Events

    public class ThreatDetectedEventArgs : EventArgs
    {
        public string FilePath { get; }
        public string ThreatName { get; }
        public ThreatSeverity Severity { get; }
        public double Confidence { get; }

        public ThreatDetectedEventArgs(string filePath, string threatName, ThreatSeverity severity, double confidence)
        {
            FilePath = filePath;
            ThreatName = threatName;
            Severity = severity;
            Confidence = confidence;
        }
    }

    #endregion
}

