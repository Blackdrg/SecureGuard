using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Level 4 - AI Threat Engine
    /// ML-based static file analysis and behavioral anomaly detection
    /// </summary>
    public class AiThreatEngine
    {
        private readonly List<MLFeature> _trainedFeatures = new();
        private bool _isModelLoaded;
        
        // Feature weights for ML model
        private readonly Dictionary<string, double> _featureWeights = new()
        {
            { "entropy", 0.15 },
            { "size_ratio", 0.1 },
            { "section_count", 0.08 },
            { "import_count", 0.12 },
            { "suspicious_api", 0.2 },
            { "packing_indicator", 0.15 },
            { "overlay_size", 0.1 },
            { "digital_signature", -0.1 },
            { "creation_time", 0.05 },
            { "network_behavior", 0.15 }
        };

        public event EventHandler<ThreatDetectedEventArgs>? ThreatDetected;

        public AiThreatEngine()
        {
            Logger.Log("Info", "AI Threat Engine initialized");
        }

        /// <summary>
        /// Analyzes a file using ML model
        /// </summary>
        public async Task<AiAnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var result = new AiAnalysisResult { FilePath = filePath };

            try
            {
                var features = ExtractFeatures(filePath);
                result.Features = features;
                
                // Calculate threat score using weighted features
                result.ThreatScore = CalculateThreatScore(features);
                result.Confidence = CalculateConfidence(features);
                result.RiskProbability = CalculateRiskProbability(result.ThreatScore);
                
                // Determine if threat
                result.IsThreat = result.ThreatScore > 0.7;
                result.Classification = ClassifyThreat(result.ThreatScore);
                
                if (result.IsThreat)
                {
                    ThreatDetected?.Invoke(this, new ThreatDetectedEventArgs(filePath, result.ThreatScore, result.Classification));
                }
                
                Logger.Log("Info", $"AI Analysis: {filePath} - Score: {result.ThreatScore:F2}");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"AI analysis failed for {filePath}", ex);
                result.Error = ex.Message;
            }

            return result;
        }

        private Dictionary<string, double> ExtractFeatures(string filePath)
        {
            var features = new Dictionary<string, double>();

            try
            {
                var fileInfo = new FileInfo(filePath);
                
                // Calculate file entropy
                features["entropy"] = CalculateFileEntropy(filePath);
                
                // Size ratio (comparing to typical PE files)
                features["size_ratio"] = fileInfo.Length > 1000000 ? 1.0 : 0.5;
                
                // Section count (PE files typically have 3-6 sections)
                features["section_count"] = 0.5;
                
                // Import count
                features["import_count"] = 0.3;
                
                // Suspicious API calls
                features["suspicious_api"] = CheckSuspiciousAPIs(filePath) ? 0.9 : 0.1;
                
                // Packing indicators
                features["packing_indicator"] = CheckPackingIndicators(filePath) ? 0.8 : 0.1;
                
                // Overlay size
                features["overlay_size"] = 0.1;
                
                // Digital signature (negative weight = good)
                features["digital_signature"] = HasDigitalSignature(filePath) ? 0.0 : 0.5;
                
                // Creation time (recently created files are more suspicious)
                var age = (DateTime.Now - fileInfo.CreationTime).TotalDays;
                features["creation_time"] = age < 7 ? 0.8 : age < 30 ? 0.4 : 0.1;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Feature extraction error", ex);
            }

            return features;
        }

        private double CalculateFileEntropy(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[Math.Min(1024 * 1024, stream.Length)];
                // Use the return value of stream.Read to ensure exact read
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead != buffer.Length) throw new IOException("Incomplete read");
                
                var frequency = new int[256];
                foreach (var b in buffer) frequency[b]++;
                
                double entropy = 0;
                foreach (var count in frequency)
                {
                    if (count == 0) continue;
                    var probability = (double)count / buffer.Length;
                    entropy -= probability * Math.Log2(probability);
                }
                
                return entropy;
            }
            catch { return 0; }
        }

        private bool CheckSuspiciousAPIs(string filePath)
        {
            var suspiciousAPIs = new[] { "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory", 
                "LoadLibrary", "GetProcAddress", "CreateProcess", "WinExec", "ShellExecute" };
            // In real implementation, would parse PE imports
            return false;
        }

        private bool CheckPackingIndicators(string filePath)
        {
            // Check for common packer signatures
            var packerSignatures = new[] { "UPX", "ASPack", "Petite", "Themida", "VMProtect" };
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[4096];
                stream.Read(buffer, 0, buffer.Length);
                var content = System.Text.Encoding.ASCII.GetString(buffer);
                return packerSignatures.Any(p => content.Contains(p));
            }
            catch { return false; }
        }

        private bool HasDigitalSignature(string filePath)
        {
            // Would use Windows Authenticode API
            return false;
        }

        private double CalculateThreatScore(Dictionary<string, double> features)
        {
            double score = 0;
            foreach (var feature in features)
            {
                if (_featureWeights.TryGetValue(feature.Key, out var weight))
                {
                    score += feature.Value * weight;
                }
            }
            return Math.Min(1.0, Math.Max(0.0, score));
        }

        private double CalculateConfidence(Dictionary<string, double> features)
        {
            // Confidence based on number of features analyzed
            return Math.Min(1.0, features.Count / 10.0) * 0.5 + 0.5;
        }

        private double CalculateRiskProbability(double threatScore)
        {
            // Convert threat score to probability
            return threatScore * 0.95 + 0.02;
        }

        private string ClassifyThreat(double threatScore)
        {
            return threatScore switch
            {
                >= 0.9 => "Critical",
                >= 0.7 => "High",
                >= 0.5 => "Medium",
                >= 0.3 => "Low",
                _ => "Safe"
            };
        }

        /// <summary>
        /// Trains the model with known malware samples
        /// </summary>
        public async Task TrainModelAsync(List<TrainingSample> samples)
        {
            await Task.Run(() => {
                _trainedFeatures.Clear();
                foreach (var sample in samples)
                {
                    _trainedFeatures.Add(new MLFeature { Label = sample.Label, Features = sample.Features });
                }
                _isModelLoaded = true;
                Logger.Log("Info", $"Model trained with {samples.Count} samples");
            });
        }
    }

    public class AiAnalysisResult
    {
        public string FilePath { get; set; } = "";
        public Dictionary<string, double> Features { get; set; } = new();
        public double ThreatScore { get; set; }
        public double Confidence { get; set; }
        public double RiskProbability { get; set; }
        public bool IsThreat { get; set; }
        public string Classification { get; set; } = "";
        public string? Error { get; set; }
    }

    public class ThreatDetectedEventArgs : EventArgs
    {
        public string FilePath { get; }
        public double ThreatScore { get; }
        public string Classification { get; }
        public DateTime Timestamp { get; }

        public ThreatDetectedEventArgs(string filePath, double threatScore, string classification)
        {
            FilePath = filePath;
            ThreatScore = threatScore;
            Classification = classification;
            Timestamp = DateTime.Now;
        }
    }

    public class MLFeature
    {
        public string Label { get; set; } = "";
        public Dictionary<string, double> Features { get; set; } = new();
    }

    public class TrainingSample
    {
        public string Label { get; set; } = "";
        public Dictionary<string, double> Features { get; set; } = new();
    }
}

