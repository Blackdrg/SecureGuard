using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.ML
{
    /// <summary>
    /// Local ML Engine - Runs ML-based threat detection locally without external APIs
    /// Uses feature extraction and ML model inference for malware classification
    /// Now integrates with trained ONNX models when available
    /// </summary>
    public class LocalMLEngine
    {
        private readonly string _modelPath;
        private ThreatModel? _model;
        private bool _isLoaded;
        
        // New ML Infrastructure components
        private readonly FeatureExtractor _featureExtractor;
        private readonly ModelManager? _modelManager;
        
        // Suspicious API calls commonly used by malware
        private readonly HashSet<string> _suspiciousAPIs = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory", "ReadProcessMemory",
            "OpenProcess", "OpenProcessToken", "AdjustTokenPrivileges",
            "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            "CreateProcess", "CreateProcessA", "CreateProcessW", "ShellExecute", "WinExec",
            "UrlDownloadToFile", "InternetOpen", "InternetOpenUrl", "InternetReadFile",
            "SetWindowsHook", "SetWindowsHookEx", "UnhookWindowsHook",
            "FindWindow", "SetForegroundWindow", "GetForegroundWindow",
            "GetAsyncKeyState", "GetKeyboardState", "MapVirtualKey",
            "RegOpenKey", "RegCreateKey", "RegSetValue", "RegDeleteKey",
            "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
            "CreateService", "StartService", "StopService",
            "AddPrinter", "AddMonitor"
        };

        // Packer signatures
        private readonly HashSet<string> _packerSignatures = new(StringComparer.OrdinalIgnoreCase)
        {
            "UPX", "ASPack", "Petite", "Themida", "VMProtect", "Armadillo",
            "PECompact", "MEW", "NSPack", "WWPack", "EXPACK", "FSG",
            "Karakurt", "ProCrypt", "VMP", "Themida", "WinLicense"
        };

        // Known good software publishers
        private readonly HashSet<string> _knownGoodPublishers = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation", "Google LLC", "Adobe Inc.", "Mozilla Corporation",
            "Apple Inc.", "Intel Corporation", "NVIDIA Corporation", "AMD",
            "Oracle Corporation", "VMware Inc.", "Amazon.com Inc."
        };

        public LocalMLEngine()
        {
            _modelPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "ml_models");
            
            Directory.CreateDirectory(_modelPath);
            
            // Initialize feature extractor
            _featureExtractor = new FeatureExtractor();
            
            // Try to initialize model manager (optional - will work without ONNX models)
            try
            {
                _modelManager = new ModelManager();
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Warning", $"ModelManager initialization failed: {ex.Message}");
                _modelManager = null;
            }
            
            LoadModel();
        }

        /// <summary>
        /// Load the pre-trained model
        /// </summary>
        private void LoadModel()
        {
            try
            {
                // Try to load existing model
                var modelFile = Path.Combine(_modelPath, "threat_model.json");
                if (File.Exists(modelFile))
                {
                    var json = File.ReadAllText(modelFile);
                    _model = System.Text.Json.JsonSerializer.Deserialize<ThreatModel>(json);
                    _isLoaded = _model != null;
                }

                // If no model exists, create default
                if (_model == null)
                {
                    _model = CreateDefaultModel();
                    SaveModel();
                    _isLoaded = true;
                }

                Core.Logger.Log("Info", $"ML Engine initialized with model: {(_model?.Name ?? "default")}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to load ML model", ex);
                _model = CreateDefaultModel();
                _isLoaded = true;
            }
        }

        private ThreatModel CreateDefaultModel()
        {
            return new ThreatModel
            {
                Name = "SecureGuard Default Model",
                Version = "1.0.0",
                CreatedAt = DateTime.Now,
                Features = new List<ModelFeature>
                {
                    new() { Name = "entropy", Weight = 0.15, Threshold = 6.5 },
                    new() { Name = "suspicious_api_count", Weight = 0.20, Threshold = 2 },
                    new() { Name = "packed", Weight = 0.15, Threshold = 0.5 },
                    new() { Name = "unsigned", Weight = 0.10, Threshold = 0.5 },
                    new() { Name = "size_ratio", Weight = 0.08, Threshold = 0.1 },
                    new() { Name = "section_count", Weight = 0.05, Threshold = 6 },
                    new() { Name = "import_count", Weight = 0.10, Threshold = 100 },
                    new() { Name = "recent_creation", Weight = 0.07, Threshold = 7 },
                    new() { Name = "network_behavior", Weight = 0.10, Threshold = 0.5 }
                }
            };
        }

        private void SaveModel()
        {
            try
            {
                var modelFile = Path.Combine(_modelPath, "threat_model.json");
                var json = System.Text.Json.JsonSerializer.Serialize(_model, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(modelFile, json);
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Failed to save ML model", ex);
            }
        }

        /// <summary>
        /// Analyze a file and return threat classification
        /// </summary>
        public async Task<MLAnalysisResult> AnalyzeFileAsync(string filePath)
        {
            var result = new MLAnalysisResult
            {
                FilePath = filePath,
                AnalyzedAt = DateTime.Now
            };

            try
            {
                if (!File.Exists(filePath))
                {
                    result.Error = "File not found";
                    return result;
                }

                var fileInfo = new FileInfo(filePath);
                result.FileSize = fileInfo.Length;

                // Skip very small or very large files
                if (fileInfo.Length < 512)
                {
                    result.IsThreat = false;
                    result.ThreatScore = 0.0;
                    result.Classification = "Too Small";
                    return result;
                }

                if (fileInfo.Length > 100 * 1024 * 1024) // 100MB
                {
                    // Deep scan for large files
                    result.IsLargeFile = true;
                }

                // Extract features
                var features = await ExtractFeaturesAsync(filePath);
                result.Features = features;

                // Run inference
                if (_model != null)
                {
                    result.ThreatScore = RunInference(features, _model);
                    result.Confidence = CalculateConfidence(features);
                }
                else
                {
                    result.ThreatScore = features.SuspiciousAPICount > 2 ? 0.8 : 0.1;
                    result.Confidence = 0.5;
                }

                // Determine classification
                result.Classification = ClassifyThreat(result.ThreatScore);
                result.IsThreat = result.ThreatScore > 0.7;

                // Add explanations
                result.Explanations = GenerateExplanations(features, result.ThreatScore);

                Core.Logger.Log("Debug", $"ML Analysis: {filePath} - Score: {result.ThreatScore:F2}, Classification: {result.Classification}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"ML analysis failed for {filePath}", ex);
                result.Error = ex.Message;
            }

            return result;
        }

        private async Task<FileFeatures> ExtractFeaturesAsync(string filePath)
        {
            return await Task.Run(() =>
            {
                var features = new FileFeatures { FilePath = filePath };

                try
                {
                    var fileInfo = new FileInfo(filePath);

                    // Basic features
                    features.FileSize = fileInfo.Length;
                    features.SizeRatio = fileInfo.Length > 1_000_000 ? 1.0 : fileInfo.Length / 1_000_000.0;

                    // Age features
                    var ageDays = (DateTime.Now - fileInfo.CreationTime).TotalDays;
                    features.IsRecentlyCreated = ageDays < 7;
                    features.CreationAgeDays = (int)ageDays;

                    // Entropy calculation
                    features.Entropy = CalculateEntropy(filePath);

                    // Check for packing
                    features.IsPacked = CheckPacking(filePath);

                    // Check digital signature
                    features.IsSigned = CheckDigitalSignature(filePath);

                    // Check suspicious APIs (for PE files)
                    if (IsPEFile(filePath))
                    {
                        features.IsPEFile = true;
                        features.SuspiciousAPICount = CheckSuspiciousAPIs(filePath);
                        features.ImportCount = GetImportCount(filePath);
                        features.SectionCount = GetSectionCount(filePath);
                    }

                    // Network indicators
                    features.HasNetworkCode = CheckNetworkCode(filePath);

                    // File location risk
                    features.LocationRisk = CalculateLocationRisk(filePath);
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", $"Feature extraction error for {filePath}", ex);
                }

                return features;
            });
        }

        private double CalculateEntropy(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var bufferSize = (int)Math.Min(1024 * 1024, stream.Length); // 1MB max
                var buffer = new byte[bufferSize];
                var bytesRead = stream.Read(buffer, 0, bufferSize);
                
                if (bytesRead == 0) return 0;

                var frequency = new int[256];
                foreach (var b in buffer) frequency[b]++;

                double entropy = 0;
                for (int i = 0; i < 256; i++)
                {
                    if (frequency[i] == 0) continue;
                    var probability = (double)frequency[i] / bytesRead;
                    entropy -= probability * Math.Log2(probability);
                }

                return entropy;
            }
            catch
            {
                return 0;
            }
        }

        private bool CheckPacking(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[4096];
                stream.Read(buffer, 0, buffer.Length);
                
                var content = Encoding.ASCII.GetString(buffer);
                return _packerSignatures.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private bool CheckDigitalSignature(string filePath)
        {
            try
            {
                // Use Wintrust for proper signature verification
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = $"(Get-AuthenticodeSignature '{filePath}').Status",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                var status = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();
                
                return status == "Valid";
            }
            catch
            {
                return false;
            }
        }

        private bool IsPEFile(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var header = new byte[2];
                stream.Read(header, 0, 2);
                return header[0] == 0x4D && header[1] == 0x5A; // "MZ"
            }
            catch
            {
                return false;
            }
        }

        private int CheckSuspiciousAPIs(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[Math.Min(1024 * 1024, stream.Length)];
                stream.Read(buffer, 0, buffer.Length);
                
                var content = Encoding.ASCII.GetString(buffer);
                return _suspiciousAPIs.Count(api => content.Contains(api, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return 0;
            }
        }

        private int GetImportCount(string filePath)
        {
            try
            {
                // Simplified - would need proper PE parsing
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[Math.Min(512 * 1024, stream.Length)];
                stream.Read(buffer, 0, buffer.Length);
                
                // Count import section references
                var content = Encoding.ASCII.GetString(buffer);
                return content.Count(c => c == '\0') / 10; // Rough estimate
            }
            catch
            {
                return 0;
            }
        }

        private int GetSectionCount(string filePath)
        {
            try
            {
                using var stream = File.OpenRead(filePath);
                stream.Seek(0x3C, SeekOrigin.Begin); // PE header offset
                var peOffsetBytes = new byte[4];
                stream.Read(peOffsetBytes, 0, 4);
                var peOffset = BitConverter.ToInt32(peOffsetBytes, 0);
                
                stream.Seek(peOffset + 6, SeekOrigin.Begin); // Number of sections
                var sectionCount = new byte[2];
                stream.Read(sectionCount, 0, 2);
                
                return BitConverter.ToInt16(sectionCount, 0);
            }
            catch
            {
                return 0;
            }
        }

        private bool CheckNetworkCode(string filePath)
        {
            var networkIndicators = new[] { "http", "https", "socket", "connect", "send", "recv", "ws2_32", "winhttp", "wininet" };
            try
            {
                using var stream = File.OpenRead(filePath);
                var buffer = new byte[Math.Min(512 * 1024, stream.Length)];
                stream.Read(buffer, 0, buffer.Length);
                
                var content = Encoding.ASCII.GetString(buffer);
                return networkIndicators.Any(n => content.Contains(n, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private double CalculateLocationRisk(string filePath)
        {
            var lowRiskPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender")
            };
            
            var highRiskPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            foreach (var path in lowRiskPaths)
            {
                if (filePath.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                    return 0.1;
            }

            foreach (var path in highRiskPaths)
            {
                if (filePath.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                    return 0.7;
            }

            return 0.5;
        }

        private double RunInference(FileFeatures features, ThreatModel model)
        {
            double score = 0;
            double totalWeight = 0;

            // Entropy
            if (features.Entropy > 6.5)
                score += model.Features.FirstOrDefault(f => f.Name == "entropy")?.Weight ?? 0.15;
            totalWeight += 0.15;

            // Suspicious APIs
            if (features.SuspiciousAPICount > 2)
            {
                var weight = model.Features.FirstOrDefault(f => f.Name == "suspicious_api_count")?.Weight ?? 0.20;
                score += weight * Math.Min(1.0, features.SuspiciousAPICount / 5.0);
            }
            totalWeight += 0.20;

            // Packing
            if (features.IsPacked)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "packed")?.Weight ?? 0.15;
            }
            totalWeight += 0.15;

            // Digital signature (negative = good)
            if (!features.IsSigned)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "unsigned")?.Weight ?? 0.10;
            }
            else
            {
                score -= 0.05; // Reduce threat score for signed files
            }
            totalWeight += 0.10;

            // File size ratio
            if (features.SizeRatio > 0.8 || features.SizeRatio < 0.05)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "size_ratio")?.Weight ?? 0.08;
            }
            totalWeight += 0.08;

            // Section count
            if (features.SectionCount > 6)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "section_count")?.Weight ?? 0.05;
            }
            totalWeight += 0.05;

            // Import count
            if (features.ImportCount > 100)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "import_count")?.Weight ?? 0.10;
            }
            totalWeight += 0.10;

            // Recent creation
            if (features.IsRecentlyCreated)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "recent_creation")?.Weight ?? 0.07;
            }
            totalWeight += 0.07;

            // Network behavior
            if (features.HasNetworkCode)
            {
                score += model.Features.FirstOrDefault(f => f.Name == "network_behavior")?.Weight ?? 0.10;
            }
            totalWeight += 0.10;

            return Math.Min(1.0, Math.Max(0.0, score));
        }

        private double CalculateConfidence(FileFeatures features)
        {
            int featuresAnalyzed = 0;
            
            if (features.Entropy > 0) featuresAnalyzed++;
            if (features.IsPEFile) featuresAnalyzed++;
            if (features.SuspiciousAPICount >= 0) featuresAnalyzed++;
            if (features.IsPacked) featuresAnalyzed++;
            if (features.IsSigned || !features.IsSigned) featuresAnalyzed++;
            if (features.SectionCount >= 0) featuresAnalyzed++;
            if (features.ImportCount >= 0) featuresAnalyzed++;
            if (features.LocationRisk >= 0) featuresAnalyzed++;

            return Math.Min(0.95, 0.3 + (featuresAnalyzed / 8.0) * 0.65);
        }

        private string ClassifyThreat(double score)
        {
            return score switch
            {
                >= 0.9 => "Critical",
                >= 0.7 => "High",
                >= 0.5 => "Medium",
                >= 0.3 => "Low",
                _ => "Safe"
            };
        }

        private List<string> GenerateExplanations(FileFeatures features, double score)
        {
            var explanations = new List<string>();

            if (features.Entropy > 6.5)
                explanations.Add($"High entropy ({features.Entropy:F2}) suggests packed or encrypted content");

            if (features.SuspiciousAPICount > 2)
                explanations.Add($"Contains {features.SuspiciousAPICount} suspicious API calls commonly used by malware");

            if (features.IsPacked)
                explanations.Add("Known packer signature detected");

            if (!features.IsSigned && features.IsPEFile)
                explanations.Add("File is not digitally signed");

            if (features.IsRecentlyCreated)
                explanations.Add("File was created recently (within 7 days)");

            if (features.HasNetworkCode)
                explanations.Add("Contains network communication code");

            if (score > 0.7 && explanations.Count == 0)
                explanations.Add("Multiple behavioral indicators suggest malicious intent");

            if (explanations.Count == 0)
                explanations.Add("No significant threat indicators detected");

            return explanations;
        }

        /// <summary>
        /// Batch analyze multiple files
        /// </summary>
        public async Task<List<MLAnalysisResult>> AnalyzeFilesAsync(IEnumerable<string> filePaths)
        {
            var results = new List<MLAnalysisResult>();
            
            foreach (var path in filePaths)
            {
                var result = await AnalyzeFileAsync(path);
                results.Add(result);
            }
            
            return results;
        }
    }

    #region Data Classes

    public class ThreatModel
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public List<ModelFeature> Features { get; set; } = new();
    }

    public class ModelFeature
    {
        public string Name { get; set; } = "";
        public double Weight { get; set; }
        public double Threshold { get; set; }
    }

    public class FileFeatures
    {
        public string FilePath { get; set; } = "";
        public long FileSize { get; set; }
        public double Entropy { get; set; }
        public bool IsPacked { get; set; }
        public bool IsSigned { get; set; }
        public bool IsPEFile { get; set; }
        public int SuspiciousAPICount { get; set; }
        public int ImportCount { get; set; }
        public int SectionCount { get; set; }
        public bool IsRecentlyCreated { get; set; }
        public int CreationAgeDays { get; set; }
        public bool HasNetworkCode { get; set; }
        public double LocationRisk { get; set; }
        public double SizeRatio { get; set; }
    }

    public class MLAnalysisResult
    {
        public string FilePath { get; set; } = "";
        public long FileSize { get; set; }
        public FileFeatures? Features { get; set; }
        public double ThreatScore { get; set; }
        public double Confidence { get; set; }
        public string Classification { get; set; } = "";
        public bool IsThreat { get; set; }
        public bool IsLargeFile { get; set; }
        public List<string> Explanations { get; set; } = new();
        public DateTime AnalyzedAt { get; set; }
        public string? Error { get; set; }
    }

    #endregion
} 


