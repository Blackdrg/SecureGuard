using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.ML
{
    /// <summary>
    /// Prediction Engine - Runs ML model inference
    /// Uses trained model weights when available, falls back to heuristic scoring
    /// </summary>
    public static class PredictionEngine
    {
        private static bool _useTrainedModel = false;
        private static TrainedModel? _staticPeModel;
        private static TrainedModel? _behaviorModel;
        private static readonly object _lock = new();
        
        // Fallback heuristic weights (used when trained models not available)
        private static readonly Dictionary<string, float> HeuristicWeights = new()
        {
            ["file_size"] = 0.05f,
            ["days_since_creation"] = 0.03f,
            ["days_since_modified"] = 0.02f,
            ["location_risk"] = 0.08f,
            ["is_pe_file"] = 0.05f,
            ["is_dll"] = 0.05f,
            ["is_executable"] = 0.02f,
            ["is_pe32"] = 0.01f,
            ["is_pe32plus"] = 0.01f,
            ["is_console"] = 0.01f,
            ["is_gui"] = 0.01f,
            ["number_of_sections"] = 0.03f,
            ["section_with_code"] = 0.02f,
            ["section_with_data"] = 0.01f,
            ["section_with_resources"] = 0.01f,
            ["size_ratio"] = 0.03f,
            ["suspicious_api_count"] = 0.15f,
            ["known_dll_count"] = -0.02f,
            ["has_process_injection"] = 0.20f,
            ["has_registry_manipulation"] = 0.08f,
            ["has_network_apis"] = 0.05f,
            ["has_cryptography"] = 0.10f,
            ["overall_entropy"] = 0.10f,
            ["header_entropy"] = 0.05f,
            ["middle_entropy"] = 0.05f,
            ["is_high_entropy"] = 0.10f,
            ["is_very_high_entropy"] = 0.15f,
            ["string_count"] = 0.02f,
            ["url_count"] = 0.05f,
            ["ip_address_count"] = 0.05f,
            ["path_count"] = 0.02f,
            ["is_packed"] = 0.15f,
            ["is_signed"] = -0.10f,
            ["is_recently_created"] = 0.08f,
            ["is_recently_modified"] = 0.05f
        };

        static PredictionEngine()
        {
            TryLoadTrainedModels();
        }

        /// <summary>
        /// Try to load trained models from the models directory
        /// </summary>
        private static void TryLoadTrainedModels()
        {
            try
            {
                var modelDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SecureGuard", "models");
                
                if (!Directory.Exists(modelDir))
                {
                    // Try relative path from application directory
                    modelDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "models");
                }
                
                if (!Directory.Exists(modelDir))
                {
                    Core.Logger.Log("Info", "No models directory found, using heuristic fallback");
                    return;
                }
                
                // Try to load static PE model
                var staticPeWeightsPath = Path.Combine(modelDir, "static_pe_malware.weights.json");
                var staticPeScalerPath = Path.Combine(modelDir, "static_pe_malware.scaler.json");
                var staticPeMetaPath = Path.Combine(modelDir, "static_pe_malware.meta.json");
                
                if (File.Exists(staticPeWeightsPath) && File.Exists(staticPeScalerPath))
                {
                    _staticPeModel = LoadModel(staticPeWeightsPath, staticPeScalerPath, staticPeMetaPath);
                    _useTrainedModel = true;
                    Core.Logger.Log("Info", $"Loaded trained static PE model: {_staticPeModel?.Metadata?.Name ?? "Unknown"}");
                }
                
                // Try to load behavior model
                var behaviorWeightsPath = Path.Combine(modelDir, "behavior_anomaly.weights.json");
                var behaviorScalerPath = Path.Combine(modelDir, "behavior_anomaly.scaler.json");
                var behaviorMetaPath = Path.Combine(modelDir, "behavior_anomaly.meta.json");
                
                if (File.Exists(behaviorWeightsPath) && File.Exists(behaviorScalerPath))
                {
                    _behaviorModel = LoadModel(behaviorWeightsPath, behaviorScalerPath, behaviorMetaPath);
                    Core.Logger.Log("Info", $"Loaded trained behavior model: {_behaviorModel?.Metadata?.Name ?? "Unknown"}");
                }
                
                if (_useTrainedModel)
                {
                    Core.Logger.Log("Info", "Using trained ML models for predictions");
                }
                else
                {
                    Core.Logger.Log("Info", "Using heuristic fallback model");
                }
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Warning", $"Failed to load trained models: {ex.Message}");
                _useTrainedModel = false;
            }
        }

        private static TrainedModel? LoadModel(string weightsPath, string scalerPath, string metaPath)
        {
            try
            {
                var model = new TrainedModel();
                
                // Load weights
                var weightsJson = File.ReadAllText(weightsPath);
                model.Weights = JsonSerializer.Deserialize<Dictionary<string, double>>(weightsJson);
                
                // Load scaler
                var scalerJson = File.ReadAllText(scalerPath);
                var scalerData = JsonSerializer.Deserialize<ScalerData>(scalerJson);
                if (scalerData != null)
                {
                    model.ScalerMean = scalerData.Mean;
                    model.ScalerScale = scalerData.Scale;
                }
                
                // Load metadata if available
                if (File.Exists(metaPath))
                {
                    var metaJson = File.ReadAllText(metaPath);
                    model.Metadata = JsonSerializer.Deserialize<ModelMetadata>(metaJson);
                }
                
                return model;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to load model from {weightsPath}", ex);
                return null;
            }
        }

        /// <summary>
        /// Run prediction on a file using ML model
        /// </summary>
        public static async Task<PredictionResult> PredictAsync(string modelPath, Dictionary<string, float> features)
        {
            var result = new PredictionResult
            {
                PredictionTime = DateTime.Now
            };

            try
            {
                if (_useTrainedModel && _staticPeModel != null)
                {
                    // Use trained model
                    result = await PredictWithTrainedModelAsync(features, _staticPeModel);
                }
                else
                {
                    // Use heuristic fallback
                    result = PredictWithHeuristics(features);
                }

                Core.Logger.Log("Debug", $"ML Prediction: Score={result.Prediction:F4}, Confidence={result.Confidence:F2}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Prediction failed", ex);
                result.Prediction = 0.5f;
                result.Confidence = 0.0f;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Run prediction with trained model
        /// </summary>
        private static async Task<PredictionResult> PredictWithTrainedModelAsync(
            Dictionary<string, float> features, TrainedModel model)
        {
            return await Task.Run(() =>
            {
                var result = new PredictionResult
                {
                    PredictionTime = DateTime.Now
                };

                try
                {
                    // Convert features to array in correct order
                    var featureNames = model.Weights.Keys.ToList();
                    var values = new List<double>();
                    
                    foreach (var name in featureNames)
                    {
                        if (features.TryGetValue(name, out var val))
                        {
                            values.Add(val);
                        }
                        else
                        {
                            values.Add(0);
                        }
                    }
                    
                    // Apply scaling
                    var scaledValues = new double[values.Count];
                    for (int i = 0; i < values.Count; i++)
                    {
                        if (i < model.ScalerMean.Count && i < model.ScalerScale.Count && model.ScalerScale[i] != 0)
                        {
                            scaledValues[i] = (values[i] - model.ScalerMean[i]) / model.ScalerScale[i];
                        }
                        else
                        {
                            scaledValues[i] = values[i];
                        }
                    }
                    
                    // Calculate weighted sum
                    double score = 0;
                    double totalWeight = 0;
                    
                    for (int i = 0; i < featureNames.Count; i++)
                    {
                        var featureName = featureNames[i];
                        if (model.Weights.TryGetValue(featureName, out var weight))
                        {
                            score += weight * scaledValues[i];
                            totalWeight += Math.Abs(weight);
                        }
                    }
                    
                    // Normalize and apply sigmoid-like transformation
                    if (totalWeight > 0)
                    {
                        var normalizedScore = score / totalWeight;
                        // Transform to 0-1 range with sigmoid-like function
                        result.Prediction = (float)(1.0 / (1.0 + Math.Exp(-normalizedScore * 3)));
                    }
                    
                    // Calculate confidence based on feature coverage
                    int featuresMatched = 0;
                    foreach (var key in model.Weights.Keys)
                    {
                        if (features.ContainsKey(key) && features[key] != 0)
                        {
                            featuresMatched++;
                        }
                    }
                    
                    result.Confidence = Math.Min(0.95f, 0.3f + (featuresMatched / (float)model.Weights.Count) * 0.65f);
                    
                    // Use model accuracy as confidence boost if available
                    if (model.Metadata?.Accuracy > 0)
                    {
                        result.Confidence = Math.Min(0.95f, result.Confidence * (float)model.Metadata.Accuracy);
                    }
                    
                    // Determine threat level
                    result.ThreatLevel = result.Prediction switch
                    {
                        >= 0.9f => "Critical",
                        >= 0.7f => "High",
                        >= 0.5f => "Medium",
                        >= 0.3f => "Low",
                        _ => "Safe"
                    };
                    
                    // Add explanations
                    result.Explanations = GenerateExplanations(features, result.Prediction);
                }
                catch (Exception ex)
                {
                    Core.Logger.Log("Error", "Trained model prediction failed", ex);
                    // Fallback to heuristic
                    return PredictWithHeuristics(features);
                }

                return result;
            });
        }

        /// <summary>
        /// Fallback heuristic-based prediction when ML model is not available
        /// </summary>
        private static PredictionResult PredictWithHeuristics(Dictionary<string, float> features)
        {
            var result = new PredictionResult
            {
                PredictionTime = DateTime.Now
            };

            float score = 0.0f;
            float totalWeight = 0.0f;

            foreach (var feature in features)
            {
                if (HeuristicWeights.TryGetValue(feature.Key, out var weight))
                {
                    float featureValue = feature.Value;
                    
                    if (feature.Key == "suspicious_api_count")
                    {
                        score += weight * Math.Min(1.0f, featureValue / 10.0f);
                    }
                    else if (feature.Key.Contains("entropy"))
                    {
                        score += weight * (float)(featureValue / 8.0);
                    }
                    else if (feature.Key == "file_size")
                    {
                        score += weight * (float)Math.Min(1.0, Math.Log10(featureValue + 1) / 7.0);
                    }
                    else if (feature.Key.EndsWith("_count"))
                    {
                        score += weight * Math.Min(1.0f, featureValue / 50.0f);
                    }
                    else
                    {
                        score += weight * featureValue;
                    }

                    totalWeight += Math.Abs(weight);
                }
            }

            if (totalWeight > 0)
            {
                result.Prediction = Math.Min(1.0f, Math.Max(0.0f, score));
            }

            int featuresMatched = 0;
            foreach (var key in HeuristicWeights.Keys)
            {
                if (features.ContainsKey(key) && features[key] != 0)
                {
                    featuresMatched++;
                }
            }
            
            result.Confidence = Math.Min(0.95f, 0.3f + (featuresMatched / (float)HeuristicWeights.Count) * 0.65f);

            result.ThreatLevel = result.Prediction switch
            {
                >= 0.9f => "Critical",
                >= 0.7f => "High",
                >= 0.5f => "Medium",
                >= 0.3f => "Low",
                _ => "Safe"
            };

            result.Explanations = GenerateExplanations(features, result.Prediction);

            return result;
        }

        /// <summary>
        /// Generate human-readable explanations for the prediction
        /// </summary>
        private static List<string> GenerateExplanations(Dictionary<string, float> features, float prediction)
        {
            var explanations = new List<string>();

            if (features.TryGetValue("overall_entropy", out var entropy) && entropy > 6.5f)
            {
                explanations.Add($"High entropy ({entropy:F2}) suggests packed or encrypted content");
            }

            if (features.TryGetValue("suspicious_api_count", out var apiCount) && apiCount > 2)
            {
                explanations.Add($"Contains {apiCount} suspicious API calls commonly used by malware");
            }

            if (features.TryGetValue("is_packed", out var isPacked) && isPacked > 0.5f)
            {
                explanations.Add("Known packer signature detected");
            }

            if (features.TryGetValue("is_signed", out var isSigned) && isSigned < 0.5f && 
                features.TryGetValue("is_pe_file", out var isPe) && isPe > 0.5f)
            {
                explanations.Add("File is not digitally signed");
            }

            if (features.TryGetValue("has_process_injection", out var hasInject) && hasInject > 0.5f)
            {
                explanations.Add("Process injection capabilities detected");
            }

            if (features.TryGetValue("has_cryptography", out var hasCrypto) && hasCrypto > 0.5f)
            {
                explanations.Add("Contains cryptographic functions");
            }

            if (features.TryGetValue("is_recently_created", out var isRecent) && isRecent > 0.5f)
            {
                explanations.Add("File was created recently");
            }

            if (features.TryGetValue("url_count", out var urlCount) && urlCount > 0)
            {
                explanations.Add($"Contains {urlCount} URL references");
            }

            if (explanations.Count == 0)
            {
                explanations.Add("No significant threat indicators detected");
            }

            return explanations;
        }

        /// <summary>
        /// Check if trained models are being used
        /// </summary>
        public static bool IsUsingTrainedModel() => _useTrainedModel;

        /// <summary>
        /// Get model information
        /// </summary>
        public static ModelInfo GetModelInfo()
        {
            return new ModelInfo
            {
                UsingTrainedModel = _useTrainedModel,
                StaticPEModelLoaded = _staticPeModel != null,
                BehaviorModelLoaded = _behaviorModel != null,
                StaticPEModelName = _staticPeModel?.Metadata?.Name ?? "Not loaded",
                BehaviorModelName = _behaviorModel?.Metadata?.Name ?? "Not loaded",
                StaticPEAccuracy = _staticPeModel?.Metadata?.Accuracy ?? 0,
                BehaviorAccuracy = _behaviorModel?.Metadata?.Accuracy ?? 0
            };
        }

        /// <summary>
        /// Get available model files
        /// </summary>
        public static List<string> GetAvailableModels(string modelDirectory)
        {
            var models = new List<string>();
            
            if (Directory.Exists(modelDirectory))
            {
                foreach (var file in Directory.GetFiles(modelDirectory, "*.weights.json"))
                {
                    models.Add(Path.GetFileNameWithoutExtension(file).Replace(".weights", ""));
                }
            }

            return models;
        }
    }

    /// <summary>
    /// Represents a loaded trained model
    /// </summary>
    public class TrainedModel
    {
        public Dictionary<string, double>? Weights { get; set; }
        public List<double> ScalerMean { get; set; } = new();
        public List<double> ScalerScale { get; set; } = new();
        public ModelMetadata? Metadata { get; set; }
    }

    /// <summary>
    /// Scaler data from training
    /// </summary>
    public class ScalerData
    {
        public List<double> Mean { get; set; } = new();
        public List<double> Scale { get; set; } = new();
        public List<string>? FeatureNames { get; set; }
    }

    /// <summary>
    /// Model information
    /// </summary>
    public class ModelInfo
    {
        public bool UsingTrainedModel { get; set; }
        public bool StaticPEModelLoaded { get; set; }
        public bool BehaviorModelLoaded { get; set; }
        public string StaticPEModelName { get; set; } = "";
        public string BehaviorModelName { get; set; } = "";
        public double StaticPEAccuracy { get; set; }
        public double BehaviorAccuracy { get; set; }
    }

    /// <summary>
    /// Result of a prediction
    /// </summary>
    public class PredictionResult
    {
        public float Prediction { get; set; }
        public float Probability { get; set; }
        public float Confidence { get; set; }
        public string ThreatLevel { get; set; } = "Unknown";
        public List<string> Explanations { get; set; } = new();
        public DateTime PredictionTime { get; set; }
        public string? ErrorMessage { get; set; }

        public bool IsThreat => Prediction > 0.7f;
        public bool IsHighConfidence => Confidence > 0.7f;
    }
}

