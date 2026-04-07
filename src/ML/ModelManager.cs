using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.ML
{
    /// <summary>
    /// ML Model Manager - Loads and manages ML models for threat detection
    /// Supports ONNX models trained with Python/PyTorch
    /// </summary>
    public class ModelManager : IDisposable
    {
        private readonly string _modelDirectory;
        private readonly Dictionary<string, MLModel> _loadedModels = new();
        private readonly object _lock = new();
        private bool _isInitialized;

        // Model types supported
        public const string MODEL_STATIC_PE = "static_pe_malware";
        public const string MODEL_BEHAVIOR = "behavior_anomaly";
        public const string MODEL_SANDBOX = "sandbox_analysis";
        public const string MODEL_DGA = "dga_detection";

        public event EventHandler<ModelLoadedEventArgs>? ModelLoaded;
        public event EventHandler<ModelLoadFailedEventArgs>? ModelLoadFailed;

        public ModelManager()
        {
            _modelDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "models");
            
            Directory.CreateDirectory(_modelDirectory);
            Core.Logger.Log("Info", $"ModelManager initialized. Model directory: {_modelDirectory}");
        }

        /// <summary>
        /// Initialize and load all available models
        /// </summary>
        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            await Task.Run(() =>
            {
                // Try to load each model type
                TryLoadModel(MODEL_STATIC_PE);
                TryLoadModel(MODEL_BEHAVIOR);
                TryLoadModel(MODEL_SANDBOX);
                TryLoadModel(MODEL_DGA);
            });

            _isInitialized = true;
            Core.Logger.Log("Info", $"ModelManager initialized with {_loadedModels.Count} models");
        }

        /// <summary>
        /// Try to load a model from the model directory
        /// </summary>
        private void TryLoadModel(string modelType)
        {
            try
            {
                var modelPath = Path.Combine(_modelDirectory, $"{modelType}.onnx");
                var metadataPath = Path.Combine(_modelDirectory, $"{modelType}.meta.json");

                if (File.Exists(modelPath))
                {
                    var model = new MLModel
                    {
                        ModelType = modelType,
                        ModelPath = modelPath,
                        IsLoaded = true,
                        LoadedAt = DateTime.Now
                    };

                    // Load metadata if available
                    if (File.Exists(metadataPath))
                    {
                        var json = File.ReadAllText(metadataPath);
                        model.Metadata = System.Text.Json.JsonSerializer.Deserialize<ModelMetadata>(json);
                    }

                    lock (_lock)
                    {
                        _loadedModels[modelType] = model;
                    }

                    ModelLoaded?.Invoke(this, new ModelLoadedEventArgs(modelType, model));
                    Core.Logger.Log("Info", $"Loaded ML model: {modelType}");
                }
                else
                {
                    Core.Logger.Log("Debug", $"Model not found: {modelType} (expected at {modelPath})");
                }
            }
            catch (Exception ex)
            {
                ModelLoadFailed?.Invoke(this, new ModelLoadFailedEventArgs(modelType, ex.Message));
                Core.Logger.Log("Error", $"Failed to load model {modelType}", ex);
            }
        }

        /// <summary>
        /// Check if a model is loaded
        /// </summary>
        public bool IsModelLoaded(string modelType)
        {
            lock (_lock)
            {
                return _loadedModels.TryGetValue(modelType, out var model) && model.IsLoaded;
            }
        }

        /// <summary>
        /// Get a loaded model
        /// </summary>
        public MLModel? GetModel(string modelType)
        {
            lock (_lock)
            {
                return _loadedModels.TryGetValue(modelType, out var model) ? model : null;
            }
        }

        /// <summary>
        /// Get all loaded models
        /// </summary>
        public List<MLModel> GetAllModels()
        {
            lock (_lock)
            {
                return _loadedModels.Values.ToList();
            }
        }

        /// <summary>
        /// Run inference using a specific model
        /// </summary>
        public async Task<MLPredictionResult> PredictAsync(string modelType, Dictionary<string, float> features)
        {
            var result = new MLPredictionResult
            {
                ModelType = modelType,
                PredictionTime = DateTime.Now
            };

            var model = GetModel(modelType);
            if (model == null || !model.IsLoaded)
            {
                result.Success = false;
                result.ErrorMessage = $"Model not loaded: {modelType}";
                Core.Logger.Log("Warning", result.ErrorMessage);
                return result;
            }

            try
            {
                // Use the prediction engine
                var prediction = await PredictionEngine.PredictAsync(model.ModelPath, features);
                result.Prediction = prediction.Prediction;
                result.Probability = prediction.Probability;
                result.Confidence = prediction.Confidence;
                result.Success = true;
                
                Core.Logger.Log("Debug", $"ML Prediction: {modelType} -> {result.Prediction:F4}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
                Core.Logger.Log("Error", $"Prediction failed for {modelType}", ex);
            }

            return result;
        }

        /// <summary>
        /// Add or update a model (for future cloud model updates)
        /// </summary>
        public async Task<bool> AddModelAsync(string modelType, byte[] modelData, ModelMetadata? metadata = null)
        {
            try
            {
                var modelPath = Path.Combine(_modelDirectory, $"{modelType}.onnx");
                await File.WriteAllBytesAsync(modelPath, modelData);

                if (metadata != null)
                {
                    var metadataPath = Path.Combine(_modelDirectory, $"{modelType}.meta.json");
                    var json = System.Text.Json.JsonSerializer.Serialize(metadata, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    await File.WriteAllTextAsync(metadataPath, json);
                }

                // Reload the model
                TryLoadModel(modelType);
                
                Core.Logger.Log("Info", $"Added/updated model: {modelType}");
                return true;
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", $"Failed to add model {modelType}", ex);
                return false;
            }
        }

        /// <summary>
        /// Get model directory path
        /// </summary>
        public string GetModelDirectory() => _modelDirectory;

        public void Dispose()
        {
            lock (_lock)
            {
                _loadedModels.Clear();
            }
            Core.Logger.Log("Info", "ModelManager disposed");
        }
    }

    /// <summary>
    /// Represents a loaded ML model
    /// </summary>
    public class MLModel
    {
        public string ModelType { get; set; } = "";
        public string ModelPath { get; set; } = "";
        public bool IsLoaded { get; set; }
        public DateTime LoadedAt { get; set; }
        public ModelMetadata? Metadata { get; set; }
    }

    /// <summary>
    /// Model metadata information
    /// </summary>
    public class ModelMetadata
    {
        public string Name { get; set; } = "";
        public string Version { get; set; } = "";
        public string Description { get; set; } = "";
        public DateTime TrainedAt { get; set; }
        public string DatasetUsed { get; set; } = "";
        public float Accuracy { get; set; }
        public float F1Score { get; set; }
        public List<string> Features { get; set; } = new();
        public string ModelArchitecture { get; set; } = "";
    }

    /// <summary>
    /// Result of ML prediction
    /// </summary>
    public class MLPredictionResult
    {
        public string ModelType { get; set; } = "";
        public bool Success { get; set; }
        public float Prediction { get; set; }
        public float Probability { get; set; }
        public float Confidence { get; set; }
        public string? ErrorMessage { get; set; }
        public DateTime PredictionTime { get; set; }
    }

    public class ModelLoadedEventArgs : EventArgs
    {
        public string ModelType { get; }
        public MLModel Model { get; }

        public ModelLoadedEventArgs(string modelType, MLModel model)
        {
            ModelType = modelType;
            Model = model;
        }
    }

    public class ModelLoadFailedEventArgs : EventArgs
    {
        public string ModelType { get; }
        public string Error { get; }

        public ModelLoadFailedEventArgs(string modelType, string error)
        {
            ModelType = modelType;
            Error = error;
        }
    }
}

