using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SecureGuard.Core
{
    /// <summary>
    /// Automatic Update System for Level 2
    /// Handles signature, engine, and AI model updates with rollback support
    /// </summary>
    public class BackgroundUpdater : IDisposable
    {
        private readonly string _updateDirectory;
        private readonly HttpClient _httpClient;
        private CancellationTokenSource? _updateCancellation;
        private Timer? _updateTimer;
        private bool _isUpdating;
        private UpdateSettings _settings;

        public event EventHandler<UpdateAvailableEventArgs>? UpdateAvailable;
        public event EventHandler<UpdateProgressEventArgs>? UpdateProgress;
        public event EventHandler<UpdateCompletedEventArgs>? UpdateCompleted;
        public event EventHandler<UpdateFailedEventArgs>? UpdateFailed;

        public BackgroundUpdater(string updateDirectory)
        {
            _updateDirectory = updateDirectory;
            _httpClient = new HttpClient();
            _settings = new UpdateSettings();
            Directory.CreateDirectory(_updateDirectory);
            LoadSettings();
        }

        public void StartAutoUpdate(int intervalHours = 4)
        {
            _updateTimer = new Timer(async _ => await CheckAndDownloadUpdatesAsync(), null, TimeSpan.Zero, TimeSpan.FromHours(intervalHours));
            Logger.Log("Info", $"Auto-update started with {intervalHours}h interval");
        }

        public void StopAutoUpdate()
        {
            _updateTimer?.Dispose();
            _updateTimer = null;
            Logger.Log("Info", "Auto-update stopped");
        }

        public async Task<UpdateCheckResult> CheckForUpdatesAsync()
        {
            try
            {
                Logger.Log("Info", "Checking for updates...");
                var signatureVersion = await CheckSignatureUpdateAsync();
                var engineVersion = await CheckEngineUpdateAsync();
                var aiModelVersion = await CheckAiModelUpdateAsync();

                var hasUpdates = signatureVersion?.HasUpdate == true || engineVersion?.HasUpdate == true || aiModelVersion?.HasUpdate == true;
                var result = new UpdateCheckResult { HasUpdates = hasUpdates, SignatureUpdate = signatureVersion, EngineUpdate = engineVersion, AiModelUpdate = aiModelVersion };

                if (hasUpdates) { Logger.Log("Info", "Updates available!"); UpdateAvailable?.Invoke(this, new UpdateAvailableEventArgs(result)); }
                else Logger.Log("Info", "No updates available");
                return result;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to check for updates", ex);
                return new UpdateCheckResult { HasUpdates = false, Error = ex.Message };
            }
        }

        public async Task<UpdateResult> DownloadAndApplyUpdatesAsync()
        {
            if (_isUpdating) return new UpdateResult { Success = false, Message = "Update already in progress" };
            _isUpdating = true;
            _updateCancellation = new CancellationTokenSource();
            var result = new UpdateResult();

            try
            {
                var checkResult = await CheckForUpdatesAsync();
                if (!checkResult.HasUpdates) { result.Success = true; result.Message = "No updates needed"; return result; }
                await BackupCurrentStateAsync();

                if (checkResult.SignatureUpdate?.HasUpdate == true) { UpdateProgress?.Invoke(this, new UpdateProgressEventArgs("Downloading signature update...", 10)); await DownloadSignatureUpdateAsync(checkResult.SignatureUpdate); }
                if (checkResult.EngineUpdate?.HasUpdate == true) { UpdateProgress?.Invoke(this, new UpdateProgressEventArgs("Downloading engine update...", 40)); await DownloadEngineUpdateAsync(checkResult.EngineUpdate); }
                if (checkResult.AiModelUpdate?.HasUpdate == true) { UpdateProgress?.Invoke(this, new UpdateProgressEventArgs("Downloading AI model update...", 70)); await DownloadAiModelUpdateAsync(checkResult.AiModelUpdate); }

                UpdateProgress?.Invoke(this, new UpdateProgressEventArgs("Applying updates...", 90));
                await ApplyUpdatesAsync();
                result.Success = true; result.Message = "Updates applied successfully";
                UpdateCompleted?.Invoke(this, new UpdateCompletedEventArgs(checkResult));
                Logger.Log("Info", "Updates applied successfully");
            }
            catch (Exception ex)
            {
                result.Success = false; result.Message = ex.Message;
                await RollbackAsync();
                UpdateFailed?.Invoke(this, new UpdateFailedEventArgs(ex.Message));
                Logger.Log("Error", "Update failed, rolled back", ex);
            }
            finally { _isUpdating = false; _updateCancellation?.Dispose(); _updateCancellation = null; }
            return result;
        }

        public VersionInfo GetCurrentVersions() => new VersionInfo { EngineVersion = GetStoredVersion("engine"), SignatureVersion = GetStoredVersion("signature"), AiModelVersion = GetStoredVersion("aimodel") };

        private async Task CheckAndDownloadUpdatesAsync() { try { await DownloadAndApplyUpdatesAsync(); } catch (Exception ex) { Logger.Log("Error", "Auto-update failed", ex); } }

        private async Task<ComponentUpdateInfo?> CheckSignatureUpdateAsync()
        {
            try
            {
                var currentVersion = GetStoredVersion("signature");
                var response = await _httpClient.GetStringAsync(_settings.SignatureUpdateUrl);
                var updateInfo = JsonSerializer.Deserialize<ComponentUpdateInfo>(response);
                if (updateInfo != null && updateInfo.Version != currentVersion) updateInfo.HasUpdate = true;
                return updateInfo;
            }
            catch { return null; }
        }

        private async Task<ComponentUpdateInfo?> CheckEngineUpdateAsync()
        {
            try
            {
                var currentVersion = GetStoredVersion("engine");
                var response = await _httpClient.GetStringAsync(_settings.EngineUpdateUrl);
                var updateInfo = JsonSerializer.Deserialize<ComponentUpdateInfo>(response);
                if (updateInfo != null && updateInfo.Version != currentVersion) updateInfo.HasUpdate = true;
                return updateInfo;
            }
            catch { return null; }
        }

        private async Task<ComponentUpdateInfo?> CheckAiModelUpdateAsync()
        {
            try
            {
                var currentVersion = GetStoredVersion("aimodel");
                var response = await _httpClient.GetStringAsync(_settings.AiModelUpdateUrl);
                var updateInfo = JsonSerializer.Deserialize<ComponentUpdateInfo>(response);
                if (updateInfo != null && updateInfo.Version != currentVersion) updateInfo.HasUpdate = true;
                return updateInfo;
            }
            catch { return null; }
        }

        private async Task DownloadSignatureUpdateAsync(ComponentUpdateInfo info)
        {
            var data = await _httpClient.GetByteArrayAsync(info.DownloadUrl);
            await File.WriteAllBytesAsync(Path.Combine(_updateDirectory, "signatures_new.dat"), data);
        }

        private async Task DownloadEngineUpdateAsync(ComponentUpdateInfo info)
        {
            var data = await _httpClient.GetByteArrayAsync(info.DownloadUrl);
            await File.WriteAllBytesAsync(Path.Combine(_updateDirectory, "engine_new.dll"), data);
        }

        private async Task DownloadAiModelUpdateAsync(ComponentUpdateInfo info)
        {
            var data = await _httpClient.GetByteArrayAsync(info.DownloadUrl);
            await File.WriteAllBytesAsync(Path.Combine(_updateDirectory, "aimodel_new.bin"), data);
        }

        private async Task ApplyUpdatesAsync()
        {
            var newSignatures = Path.Combine(_updateDirectory, "signatures_new.dat");
            if (File.Exists(newSignatures))
            {
                var old = Path.Combine(_updateDirectory, "signatures.dat");
                if (File.Exists(old)) File.Delete(old);
                File.Move(newSignatures, old);
                SetStoredVersion("signature", "1.0.0");
            }
            var newEngine = Path.Combine(_updateDirectory, "engine_new.dll");
            if (File.Exists(newEngine))
            {
                var old = Path.Combine(_updateDirectory, "engine.dll");
                if (File.Exists(old)) File.Delete(old);
                File.Move(newEngine, old);
            }
            var newAi = Path.Combine(_updateDirectory, "aimodel_new.bin");
            if (File.Exists(newAi))
            {
                var old = Path.Combine(_updateDirectory, "aimodel.bin");
                if (File.Exists(old)) File.Delete(old);
                File.Move(newAi, old);
            }
            await Task.CompletedTask;
        }

        private async Task BackupCurrentStateAsync()
        {
            var backupDir = Path.Combine(_updateDirectory, "backup");
            Directory.CreateDirectory(backupDir);
            var signatures = Path.Combine(_updateDirectory, "signatures.dat");
            if (File.Exists(signatures)) File.Copy(signatures, Path.Combine(backupDir, "signatures.dat"), true);
            await Task.CompletedTask;
        }

        private async Task RollbackAsync()
        {
            try
            {
                var backupDir = Path.Combine(_updateDirectory, "backup");
                var backupSigs = Path.Combine(backupDir, "signatures.dat");
                var sigs = Path.Combine(_updateDirectory, "signatures.dat");
                if (File.Exists(backupSigs)) { if (File.Exists(sigs)) File.Delete(sigs); File.Copy(backupSigs, sigs); }
                Logger.Log("Info", "Rollback completed");
            }
            catch (Exception ex) { Logger.Log("Error", "Rollback failed", ex); }
            await Task.CompletedTask;
        }

        private string GetStoredVersion(string component)
        {
            var versionFile = Path.Combine(_updateDirectory, $"{component}.ver");
            return File.Exists(versionFile) ? File.ReadAllText(versionFile).Trim() : "1.0.0";
        }

        private void SetStoredVersion(string component, string version) => File.WriteAllText(Path.Combine(_updateDirectory, $"{component}.ver"), version);

        private void LoadSettings()
        {
            var settingsPath = Path.Combine(_updateDirectory, "settings.json");
            if (File.Exists(settingsPath))
            {
                try { _settings = JsonSerializer.Deserialize<UpdateSettings>(File.ReadAllText(settingsPath)) ?? new UpdateSettings(); }
                catch { _settings = new UpdateSettings(); }
            }
        }

        public void Dispose() { StopAutoUpdate(); _httpClient.Dispose(); }
    }

    public class UpdateSettings
    {
        public string SignatureUpdateUrl { get; set; } = "https://updates.secureguard.com/signatures/version.json";
        public string EngineUpdateUrl { get; set; } = "https://updates.secureguard.com/engine/version.json";
        public string AiModelUpdateUrl { get; set; } = "https://updates.secureguard.com/aimodel/version.json";
        public int UpdateCheckIntervalHours { get; set; } = 4;
    }

    public class UpdateCheckResult { public bool HasUpdates { get; set; } public ComponentUpdateInfo? SignatureUpdate { get; set; } public ComponentUpdateInfo? EngineUpdate { get; set; } public ComponentUpdateInfo? AiModelUpdate { get; set; } public string? Error { get; set; } }
    public class ComponentUpdateInfo { public string Version { get; set; } = ""; public bool HasUpdate { get; set; } public string DownloadUrl { get; set; } = ""; public string? Changelog { get; set; } public long Size { get; set; } }
    public class UpdateResult { public bool Success { get; set; } public string Message { get; set; } = ""; }
    public class VersionInfo { public string EngineVersion { get; set; } = ""; public string SignatureVersion { get; set; } = ""; public string AiModelVersion { get; set; } = ""; }
    public class UpdateAvailableEventArgs : EventArgs { public UpdateCheckResult UpdateInfo { get; } public UpdateAvailableEventArgs(UpdateCheckResult i) { UpdateInfo = i; } }
    public class UpdateProgressEventArgs : EventArgs { public string Message { get; } public int Percentage { get; } public UpdateProgressEventArgs(string m, int p) { Message = m; Percentage = p; } }
    public class UpdateCompletedEventArgs : EventArgs { public UpdateCheckResult UpdateInfo { get; } public UpdateCompletedEventArgs(UpdateCheckResult i) { UpdateInfo = i; } }
    public class UpdateFailedEventArgs : EventArgs { public string Error { get; } public UpdateFailedEventArgs(string e) { Error = e; } }
}

