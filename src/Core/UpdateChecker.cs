using System;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SecureGuard.Core
{
    public class UpdateChecker
    {
        private const string CurrentVersion = "1.0.0";
        private const string UpdateUrl = "https://updates.secureguard.com/latest.xml";
        private readonly HttpClient _httpClient;
        
        public UpdateChecker()
        {
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
        }

        public static string GetCurrentVersion()
        {
            return Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? CurrentVersion;
        }

        public async Task<bool> CheckForUpdateAsync()
        {
            try
            {
                Logger.Log("Info", "Checking for updates...");
                
                var response = await _httpClient.GetStringAsync(UpdateUrl);
                var latestVersion = ParseVersionFromResponse(response);
                
                if (CompareVersions(latestVersion, GetCurrentVersion()) > 0)
                {
                    Logger.Log("Info", $"Update available: {latestVersion}");
                    return true;
                }
                
                Logger.Log("Info", "No updates available");
                return false;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Update check failed: {ex.Message}", ex);
                return false;
            }
        }

        public async Task<UpdateInfo?> GetUpdateInfoAsync()
        {
            try
            {
                var response = await _httpClient.GetStringAsync(UpdateUrl);
                return ParseUpdateInfo(response);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Failed to get update info: {ex.Message}", ex);
                return null;
            }
        }

        public async Task<bool> DownloadUpdateAsync(string downloadPath, IProgress<int>? progress = null)
        {
            try
            {
                var updateInfo = await GetUpdateInfoAsync();
                if (updateInfo == null || string.IsNullOrEmpty(updateInfo.DownloadUrl))
                {
                    return false;
                }

                Logger.Log("Info", $"Downloading update from {updateInfo.DownloadUrl}");
                
                var response = await _httpClient.GetAsync(updateInfo.DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();
                
                var totalBytes = response.Content.Headers.ContentLength ?? -1L;
                var downloadedBytes = 0L;
                
                using var contentStream = await response.Content.ReadAsStreamAsync();
                using var fileStream = new FileStream(downloadPath, FileMode.Create, FileAccess.Write, FileShare.None);
                
                var buffer = new byte[8192];
                int bytesRead;
                
                while ((bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await fileStream.WriteAsync(buffer, 0, bytesRead);
                    downloadedBytes += bytesRead;
                    
                    if (totalBytes > 0)
                    {
                        var progressPercent = (int)((downloadedBytes * 100) / totalBytes);
                        progress?.Report(progressPercent);
                    }
                }
                
                Logger.Log("Info", "Update downloaded successfully");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Download failed: {ex.Message}", ex);
                return false;
            }
        }

        private string ParseVersionFromResponse(string response)
        {
            try
            {
                var doc = XDocument.Parse(response);
                return doc.Root?.Element("version")?.Value ?? CurrentVersion;
            }
            catch
            {
                return CurrentVersion;
            }
        }

        private UpdateInfo? ParseUpdateInfo(string response)
        {
            try
            {
                var doc = XDocument.Parse(response);
                var root = doc.Root;
                
                if (root == null) return null;
                
                return new UpdateInfo
                {
                    Version = root.Element("version")?.Value ?? "",
                    DownloadUrl = root.Element("downloadUrl")?.Value ?? "",
                    ReleaseNotes = root.Element("releaseNotes")?.Value ?? "",
                    Checksum = root.Element("checksum")?.Value ?? "",
                    FileSize = long.TryParse(root.Element("fileSize")?.Value, out var size) ? size : 0
                };
            }
            catch
            {
                return null;
            }
        }

        private int CompareVersions(string version1, string version2)
        {
            var v1Parts = version1.Split('.');
            var v2Parts = version2.Split('.');
            
            var maxLength = Math.Max(v1Parts.Length, v2Parts.Length);
            
            for (int i = 0; i < maxLength; i++)
            {
                var v1 = i < v1Parts.Length && int.TryParse(v1Parts[i], out var n1) ? n1 : 0;
                var v2 = i < v2Parts.Length && int.TryParse(v2Parts[i], out var n2) ? n2 : 0;
                
                if (v1 > v2) return 1;
                if (v1 < v2) return -1;
            }
            
            return 0;
        }
    }

    public class UpdateInfo

    {
        public string Version { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string ReleaseNotes { get; set; } = "";
        public string Checksum { get; set; } = "";
        public long FileSize { get; set; }
    }
}
