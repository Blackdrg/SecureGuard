using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace SecureGuard.Core
{
    /// <summary>
    /// Quarantine metadata for tracking quarantined files
    /// </summary>
    public class QuarantineItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string OriginalPath { get; set; } = "";
        public string QuarantinedPath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string ThreatName { get; set; } = "";
        public DateTime QuarantinedDate { get; set; } = DateTime.Now;
        public long FileSize { get; set; }
        public string FileHash { get; set; } = "";
        public string Status { get; set; } = "Quarantined";
    }

    public class QuarantineManager
    {
        private readonly string quarantineFolder;
        private readonly string metadataPath;
        private List<QuarantineItem> quarantineItems;

        public QuarantineManager(string folder)
        {
            quarantineFolder = folder;
            metadataPath = Path.Combine(folder, "quarantine_metadata.json");
            Directory.CreateDirectory(quarantineFolder);
            quarantineItems = LoadMetadata();
        }

        private List<QuarantineItem> LoadMetadata()
        {
            try
            {
                if (File.Exists(metadataPath))
                {
                    var json = File.ReadAllText(metadataPath);
                    return JsonConvert.DeserializeObject<List<QuarantineItem>>(json) ?? new List<QuarantineItem>();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load quarantine metadata", ex);
            }
            return new List<QuarantineItem>();
        }

        private void SaveMetadata()
        {
            try
            {
                var json = JsonConvert.SerializeObject(quarantineItems, Formatting.Indented);
                File.WriteAllText(metadataPath, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save quarantine metadata", ex);
            }
        }

        /// <summary>
        /// Quarantine a file with full metadata tracking
        /// </summary>
        public void QuarantineFile(string filePath, string threatName = "Unknown Threat")
        {
            if (!File.Exists(filePath)) return;

            var fileName = Path.GetFileName(filePath);
            var uniqueName = $"{Guid.NewGuid()}_{fileName}";
            var destPath = Path.Combine(quarantineFolder, uniqueName);

            // Move file to quarantine
            File.Move(filePath, destPath, true);

            // Create metadata
            var item = new QuarantineItem
            {
                OriginalPath = filePath,
                QuarantinedPath = destPath,
                FileName = fileName,
                ThreatName = threatName,
                QuarantinedDate = DateTime.Now,
                FileSize = new FileInfo(destPath).Length,
                FileHash = Hashing.ComputeSHA256(destPath),
                Status = "Quarantined"
            };

            quarantineItems.Add(item);
            SaveMetadata();

            Logger.Log("Info", $"File quarantined: {filePath} - {threatName}");
        }

        /// <summary>
        /// List all quarantined files with metadata
        /// </summary>
        public List<QuarantineItem> ListQuarantinedFiles()
        {
            // Clean up any items where file no longer exists
            quarantineItems.RemoveAll(item => !File.Exists(item.QuarantinedPath));
            SaveMetadata();
            return quarantineItems;
        }

        /// <summary>
        /// Get a specific quarantined item by ID
        /// </summary>
        public QuarantineItem? GetQuarantineItem(string id)
        {
            return quarantineItems.Find(item => item.Id == id);
        }

        /// <summary>
        /// Restore a quarantined file to its original location
        /// </summary>
        public bool RestoreFile(string id)
        {
            var item = quarantineItems.Find(i => i.Id == id);
            if (item == null || !File.Exists(item.QuarantinedPath))
                return false;

            try
            {
                // Ensure original directory exists
                var originalDir = Path.GetDirectoryName(item.OriginalPath);
                if (!string.IsNullOrEmpty(originalDir) && !Directory.Exists(originalDir))
                {
                    Directory.CreateDirectory(originalDir);
                }

                // Move back to original location
                File.Move(item.QuarantinedPath, item.OriginalPath, true);
                item.Status = "Restored";
                SaveMetadata();

                Logger.Log("Info", $"File restored: {item.OriginalPath}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Failed to restore file: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Permanently delete a quarantined file
        /// </summary>
        public bool DeleteFile(string id)
        {
            var item = quarantineItems.Find(i => i.Id == id);
            if (item == null) return false;

            try
            {
                SecureDelete(item.QuarantinedPath);
                quarantineItems.Remove(item);
                SaveMetadata();

                Logger.Log("Info", $"Quarantined file deleted: {item.FileName}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"Failed to delete quarantined file: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Delete all quarantined files
        /// </summary>
        public void DeleteAll()
        {
            foreach (var item in quarantineItems)
            {
                try
                {
                    if (File.Exists(item.QuarantinedPath))
                        SecureDelete(item.QuarantinedPath);
                }
                catch { }
            }
            quarantineItems.Clear();
            SaveMetadata();
            Logger.Log("Info", "All quarantined files deleted");
        }

        /// <summary>
        /// Get count of quarantined files
        /// </summary>
        public int Count => quarantineItems.Count;

        /// <summary>
        /// Securely delete a file by overwriting with random data
        /// </summary>
        public void SecureDelete(string filePath)
        {
            if (File.Exists(filePath))
            {
                var length = new FileInfo(filePath).Length;
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    var random = new byte[4096];
                    RandomNumberGenerator.Fill(random);
                    long written = 0;
                    while (written < length)
                    {
                        stream.Write(random, 0, (int)System.Math.Min(random.Length, length - written));
                        written += 4096;
                    }
                }
                File.Delete(filePath);
            }
        }
    }
}
