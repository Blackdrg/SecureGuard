using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace SecureGuard.Core
{
    public class ThreatLogManager
    {
        private readonly string _logFilePath;
        private List<ThreatLogEntry> _entries;

        public ThreatLogManager()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard");
            Directory.CreateDirectory(appDataPath);
            _logFilePath = Path.Combine(appDataPath, "threats.json");
            _entries = LoadEntries();
        }

        private List<ThreatLogEntry> LoadEntries()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    var json = File.ReadAllText(_logFilePath);
                    return JsonConvert.DeserializeObject<List<ThreatLogEntry>>(json) ?? new List<ThreatLogEntry>();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load threat logs", ex);
            }
            return new List<ThreatLogEntry>();
        }

        private void SaveEntries()
        {
            try
            {
                var json = JsonConvert.SerializeObject(_entries, Formatting.Indented);
                File.WriteAllText(_logFilePath, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save threat logs", ex);
            }
        }

        public void AddEntry(ThreatLogEntry entry)
        {
            _entries.Insert(0, entry);
            // Keep only last 1000 entries
            if (_entries.Count > 1000)
            {
                _entries = _entries.Take(1000).ToList();
            }
            SaveEntries();
            Logger.Log("Info", $"Threat log entry added: {entry.ThreatName}");
        }

        public List<ThreatLogEntry> GetAllEntries()
        {
            return _entries.ToList();
        }

        public List<ThreatLogEntry> GetEntriesByDate(DateTime date)
        {
            return _entries.Where(e => e.Timestamp.Date == date.Date).ToList();
        }

        public int GetThreatCountToday()
        {
            return _entries.Count(e => e.Timestamp.Date == DateTime.Today);
        }

        public int GetThreatCountBySeverity(ThreatSeverity severity)
        {
            return _entries.Count(e => e.Severity == severity);
        }

        public void ClearOldEntries(int daysToKeep = 30)
        {
            var cutoffDate = DateTime.Today.AddDays(-daysToKeep);
            _entries = _entries.Where(e => e.Timestamp >= cutoffDate).ToList();
            SaveEntries();
        }

        public void ExportToCsv(string filePath)
        {
            try
            {
                var lines = new List<string>
                {
                    "Id,ThreatName,FilePath,Description,Severity,ActionTaken,Timestamp,DetectionMethod,FileHash,ProcessName"
                };

                foreach (var entry in _entries)
                {
                    lines.Add($"\"{entry.Id}\",\"{entry.ThreatName}\",\"{entry.FilePath}\",\"{entry.Description}\",{entry.Severity},{entry.ActionTaken},{entry.Timestamp:yyyy-MM-dd HH:mm:ss},\"{entry.DetectionMethod}\",\"{entry.FileHash}\",\"{entry.ProcessName}\"");
                }

                File.WriteAllLines(filePath, lines);
                Logger.Log("Info", $"Threat logs exported to: {filePath}");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to export threat logs", ex);
            }
        }
    }
}
