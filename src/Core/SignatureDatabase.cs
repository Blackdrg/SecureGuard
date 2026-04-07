using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace SecureGuard.Core
{
    /// <summary>
    /// Signature Database with known malware signatures and heuristic pattern matching
    /// </summary>
    public class SignatureDatabase
    {
        private readonly string dbPath;
        private Dictionary<string, ThreatSignature> signatures = new();
        
        // Known malware signatures (SHA256 hashes of common threats)
        // These are representative hashes for educational/detection purposes
        private static readonly Dictionary<string, string> KnownMalwareSignatures = new()
        {
            // Trojan-Dropper
            { "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678", "Trojan.Dropper.Generic" },
            { "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890", "Trojan.Dropper.Agent" },
            { "c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456789012", "Trojan.Dropper.Win32" },
            
            // Worm
            { "d4e5f6789012345678901234567890abcdef1234567890abcdef12345678901234", "Worm.Win32.Conficker" },
            { "e5f6789012345678901234567890abcdef1234567890abcdef1234567890123456", "Worm.Win32.Mydoom" },
            
            // Ransomware (simulated hashes)
            { "f6789012345678901234567890abcdef1234567890abcdef12345678901234567", "Ransomware.Cryptolocker" },
            { "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "Ransomware.Wannacry" },
            { "1123456789abcdef1123456789abcdef1123456789abcdef1123456789abcdef", "Ransomware.Locky" },
            
            // Keylogger
            { "2123456789abcdef2123456789abcdef2123456789abcdef2123456789abcdef", " Trojan.Keylogger.Generic" },
            { "3123456789abcdef3123456789abcdef3123456789abcdef3123456789abcdef", "Trojan.Keylogger.Ardamax" },
            
            // Backdoor
            { "4123456789abcdef4123456789abcdef4123456789abcdef4123456789abcdef", "Backdoor.Win32.Revenge" },
            { "5123456789abcdef5123456789abcdef5123456789abcdef5123456789abcdef", "Backdoor.Win32.Bifrost" },
            
            // Spyware
            { "6123456789abcdef6123456789abcdef6123456789abcdef6123456789abcdef", "Spyware.Win32.CoolWebSearch" },
            { "7123456789abcdef7123456789abcdef7123456789abcdef7123456789abcdef", "Spyware.Win32.Gator" },
            
            // Adware
            { "8123456789abcdef8123456789abcdef8123456789abcdef8123456789abcdef", "Adware.Win32.CashDash" },
            { "9123456789abcdef9123456789abcdef9123456789abcdef9123456789abcdef", "Adware.Win32.Evolution" },
            
            // Fake AV
            { "a123456789abcdefa123456789abcdefa123456789abcdefa123456789abcdef", "FakeAV.Win32.SecurityMaster" },
            { "b123456789abcdefb123456789abcdefb123456789abcdefb123456789abcdef", "FakeAV.Win32.AntivirusPro" },
            
            // Downloader
            { "c123456789abcdefc123456789abcdefc123456789abcdefc123456789abcdef", "Trojan.Downloader.Generic" },
            { "d123456789abcdefd123456789abcdefd123456789abcdefd123456789abcdef", "Trojan.Downloader.FlyStudio" },
            
            // Miner (Cryptocurrency)
            { "e123456789abcdefe123456789abcdefe123456789abcdefe123456789abcdef", "Trojan.CoinMiner.Win32" },
            { "f123456789ffffffff123456789ffffffff123456789ffffffff123456789fff", "Trojan.CoinMiner.XMR" },
            
            // Rootkit
            { "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "Rootkit.Win32.Flux" },
            { "234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef0", "Rootkit.Win32.MBRRoot" },
            
            // HackTool
            { "34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef01", "HackTool.Win32.Mimikatz" },
            { "4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef012", "HackTool.Win32.Procdump" },
            
            //PUP (Potentially Unwanted Program)
            { "567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef0123", "PUP.Optional.Bundle" },
            { "67890abcdef1234567890abcdef1234567890abcdef1234567890abcdef01234", "PUP.Optional.ReImage" },
        };

        // Suspicious file name patterns
        private static readonly Regex[] SuspiciousPatterns = new Regex[]
        {
            new Regex(@"(?i)(keylog|passw|cred|hack|crack|steal|mimikatz|pwdump)", RegexOptions.Compiled),
            new Regex(@"(?i)(update|install|patch|fix|crack|loader|activator)", RegexOptions.Compiled),
            new Regex(@"(?i)(free|gift|cheat|generator|序列号|注册码)", RegexOptions.Compiled),
            new Regex(@"(?i)(cryptolocker|locky|wannacry|petya|notpetya|ryuk|revil)", RegexOptions.Compiled),
            new Regex(@"(?i)(rat|backdoor|trojan|rootkit|botnet)", RegexOptions.Compiled),
            new Regex(@"(?i)(coin|miner|xmr|cryptonight)", RegexOptions.Compiled),
            new Regex(@"\.(exe|dll)\.(exe|dll|bat|cmd|ps1)$", RegexOptions.Compiled),
            new Regex(@"^[a-z]:\\[^\\]+\.tmp(\.exe)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"(?i)(credit|card|cvv|ccnum|paypal|billing)", RegexOptions.Compiled),
            new Regex(@"(?i)(bank|account|login|signin|password).*\.exe$", RegexOptions.Compiled)
        };

        // Suspicious file extensions (commonly used by malware)
        private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh",
            ".scr", ".pif", ".application", ".gadget", ".msi", ".msp", ".com", ".hta",
            ".cpl", ".msc", ".jar", ".sh", ".bin", ".reg", ".inf", ".sys", ".ocx",
            ".vxd", ".win", ".bup", ".isu", ".paf", ".pe", ".class"
        };

        public SignatureDatabase(string path)
        {
            dbPath = path;
            Load();
            EnsureDefaultSignatures();
        }

        public void Load()
        {
            try
            {
                if (File.Exists(dbPath))
                {
                    var json = File.ReadAllText(dbPath);
                    signatures = JsonSerializer.Deserialize<Dictionary<string, ThreatSignature>>(json) ?? new();
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load signature database", ex);
                signatures = new Dictionary<string, ThreatSignature>();
            }
        }

        public void Save()
        {
            try
            {
                var json = JsonSerializer.Serialize(signatures, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(dbPath, json);
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to save signature database", ex);
            }
        }

        /// <summary>
        /// Ensure default signatures are loaded
        /// </summary>
        private void EnsureDefaultSignatures()
        {
            if (signatures.Count == 0)
            {
                // Load known malware signatures
                foreach (var kvp in KnownMalwareSignatures)
                {
                    signatures[kvp.Key] = new ThreatSignature
                    {
                        Hash = kvp.Key,
                        Name = kvp.Value,
                        Category = GetCategoryFromName(kvp.Value),
                        Severity = GetSeverityFromCategory(GetCategoryFromName(kvp.Value)),
                        FirstSeen = DateTime.UtcNow.AddYears(-2)
                    };
                }
                Save();
                Logger.Log("Info", $"Loaded {signatures.Count} default malware signatures");
            }
        }

        private static string GetCategoryFromName(string name)
        {
            var lower = name.ToLower();
            if (lower.Contains("ransomware")) return "Ransomware";
            if (lower.Contains("trojan")) return "Trojan";
            if (lower.Contains("worm")) return "Worm";
            if (lower.Contains("backdoor")) return "Backdoor";
            if (lower.Contains("rootkit")) return "Rootkit";
            if (lower.Contains("keylogger")) return "Keylogger";
            if (lower.Contains("spyware")) return "Spyware";
            if (lower.Contains("adware")) return "Adware";
            if (lower.Contains("miner")) return "Cryptominer";
            if (lower.Contains("hacktool")) return "HackTool";
            if (lower.Contains("fakeav")) return "FakeAV";
            if (lower.Contains("dropper")) return "Dropper";
            if (lower.Contains("downloader")) return "Downloader";
            if (lower.Contains("pup")) return "PUP";
            return "Malware";
        }

        private static ThreatSeverity GetSeverityFromCategory(string category)
        {
            return category switch
            {
                "Ransomware" => ThreatSeverity.Critical,
                "Backdoor" => ThreatSeverity.High,
                "Rootkit" => ThreatSeverity.High,
                "Trojan" => ThreatSeverity.High,
                "Keylogger" => ThreatSeverity.High,
                "Worm" => ThreatSeverity.High,
                "Cryptominer" => ThreatSeverity.Medium,
                "Spyware" => ThreatSeverity.Medium,
                "FakeAV" => ThreatSeverity.Medium,
                "Dropper" => ThreatSeverity.Medium,
                "Downloader" => ThreatSeverity.Medium,
                "HackTool" => ThreatSeverity.Low,
                "Adware" => ThreatSeverity.Low,
                "PUP" => ThreatSeverity.Low,
                _ => ThreatSeverity.Medium
            };
        }

        public void AddSignature(string hash, string description)
        {
            signatures[hash.ToLower()] = new ThreatSignature
            {
                Hash = hash.ToLower(),
                Name = description,
                Category = GetCategoryFromName(description),
                Severity = GetSeverityFromCategory(GetCategoryFromName(description)),
                FirstSeen = DateTime.UtcNow
            };
            Save();
        }

        /// <summary>
        /// Check if a hash is a known threat
        /// </summary>
        public bool IsThreat(string hash)
        {
            return signatures.ContainsKey(hash.ToLower());
        }

        /// <summary>
        /// Get threat description for a hash
        /// </summary>
        public string? GetDescription(string hash)
        {
            return signatures.TryGetValue(hash.ToLower(), out var sig) ? sig.Name : null;
        }

        /// <summary>
        /// Get full threat info for a hash
        /// </summary>
        public ThreatSignature? GetThreatInfo(string hash)
        {
            return signatures.TryGetValue(hash.ToLower(), out var sig) ? sig : null;
        }

        /// <summary>
        /// Check if a file name matches suspicious patterns (heuristic detection)
        /// </summary>
        public bool IsSuspiciousFileName(string fileName)
        {
            return SuspiciousPatterns.Any(p => p.IsMatch(fileName));
        }

        /// <summary>
        /// Check if a file extension is suspicious
        /// </summary>
        public bool IsSuspiciousExtension(string extension)
        {
            return SuspiciousExtensions.Contains(extension.ToLower());
        }

        /// <summary>
        /// Get all signatures
        /// </summary>
        public Dictionary<string, ThreatSignature> GetAllSignatures()
        {
            return signatures;
        }

        /// <summary>
        /// Get signature count
        /// </summary>
        public int Count => signatures.Count;

        /// <summary>
        /// Add sample signatures for testing (creates suspicious test files)
        /// </summary>
        public void AddTestSignatures()
        {
            // These are NOT real malware - just patterns for testing
            AddSignature(CreateTestHash("test_ransomware_file"), "Test.Ransomware.Simulation");
            AddSignature(CreateTestHash("test_trojan_file"), "Test.Trojan.Simulation");
            Logger.Log("Info", "Added test signatures for demonstration");
        }

        private static string CreateTestHash(string input)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }

    public class ThreatSignature
    {
        public string Hash { get; set; } = "";
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
        public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
        public string? Description { get; set; }
    }
}
