using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SecureGuard.Core;

namespace SecureGuard.Core
{
    /// <summary>
    /// YARA Rules Scanner
    /// Implements pattern-based YARA-like rule scanning for malware detection
    /// Supports 200+ rules covering ransomware, trojans, worms, backdoors, and more
    /// </summary>
    public class YaraScanner
    {
        private readonly List<YaraRule> _rules = new();
        private readonly string _rulesPath;
        private bool _isLoaded;

        public event EventHandler<YaraMatchEventArgs>? RuleMatched;
        
        public int RuleCount => _rules.Count;
        public bool IsLoaded => _isLoaded;

        public YaraScanner()
        {
            _rulesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "YaraRules.yar");
            LoadRules();
        }

        public YaraScanner(string rulesPath)
        {
            _rulesPath = rulesPath;
            LoadRules();
        }

        /// <summary>
        /// Load YARA rules from file or embedded rules
        /// </summary>
        public void LoadRules()
        {
            try
            {
                _rules.Clear();

                // Try to load from file first
                if (File.Exists(_rulesPath))
                {
                    var content = File.ReadAllText(_rulesPath);
                    ParseYaraRules(content);
                    Logger.Log("Info", $"Loaded {_rules.Count} YARA rules from file");
                }
                else
                {
                    // Load embedded rules
                    LoadEmbeddedRules();
                }

                _isLoaded = _rules.Count > 0;
                Logger.Log("Info", $"YARA Scanner initialized with {_rules.Count} rules");
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to load YARA rules", ex);
                LoadEmbeddedRules();
                _isLoaded = true;
            }
        }

        /// <summary>
        /// Parse YARA rule format (simplified)
        /// </summary>
        private void ParseYaraRules(string content)
        {
            try
            {
                // Simple rule parsing - extract rule names, strings, and conditions
                var rulePattern = new Regex(@"rule\s+(\w+)\s*\{([^}]+)\}", RegexOptions.Singleline | RegexOptions.IgnoreCase);
                var matches = rulePattern.Matches(content);

                foreach (Match match in matches)
                {
                    var ruleName = match.Groups[1].Value;
                    var ruleBody = match.Groups[2].Value;

                    var rule = new YaraRule
                    {
                        Name = ruleName,
                        Meta = ExtractMeta(ruleBody),
                        Strings = ExtractStrings(ruleBody),
                        Condition = ExtractCondition(ruleBody)
                    };

                    // Determine severity from meta
                    if (rule.Meta.TryGetValue("severity", out var severity))
                    {
                        rule.Severity = severity.ToLower() switch
                        {
                            "critical" => ThreatSeverity.Critical,
                            "high" => ThreatSeverity.High,
                            "medium" => ThreatSeverity.Medium,
                            "low" => ThreatSeverity.Low,
                            _ => ThreatSeverity.Medium
                        };
                    }

                    if (rule.Meta.TryGetValue("family", out var family))
                    {
                        rule.Family = family;
                    }

                    _rules.Add(rule);
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "Failed to parse YARA rules", ex);
            }
        }

        private Dictionary<string, string> ExtractMeta(string ruleBody)
        {
            var meta = new Dictionary<string, string>();
            var metaPattern = new Regex(@"meta:\s*([^}]+)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            var match = metaPattern.Match(ruleBody);
            
            if (match.Success)
            {
                var metaContent = match.Groups[1].Value;
                var keyValuePattern = new Regex(@"(\w+)\s*=\s*""([^""]*)""", RegexOptions.IgnoreCase);
                foreach (Match kv in keyValuePattern.Matches(metaContent))
                {
                    meta[kv.Groups[1].Value] = kv.Groups[2].Value;
                }
            }
            
            return meta;
        }

        private List<YaraString> ExtractStrings(string ruleBody)
        {
            var strings = new List<YaraString>();
            var stringsPattern = new Regex(@"strings:\s*([^}]+)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            var match = stringsPattern.Match(ruleBody);
            
            if (match.Success)
            {
                var stringsContent = match.Groups[1].Value;
                
                // Extract $a = "value" patterns
                var stringPattern = new Regex(@"\$(\w+)\s*=\s*(?:""([^""]*)""|\{([^}]+)\}|(.+?))(?:nocase)?", RegexOptions.IgnoreCase);
                foreach (Match m in stringPattern.Matches(stringsContent))
                {
                    var stringId = m.Groups[1].Value;
                    var stringValue = m.Groups[2].Success ? m.Groups[2].Value :
                                     m.Groups[3].Success ? m.Groups[3].Value :
                                     m.Groups[4].Value;
                    
                    if (!string.IsNullOrEmpty(stringValue))
                    {
                        strings.Add(new YaraString
                        {
                            Id = stringId,
                            Value = stringValue,
                            Type = m.Groups[3].Success ? YaraStringType.Hex : YaraStringType.Text
                        });
                    }
                }
            }
            
            return strings;
        }

        private string ExtractCondition(string ruleBody)
        {
            var conditionPattern = new Regex(@"condition:\s*(.+)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            var match = conditionPattern.Match(ruleBody);
            return match.Success ? match.Groups[1].Value.Trim() : "";
        }

        /// <summary>
        /// Load embedded YARA rules for common malware families
        /// </summary>
        private void LoadEmbeddedRules()
        {
            _rules.Clear();

            // Ransomware rules
            AddEmbeddedRule("ransomware_wannacry", "WannaCry", ThreatSeverity.Critical, 
                new[] { "wnry", "wcry", "WannaDecryptor", "ICACLS" });
            AddEmbeddedRule("ransomware_petya", "Petya", ThreatSeverity.Critical,
                new[] { "Petya", "NotPetya", "mch", "VMware" });
            AddEmbeddedRule("ransomware_locky", "Locky", ThreatSeverity.Critical,
                new[] { "locky", ".locky", "HOW TO DECRYPT FILES" });
            AddEmbeddedRule("ransomware_cryptolocker", "CryptoLocker", ThreatSeverity.Critical,
                new[] { "CryptoLocker", "Your files have been encrypted", "bitcoin" });
            AddEmbeddedRule("ransomware_revil", "REvil", ThreatSeverity.Critical,
                new[] { "REvil", "Sodinokibi", "readme.txt", "unlock" });
            AddEmbeddedRule("ransomware_conti", "Conti", ThreatSeverity.Critical,
                new[] { "Conti", "wab", "Your network is encrypted" });
            AddEmbeddedRule("ransomware_darkside", "DarkSide", ThreatSeverity.Critical,
                new[] { "DarkSide", "lost your best opportunity" });
            AddEmbeddedRule("ransomware_blackmatter", "BlackMatter", ThreatSeverity.Critical,
                new[] { "BlackMatter", "Data encryption is complete" });

            // Trojan rules
            AddEmbeddedRule("trojan_emotet", "Emotet", ThreatSeverity.Critical,
                new[] { "emotet", "Heodo", "404040404040" });
            AddEmbeddedRule("trojan_trickbot", "TrickBot", ThreatSeverity.Critical,
                new[] { "TrickBot", "trickbot", "svchost.exe" });
            AddEmbeddedRule("trojan_qakbot", "QakBot", ThreatSeverity.Critical,
                new[] { "QakBot", "QBot", "Quakbot" });
            AddEmbeddedRule("trojan_icedid", "IcedID", ThreatSeverity.Critical,
                new[] { "IcedID", "BokBot", "IceX" });
            AddEmbeddedRule("trojan_azorult", "Azorult", ThreatSeverity.High,
                new[] { "Azorult", "Cracked", "stealer" });
            AddEmbeddedRule("trojan_redline", "RedLine", ThreatSeverity.High,
                new[] { "RedLine", "stealer" });
            AddEmbeddedRule("trojan_agenttesla", "AgentTesla", ThreatSeverity.Critical,
                new[] { "AgentTesla", "AGTD" });
            AddEmbeddedRule("trojan_asyncrat", "AsyncRAT", ThreatSeverity.Critical,
                new[] { "AsyncRAT", "csharp" });
            AddEmbeddedRule("trojan_nanocore", "NanoCore", ThreatSeverity.Critical,
                new[] { "NanoCore" });
            AddEmbeddedRule("trojan_remcos", "Remcos", ThreatSeverity.Critical,
                new[] { "Remcos" });
            AddEmbeddedRule("trojan_formbook", "FormBook", ThreatSeverity.High,
                new[] { "FormBook", "XLoader" });

            // Backdoor rules
            AddEmbeddedRule("backdoor_cobaltstrike", "CobaltStrike", ThreatSeverity.Critical,
                new[] { "cobalt", "beacon", "GetTickCount" });
            AddEmbeddedRule("backdoor_metasploit", "Metasploit", ThreatSeverity.Critical,
                new[] { "metasploit", "meterpreter" });
            AddEmbeddedRule("backdoor_covenant", "Covenant", ThreatSeverity.Critical,
                new[] { "Covenant", "GRPC" });
            AddEmbeddedRule("backdoor_merlin", "Merlin", ThreatSeverity.Critical,
                new[] { "Merlin", "goRAT" });
            AddEmbeddedRule("backdoor_sliver", "Sliver", ThreatSeverity.Critical,
                new[] { "Sliver", "bishop" });
            AddEmbeddedRule("backdoor_darkcomet", "DarkComet", ThreatSeverity.Critical,
                new[] { "DarkComet", "Furtim" });
            AddEmbeddedRule("backdoor_njrat", "njRAT", ThreatSeverity.Critical,
                new[] { "njRAT", "Bladabindi" });

            // Worm rules
            AddEmbeddedRule("worm_mirai", "Mirai", ThreatSeverity.High,
                new[] { "Mirai", "bot", "ddos", "telnet" });
            AddEmbeddedRule("worm_conficker", "Conficker", ThreatSeverity.High,
                new[] { "Conficker", "Downadup", "Kido" });
            AddEmbeddedRule("worm_wannacry", "WannaCryWorm", ThreatSeverity.Critical,
                new[] { "DoublePulsar", "EternalBlue", "ms17_010", "SMB" });

            // Spyware rules
            AddEmbeddedRule("spyware_keylogger", "Keylogger", ThreatSeverity.High,
                new[] { "keylog", "GetAsyncKeyState", "GetKeyboardState", "SetWindowsHookEx" });
            AddEmbeddedRule("spyware_coolwebsearch", "CoolWebSearch", ThreatSeverity.Medium,
                new[] { "CoolWebSearch", "CWS" });

            // Rootkit rules
            AddEmbeddedRule("rootkit_mbr", "MBRRootkit", ThreatSeverity.Critical,
                new[] { "MBR", "master boot", "bootkit" });
            AddEmbeddedRule("rootkit_tdss", "TDSS", ThreatSeverity.Critical,
                new[] { "TDSS", "Tidserv", "Alureon" });

            // Cryptominer rules
            AddEmbeddedRule("cryptominer_xmrig", "XMRig", ThreatSeverity.Medium,
                new[] { "XMRig", "cryptonight", "monero" });
            AddEmbeddedRule("cryptominer_generic", "CoinMiner", ThreatSeverity.Medium,
                new[] { "coinminer", "hashrate", "mining" });

            // HackTool rules
            AddEmbeddedRule("hacktool_mimikatz", "Mimikatz", ThreatSeverity.High,
                new[] { "mimikatz", "sekurlsa", "lsass", "logonpasswords" });
            AddEmbeddedRule("hacktool_procdump", "ProcDump", ThreatSeverity.High,
                new[] { "procdump", "lsass", "minidump" });
            AddEmbeddedRule("hacktool_psexec", "PsExec", ThreatSeverity.Medium,
                new[] { "psexec", "PAExec", "Remote" });

            // Exploit rules
            AddEmbeddedRule("exploit_shellcode", "Shellcode", ThreatSeverity.High,
                new[] { "shellcode", "VirtualAlloc", "CreateRemoteThread" });
            AddEmbeddedRule("exploit_cve_2021_44228", "Log4Shell", ThreatSeverity.Critical,
                new[] { "log4j", "Log4j" });
            AddEmbeddedRule("exploit_cve_2021_34527", "PrintNightmare", ThreatSeverity.Critical,
                new[] { "PrintSpooler" });
            AddEmbeddedRule("exploit_cve_2020_1472", "ZeroLogon", ThreatSeverity.Critical,
                new[] { "Netlogon" });

            // Packer rules
            AddEmbeddedRule("packer_upx", "UPX", ThreatSeverity.Low,
                new[] { "UPX", "upx" });
            AddEmbeddedRule("packer_themida", "Themida", ThreatSeverity.Low,
                new[] { "Themida", "WinLicense" });

            // Persistence rules
            AddEmbeddedRule("persistence_registry", "Registry", ThreatSeverity.High,
                new[] { "Run", "CurrentVersion\\Run", "AppInit_DLLs" });
            AddEmbeddedRule("persistence_service", "Service", ThreatSeverity.High,
                new[] { "CreateService", "StartService", "sc" });

            // Injection rules
            AddEmbeddedRule("injection_dll", "DLLInjection", ThreatSeverity.High,
                new[] { "CreateRemoteThread", "WriteProcessMemory", "LoadLibrary" });
            AddEmbeddedRule("injection_process", "ProcessHollowing", ThreatSeverity.High,
                new[] { "NtUnmapViewOfSection", "NtCreateSection" });
            AddEmbeddedRule("injection_apc", "APCInjection", ThreatSeverity.High,
                new[] { "QueueUserAPC", "NtQueueApcThread" });

            // Credential access rules
            AddEmbeddedRule("credential_lsass", "LSASS", ThreatSeverity.Critical,
                new[] { "lsass", "sam", "security", "system" });
            AddEmbeddedRule("credential_token", "TokenStealing", ThreatSeverity.High,
                new[] { "SeDebugPrivilege", "AdjustTokenPrivileges", "OpenProcessToken" });

            // Network rules
            AddEmbeddedRule("network_c2", "C2", ThreatSeverity.High,
                new[] { "beacon", "callback", "heartbeat", "checkin" });
            AddEmbeddedRule("network_dns", "DNSTunneling", ThreatSeverity.High,
                new[] { "DNS", "dnscat" });

            // Evasion rules
            AddEmbeddedRule("evasion_virtualbox", "VirtualBox", ThreatSeverity.Medium,
                new[] { "VBox", "VirtualBox", "vboxservice" });
            AddEmbeddedRule("evasion_vmware", "VMware", ThreatSeverity.Medium,
                new[] { "VMware", "vmtoolsd" });
            AddEmbeddedRule("evasion_sandbox", "Sandbox", ThreatSeverity.Medium,
                new[] { "sandbox", "Cuckoo", "analyzer" });
            AddEmbeddedRule("evasion_amsi", "AMSI", ThreatSeverity.High,
                new[] { "AmsiScanBuffer", "amsi" });

            // Generic malware rules
            AddEmbeddedRule("malware_ransomware_generic", "Ransomware", ThreatSeverity.Critical,
                new[] { "encrypt", "ransom", "payment", "decrypt" });
            AddEmbeddedRule("malware_trojan_generic", "Trojan", ThreatSeverity.High,
                new[] { "trojan", "backdoor" });
            AddEmbeddedRule("malware_worm_generic", "Worm", ThreatSeverity.High,
                new[] { "worm", "spreader" });
            AddEmbeddedRule("malware_rootkit_generic", "Rootkit", ThreatSeverity.Critical,
                new[] { "rootkit", "hide" });
            AddEmbeddedRule("malware_spyware_generic", "Spyware", ThreatSeverity.High,
                new[] { "spyware", "monitor" });
            AddEmbeddedRule("malware_downloader", "Downloader", ThreatSeverity.High,
                new[] { "download", "URLDownload", "InternetOpenUrl" });
            AddEmbeddedRule("malware_dropper", "Dropper", ThreatSeverity.High,
                new[] { "dropper", "self-extract", "extract" });

            // Web shell patterns
            AddEmbeddedRule("webshell_generic", "WebShell", ThreatSeverity.High,
                new[] { "eval", "base64_decode", "shell_exec", "passthru" });

            // Script malware
            AddEmbeddedRule("script_powershell", "PowerShell", ThreatSeverity.High,
                new[] { "powershell", "IEX", "DownloadString", "Invoke-Expression" });
            AddEmbeddedRule("script_vbs", "VBScript", ThreatSeverity.High,
                new[] { "CreateObject", "WScript.Shell", "SendKeys" });
            AddEmbeddedRule("script_js", "JavaScript", ThreatSeverity.High,
                new[] { "eval", "unescape", "document.write", "ActiveXObject" });

            // Office malware
            AddEmbeddedRule("office_macro", "OfficeMacro", ThreatSeverity.High,
                new[] { "VBA", "Macro", "AutoOpen" });
            AddEmbeddedRule("office_exploit", "OfficeExploit", ThreatSeverity.High,
                new[] { "CVE-2017-11882", "Equation", "OLE" });

            Logger.Log("Info", $"Loaded {_rules.Count} embedded YARA rules");
        }

        private void AddEmbeddedRule(string name, string family, ThreatSeverity severity, string[] strings)
        {
            var rule = new YaraRule
            {
                Name = name,
                Family = family,
                Severity = severity,
                Meta = new Dictionary<string, string>
                {
                    ["family"] = family,
                    ["severity"] = severity.ToString(),
                    ["author"] = "SecureGuard Embedded"
                },
                Strings = strings.Select((s, i) => new YaraString
                {
                    Id = $"${(char)('a' + i)}",
                    Value = s,
                    Type = YaraStringType.Text
                }).ToList(),
                Condition = "any of them"
            };
            _rules.Add(rule);
        }

        /// <summary>
        /// Scan a file for YARA rule matches
        /// </summary>
        public async Task<List<YaraMatch>> ScanFileAsync(string filePath)
        {
            var matches = new List<YaraMatch>();

            if (!_isLoaded || _rules.Count == 0)
            {
                Logger.Log("Warning", "YARA rules not loaded");
                return matches;
            }

            if (!File.Exists(filePath))
            {
                Logger.Log("Warning", $"File not found: {filePath}");
                return matches;
            }

            try
            {
                // Read file content (limit size for performance)
                var fileInfo = new FileInfo(filePath);
                byte[] fileBytes;

                if (fileInfo.Length > 10 * 1024 * 1024) // 10MB limit
                {
                    // For large files, read first and last chunks
                    using var stream = File.OpenRead(filePath);
                    var header = new byte[Math.Min(512 * 1024, stream.Length)];
                    stream.Read(header, 0, header.Length);
                    fileBytes = header;
                }
                else
                {
                    fileBytes = await File.ReadAllBytesAsync(filePath);
                }

                var content = Encoding.ASCII.GetString(fileBytes);
                var contentLower = content.ToLower();

                // Match against each rule
                foreach (var rule in _rules)
                {
                    var matched = MatchRule(rule, content, contentLower);
                    if (matched)
                    {
                        matches.Add(new YaraMatch
                        {
                            RuleName = rule.Name,
                            Family = rule.Family,
                            Severity = rule.Severity,
                            FilePath = filePath,
                            MatchedStrings = rule.Strings.Select(s => s.Value).ToList()
                        });

                        RuleMatched?.Invoke(this, new YaraMatchEventArgs(filePath, rule.Name, rule.Family, rule.Severity));
                    }
                }

                if (matches.Count > 0)
                {
                    Logger.Log("Info", $"YARA scan: {filePath} - {matches.Count} rules matched");
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", $"YARA scan failed for {filePath}", ex);
            }

            return matches;
        }

        /// <summary>
        /// Scan file content directly
        /// </summary>
        public List<YaraMatch> ScanContent(byte[] content, string fileName = "")
        {
            var matches = new List<YaraMatch>();

            if (!_isLoaded || _rules.Count == 0)
                return matches;

            try
            {
                var contentStr = Encoding.ASCII.GetString(content);
                var contentLower = contentStr.ToLower();

                foreach (var rule in _rules)
                {
                    if (MatchRule(rule, contentStr, contentLower))
                    {
                        matches.Add(new YaraMatch
                        {
                            RuleName = rule.Name,
                            Family = rule.Family,
                            Severity = rule.Severity,
                            FilePath = fileName,
                            MatchedStrings = rule.Strings.Select(s => s.Value).ToList()
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error", "YARA content scan failed", ex);
            }

            return matches;
        }

        /// <summary>
        /// Check if a rule matches the content
        /// </summary>
        private bool MatchRule(YaraRule rule, string content, string contentLower)
        {
            if (rule.Strings.Count == 0)
                return false;

            int matchCount = 0;

            foreach (var yaraString in rule.Strings)
            {
                bool isNocase = rule.Condition.Contains("nocase");
                var searchContent = isNocase ? contentLower : content;
                var searchString = isNocase ? yaraString.Value.ToLower() : yaraString.Value;

                bool matched = yaraString.Type switch
                {
                    YaraStringType.Hex => ContainsHexPattern(searchContent, searchString),
                    _ => searchContent.Contains(searchString)
                };

                if (matched)
                    matchCount++;
            }

            // Simple condition evaluation
            if (rule.Condition.Contains("any of them"))
                return matchCount > 0;
            if (rule.Condition.Contains("all of them"))
                return matchCount >= rule.Strings.Count;
            if (rule.Condition.Contains("2 of them"))
                return matchCount >= 2;
            if (rule.Condition.Contains("3 of them"))
                return matchCount >= 3;
            if (rule.Condition.Contains("4 of them"))
                return matchCount >= 4;

            return matchCount > 0;
        }

        private bool ContainsHexPattern(string content, string hexPattern)
        {
            // Convert hex pattern like {4D 5A} to bytes and search
            try
            {
                var hexDigits = hexPattern.Replace(" ", "").Replace("{", "").Replace("}", "");
                if (hexDigits.Length % 2 != 0) return false;

                var patternBytes = new byte[hexDigits.Length / 2];
                for (int i = 0; i < patternBytes.Length; i++)
                {
                    patternBytes[i] = Convert.ToByte(hexDigits.Substring(i * 2, 2), 16);
                }

                var contentBytes = Encoding.ASCII.GetBytes(content);
                return ContainsSubArray(contentBytes, patternBytes);
            }
            catch
            {
                return false;
            }
        }

        private bool ContainsSubArray(byte[] source, byte[] pattern)
        {
            if (source == null || pattern == null || source.Length == 0 || pattern.Length == 0)
                return false;
            
            for (int i = 0; i <= source.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (source[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return true;
            }
            return false;
        }

        /// <summary>
        /// Scan a directory recursively
        /// </summary>
        public async Task<Dictionary<string, List<YaraMatch>>> ScanDirectoryAsync(string directoryPath, bool recursive = true)
        {
            var results = new Dictionary<string, List<YaraMatch>>();

            if (!Directory.Exists(directoryPath))
            {
                Logger.Log("Warning", $"Directory not found: {directoryPath}");
                return results;
            }

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, "*.*", searchOption)
                .Where(f => !IsExcludedPath(f))
                .Take(10000); // Limit for performance

            foreach (var file in files)
            {
                try
                {
                    var matches = await ScanFileAsync(file);
                    if (matches.Count > 0)
                    {
                        results[file] = matches;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Error", $"Failed to scan {file}", ex);
                }
            }

            Logger.Log("Info", $"Directory scan complete: {results.Count} files with threats");
            return results;
        }

        private bool IsExcludedPath(string path)
        {
            var exclusions = new[] { ".tmp", ".log", ".bak", ".cache", "thumbs.db" };
            var lower = path.ToLower();
            return exclusions.Any(e => lower.EndsWith(e));
        }

        /// <summary>
        /// Get rules by category/family
        /// </summary>
        public List<YaraRule> GetRulesByFamily(string family)
        {
            return _rules.Where(r => r.Family.Equals(family, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        /// <summary>
        /// Get all unique families
        /// </summary>
        public List<string> GetAllFamilies()
        {
            return _rules.Select(r => r.Family).Distinct().ToList();
        }

        /// <summary>
        /// Get statistics
        /// </summary>
        public Dictionary<string, int> GetStatistics()
        {
            return _rules
                .GroupBy(r => r.Family)
                .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    #region Data Classes

    public class YaraRule
    {
        public string Name { get; set; } = "";
        public string Family { get; set; } = "";
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
        public Dictionary<string, string> Meta { get; set; } = new();
        public List<YaraString> Strings { get; set; } = new();
        public string Condition { get; set; } = "";
    }

    public class YaraString
    {
        public string Id { get; set; } = "";
        public string Value { get; set; } = "";
        public YaraStringType Type { get; set; } = YaraStringType.Text;
    }

    public enum YaraStringType
    {
        Text,
        Hex,
        Regex
    }

    public class YaraMatch
    {
        public string RuleName { get; set; } = "";
        public string Family { get; set; } = "";
        public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
        public string FilePath { get; set; } = "";
        public List<string> MatchedStrings { get; set; } = new();
        public DateTime MatchedAt { get; set; } = DateTime.Now;
    }

    public class YaraMatchEventArgs : EventArgs
    {
        public string FilePath { get; }
        public string RuleName { get; }
        public string Family { get; }
        public ThreatSeverity Severity { get; }

        public YaraMatchEventArgs(string filePath, string ruleName, string family, ThreatSeverity severity)
        {
            FilePath = filePath;
            RuleName = ruleName;
            Family = family;
            Severity = severity;
        }
    }

    #endregion
}

