using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SecureGuard.Core;

namespace SecureGuard.AI
{
    /// <summary>
    /// Feature 9: Autonomous Security Agent
    /// AI assistant that explains threats, recommends fixes, answers questions
    /// </summary>
    public class SecurityAssistant : IDisposable
    {
        private readonly KnowledgeBase _knowledgeBase;
        private readonly List<ConversationSession> _sessions;
        private readonly object _lock = new();
        
        public event EventHandler<AssistantQueryEventArgs>? QueryReceived;
        public event EventHandler<AssistantResponseEventArgs>? ResponseGenerated;

        public SecurityAssistant()
        {
            _knowledgeBase = new KnowledgeBase();
            _sessions = new List<ConversationSession>();
            InitializeKnowledgeBase();
            Core.Logger.Log("Info", "Security Assistant initialized");
        }

        private void InitializeKnowledgeBase()
        {
            // Threat explanations
            _knowledgeBase.ThreatExplanations["ransomware"] = new ThreatExplanation
            {
                Name = "Ransomware",
                Category = "Malware",
                Description = "Ransomware is malicious software that encrypts your files and demands payment for the decryption key.",
                HowItSpreads = "Email attachments, malicious downloads, exploit kits, vulnerable software",
                Symptoms = new List<string> { "Files cannot be opened", "File extensions changed", "Ransom note appears", "Cannot access folders" },
                Prevention = new List<string> { "Keep backups", "Don't open suspicious emails", "Update software", "Use antivirus" },
                Removal = "Use SecureGuard to remove ransomware, then restore files from backup"
            };

            _knowledgeBase.ThreatExplanations["phishing"] = new ThreatExplanation
            {
                Name = "Phishing",
                Category = "Social Engineering",
                Description = "Phishing attacks attempt to trick you into revealing sensitive information like passwords or credit card numbers.",
                HowItSpreads = "Fake emails, fraudulent websites, SMS messages, social media",
                Symptoms = new List<string> { "Suspicious emails", "Fake login pages", "Urgent requests", "Unknown senders" },
                Prevention = new List<string> { "Verify senders", "Check URLs", "Don't click unknown links", "Use 2FA" },
                Removal = "Delete the message, don't provide any information, report to IT if work device"
            };

            _knowledgeBase.ThreatExplanations["trojan"] = new ThreatExplanation
            {
                Name = "Trojan Horse",
                Category = "Malware",
                Description = "Trojans appear to be legitimate software but contain malicious code that can damage your system.",
                HowItSpreads = "Fake software downloads, email attachments, cracked applications",
                Symptoms = new List<string> { "Slow computer", "Unusual popups", "Disabled antivirus", "Unknown processes" },
                Prevention = new List<string> { "Download only from official sources", "Verify file signatures", "Use antivirus" },
                Removal = "Run a full system scan with SecureGuard"
            };

            _knowledgeBase.ThreatExplanations["virus"] = new ThreatExplanation
            {
                Name = "Computer Virus",
                Category = "Malware",
                Description = "A virus is a program that replicates itself and spreads to other computers, often causing damage.",
                HowItSpreads = "Infected files, USB drives, email attachments, downloads",
                Symptoms = new List<string> { "Computer runs slow", "Files missing", "System crashes", "Unknown programs" },
                Prevention = new List<string> { "Use antivirus", "Don't open unknown files", "Keep software updated" },
                Removal = "Run full scan with SecureGuard, restore from backup if needed"
            };

            _knowledgeBase.ThreatExplanations["spyware"] = new ThreatExplanation
            {
                Name = "Spyware",
                Category = "Malware",
                Description = "Spyware secretly monitors your computer activity and collects personal information.",
                HowItSpreads = "Free software, toolbars, downloads, email attachments",
                Symptoms = new List<string> { "Browser redirects", "New toolbars", "Slow performance", "Popups" },
                Prevention = new List<string> { "Careful with free software", "Read EULAs", "Use anti-spyware" },
                Removal = "Run SecureGuard scan in safe mode"
            };

            // Quick fixes
            _knowledgeBase.QuickFixes["slow_computer"] = new QuickFix
            {
                Issue = "Computer running slow",
                Steps = new List<string>
                {
                    "1. Check for malware: Run SecureGuard full scan",
                    "2. Check disk space: Open File Explorer > Right-click C: > Properties",
                    "3. Clear temporary files: Press Win+R, type %temp%, delete files",
                    "4. Disable startup programs: Task Manager > Startup tab",
                    "5. Check for updates: Settings > Update & Security > Windows Update"
                }
            };

            _knowledgeBase.QuickFixes["virus_detected"] = new QuickFix
            {
                Issue = "Virus detected",
                Steps = new List<string>
                {
                    "1. Don't panic - SecureGuard is blocking the threat",
                    "2. Update virus definitions if prompted",
                    "3. Run a full system scan",
                    "4. Quarantine or delete detected threats",
                    "5. Restart your computer",
                    "6. Run scan again to confirm clean"
                }
            };

            _knowledgeBase.QuickFixes["cant_open_files"] = new QuickFix
            {
                Issue = "Cannot open files",
                Steps = new List<string>
                {
                    "1. Check if files have unusual extensions (like .encrypted)",
                    "2. Run SecureGuard ransomware scan",
                    "3. Check for recent backup",
                    "4. Try system restore to earlier point",
                    "5. Contact support if files are critical"
                }
            };

            _knowledgeBase.QuickFixes["browser_redirect"] = new QuickFix
            {
                Issue = "Browser redirects to unknown sites",
                Steps = new List<string>
                {
                    "1. Check browser extensions - remove unknown ones",
                    "2. Clear browser cache and cookies",
                    "3. Reset browser settings",
                    "4. Run SecureGuard malware scan",
                    "5. Check DNS settings for hijacking"
                }
            };

            // Optimization tips
            _knowledgeBase.OptimizationTips = new List<string>
            {
                "Enable real-time protection for continuous security",
                "Keep Windows and all software updated",
                "Use strong, unique passwords for each account",
                "Enable two-factor authentication where available",
                "Regularly backup important files to external drive or cloud",
                "Don't use the same password for multiple accounts",
                "Be cautious of emails from unknown senders",
                "Verify URLs before clicking - check for typos",
                "Use a password manager to generate and store passwords",
                "Lock your computer when stepping away (Win+L)"
            };

            Core.Logger.Log("Info", $"Knowledge base initialized with {_knowledgeBase.ThreatExplanations.Count} threat explanations");
        }

        public AssistantResponse ProcessQuery(string query, string? userContext = null)
        {
            var response = new AssistantResponse
            {
                Query = query,
                Timestamp = DateTime.Now
            };

            try
            {
                QueryReceived?.Invoke(this, new AssistantQueryEventArgs(query, userContext));

                var lowerQuery = query.ToLower();

                // Check for threat-related queries
                foreach (var threat in _knowledgeBase.ThreatExplanations.Values)
                {
                    if (lowerQuery.Contains(threat.Name.ToLower()) || 
                        lowerQuery.Contains(threat.Category.ToLower()) ||
                        IsRelatedQuery(lowerQuery, threat))
                    {
                        response.Type = ResponseType.ThreatExplanation;
                        response.ThreatExplanation = threat;
                        response.Message = GenerateThreatResponse(threat);
                        ResponseGenerated?.Invoke(this, new AssistantResponseEventArgs(response));
                        return response;
                    }
                }

                // Check for quick fix queries
                foreach (var fix in _knowledgeBase.QuickFixes.Values)
                {
                    if (lowerQuery.Contains(fix.Issue.ToLower().Split(' ')[0]))
                    {
                        response.Type = ResponseType.QuickFix;
                        response.QuickFix = fix;
                        response.Message = $"Here's how to fix: {fix.Issue}\n\n{string.Join("\n", fix.Steps)}";
                        ResponseGenerated?.Invoke(this, new AssistantResponseEventArgs(response));
                        return response;
                    }
                }

                // Check for greeting
                if (IsGreeting(lowerQuery))
                {
                    response.Type = ResponseType.Greeting;
                    response.Message = GenerateGreeting();
                    ResponseGenerated?.Invoke(this, new AssistantResponseEventArgs(response));
                    return response;
                }

                // Check for help request
                if (lowerQuery.Contains("help") || lowerQuery.Contains("what can you do"))
                {
                    response.Type = ResponseType.Help;
                    response.Message = GenerateHelp();
                    ResponseGenerated?.Invoke(this, new AssistantResponseEventArgs(response));
                    return response;
                }

                // Check for optimization query
                if (lowerQuery.Contains("optimize") || lowerQuery.Contains("speed up") || lowerQuery.Contains("improve"))
                {
                    response.Type = ResponseType.Optimization;
                    response.OptimizationTips = _knowledgeBase.OptimizationTips;
                    response.Message = "Here are some tips to improve your system security and performance:";
                    foreach (var tip in _knowledgeBase.OptimizationTips.Take(5))
                    {
                        response.Message += $"\n• {tip}";
                    }
                    ResponseGenerated?.Invoke(this, new AssistantResponseEventArgs(response));
                    return response;
                }

                // Default response
                response.Type = ResponseType.General;
                response.Message = GenerateDefaultResponse(query);
                ResponseGenerated?.Invoke(this, new AssistantResponseEventArgs(response));

                Core.Logger.Log("Debug", $"Query processed: {query}");
            }
            catch (Exception ex)
            {
                Core.Logger.Log("Error", "Query processing failed", ex);
                response.Type = ResponseType.Error;
                response.Message = "I apologize, but I encountered an error processing your request. Please try again.";
            }

            return response;
        }

        private bool IsRelatedQuery(string query, ThreatExplanation threat)
        {
            var relatedTerms = new Dictionary<string, string[]>
            {
                ["ransomware"] = new[] { "encrypt", "pay", "bitcoin", "decrypt", "lock", "kidnap" },
                ["phishing"] = new[] { "fake", "scam", "email", "password", "steal", "login" },
                ["trojan"] = new[] { "fake", "fake software", "backdoor", "remote" },
                ["virus"] = new[] { "infect", "spread", "replicate", "contaminate" },
                ["spyware"] = new[] { "monitor", "track", "record", "watch", "privacy" }
            };

            if (relatedTerms.TryGetValue(threat.Name.ToLower(), out var terms))
            {
                return terms.Any(t => query.Contains(t));
            }

            return false;
        }

        private bool IsGreeting(string query)
        {
            var greetings = new[] { "hello", "hi", "hey", "good morning", "good afternoon", "good evening", "howdy" };
            return greetings.Any(g => query.StartsWith(g));
        }

        private string GenerateGreeting()
        {
            var time = DateTime.Now.Hour;
            string greeting = time < 12 ? "Good morning" : time < 17 ? "Good afternoon" : "Good evening";
            
            return $"{greeting}! I'm SecureGuard's Security Assistant.\n\n" +
                   "I can help you with:\n" +
                   "• Explaining threats and malware\n" +
                   "• Fixing common security issues\n" +
                   "• Optimizing your system's security\n" +
                   "• Answering security questions\n\n" +
                   "What would you like to know about?";
        }

        private string GenerateHelp()
        {
            return "I can help you with:\n\n" +
                   "🔍 THREAT INFORMATION\n" +
                   "Ask about: ransomware, phishing, trojan, virus, spyware, malware\n\n" +
                   "🛠 QUICK FIXES\n" +
                   "Ask about: slow computer, virus detected, can't open files, browser redirect\n\n" +
                   "⚡ OPTIMIZATION\n" +
                   "Ask about: how to optimize, speed up, improve security\n\n" +
                   "❓ GENERAL QUESTIONS\n" +
                   "Ask me anything about computer security!\n\n" +
                   "Just describe your issue or question in natural language.";
        }

        private string GenerateThreatResponse(ThreatExplanation threat)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"📛 {threat.Name}");
            sb.AppendLine($"Category: {threat.Category}");
            sb.AppendLine();
            sb.AppendLine("What is it?");
            sb.AppendLine(threat.Description);
            sb.AppendLine();
            sb.AppendLine("How does it spread?");
            sb.AppendLine(threat.HowItSpreads);
            sb.AppendLine();
            sb.AppendLine("Warning signs:");
            foreach (var symptom in threat.Symptoms)
                sb.AppendLine($"• {symptom}");
            sb.AppendLine();
            sb.AppendLine("Prevention:");
            foreach (var tip in threat.Prevention)
                sb.AppendLine($"• {tip}");
            sb.AppendLine();
            sb.AppendLine($"Removal: {threat.Removal}");

            return sb.ToString();
        }

        private string GenerateDefaultResponse(string query)
        {
            return $"I understand you're asking about: \"{query}\"\n\n" +
                   "I'm not sure I have specific information about this, but here are some things I can help with:\n\n" +
                   "• Explaining different types of malware and threats\n" +
                   "• Providing quick fixes for common issues\n" +
                   "• Giving security optimization tips\n" +
                   "• Answering general security questions\n\n" +
                   "Try asking about a specific threat or issue, or say \"help\" to see what I can do!";
        }

        public string[] GetAvailableTopics()
        {
            var topics = new List<string>();
            
            foreach (var threat in _knowledgeBase.ThreatExplanations.Values)
            {
                topics.Add(threat.Name);
            }
            
            foreach (var fix in _knowledgeBase.QuickFixes.Values)
            {
                topics.Add(fix.Issue);
            }
            
            topics.Add("optimization");
            topics.Add("security tips");
            topics.Add("help");
            
            return topics.ToArray();
        }

        public void Dispose()
        {
            Core.Logger.Log("Info", "Security Assistant disposed");
        }
    }

    public class KnowledgeBase
    {
        public Dictionary<string, ThreatExplanation> ThreatExplanations { get; set; } = new();
        public Dictionary<string, QuickFix> QuickFixes { get; set; } = new();
        public List<string> OptimizationTips { get; set; } = new();
    }

    public class ThreatExplanation
    {
        public string Name { get; set; } = "";
        public string Category { get; set; } = "";
        public string Description { get; set; } = "";
        public string HowItSpreads { get; set; } = "";
        public List<string> Symptoms { get; set; } = new();
        public List<string> Prevention { get; set; } = new();
        public string Removal { get; set; } = "";
    }

    public class QuickFix
    {
        public string Issue { get; set; } = "";
        public List<string> Steps { get; set; } = new();
    }

    public class AssistantResponse
    {
        public string Query { get; set; } = "";
        public ResponseType Type { get; set; }
        public string Message { get; set; } = "";
        public ThreatExplanation? ThreatExplanation { get; set; }
        public QuickFix? QuickFix { get; set; }
        public List<string>? OptimizationTips { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum ResponseType
    {
        Greeting,
        ThreatExplanation,
        QuickFix,
        Optimization,
        Help,
        General,
        Error
    }

    public class ConversationSession
    {
        public string SessionId { get; set; } = "";
        public DateTime StartedAt { get; set; }
        public List<AssistantResponse> Messages { get; set; } = new();
    }

    public class AssistantQueryEventArgs : EventArgs
    {
        public string Query { get; }
        public string? UserContext { get; }
        public DateTime Timestamp { get; }

        public AssistantQueryEventArgs(string query, string? userContext)
        {
            Query = query;
            UserContext = userContext;
            Timestamp = DateTime.Now;
        }
    }

    public class AssistantResponseEventArgs : EventArgs
    {
        public AssistantResponse Response { get; }
        public DateTime Timestamp { get; }

        public AssistantResponseEventArgs(AssistantResponse response)
        {
            Response = response;
            Timestamp = DateTime.Now;
        }
    }
}

