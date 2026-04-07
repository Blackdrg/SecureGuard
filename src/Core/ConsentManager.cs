using System.Text.Json;
using System.IO;
using System;

namespace SecureGuard.Core
{
    [Flags]
    public enum ConsentType
    {
        None = 0,
        Telemetry = 1 << 0,
        Webcam = 1 << 1,
        Microphone = 1 << 2,
        KeyloggerProtection = 1 << 3,
        DarkWebMonitoring = 1 << 4,
        CloudSync = 1 << 5,
        All = 0xFFFFFFFF
    }

    public class ConsentRecord
    {
        public DateTime GrantedAt { get; set; }
        public ConsentType Types { get; set; }
        public bool IsEUUser { get; set; }
        public string UserId { get; set; } = "";
    }

    public class ConsentManager
    {
        private readonly string consentPath;
        private ConsentRecord? currentConsent;
        private readonly object lockObj = new();

        public ConsentManager(string appDataPath)
        {
            consentPath = Path.Combine(appDataPath, "user_consent.json");
            Load();
        }

        public void Load()
        {
            lock (lockObj)
            {
                if (!File.Exists(consentPath))
                {
                    currentConsent = null;
                    return;
                }

                try
                {
                    var json = File.ReadAllText(consentPath);
                    currentConsent = JsonSerializer.Deserialize<ConsentRecord>(json);
                }
                catch
                {
                    currentConsent = null;
                }
            }
        }

        public void Save()
        {
            lock (lockObj)
            {
                if (currentConsent != null)
                {
                    var json = JsonSerializer.Serialize(currentConsent, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(consentPath, json);
                }
            }
        }

        public bool HasConsent(ConsentType type)
        {
            return currentConsent != null && (currentConsent.Types & type) == type;
        }

        public void GrantConsent(ConsentType types, bool isEU = false)
        {
            lock (lockObj)
            {
                currentConsent = new ConsentRecord
                {
                    GrantedAt = DateTime.UtcNow,
                    Types = types,
                    IsEUUser = isEU,
                    UserId = Guid.NewGuid().ToString()
                };
                Save();
                Logger.Log("Info", $"Consent granted: {types} (EU: {isEU})");
            }
        }

        public void RevokeConsent(ConsentType type)
        {
            lock (lockObj)
            {
                if (currentConsent != null)
                {
                    currentConsent.Types &= ~type;
                    Save();
                    Logger.Log("Info", $"Consent revoked: {type}");
                }
            }
        }

        public ConsentRecord? GetCurrentConsent() => currentConsent;
    }
}

