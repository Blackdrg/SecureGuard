using System;
using System.IO;
using System.Text.Json;

namespace SecureGuard.Core
{
    public static class Logger
    {
        private static readonly string logPath;

        static Logger()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecureGuard", "logs");
            Directory.CreateDirectory(appDataPath);
            logPath = Path.Combine(appDataPath, "SecureGuard.log");
        }

        public static void Log(string level, string message, Exception? ex = null)
        {
            try
            {
                var entry = new
                {
                    Timestamp = DateTime.UtcNow,
                    Level = level,
                    Message = message,
                    Exception = ex?.ToString()
                };
                var json = JsonSerializer.Serialize(entry);
                File.AppendAllText(logPath, json + Environment.NewLine);
            }
            catch
            {
                // Fail silently to prevent infinite loops
            }
        }

        public static void Info(string message)
        {
            Log("INFO", message);
        }

        public static void Warning(string message)
        {
            Log("WARNING", message);
        }

        public static void Error(string message, Exception? ex = null)
        {
            Log("ERROR", message, ex);
        }

        public static void Debug(string message)
        {
            Log("DEBUG", message);
        }

        public static void Fatal(string message, Exception? ex = null)
        {
            Log("FATAL", message, ex);
        }
    }
}
