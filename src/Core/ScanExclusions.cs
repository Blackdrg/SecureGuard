using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace SecureGuard.Core
{
    public class ScanExclusions
    {
        private readonly string exclusionsPath;
        private HashSet<string> exclusions = new();

        public ScanExclusions(string path)
        {
            exclusionsPath = path;
            Load();
        }

        public void Load()
        {
            if (File.Exists(exclusionsPath))
            {
                var json = File.ReadAllText(exclusionsPath);
                exclusions = JsonSerializer.Deserialize<HashSet<string>>(json) ?? new();
            }
        }

        public void Save()
        {
            var json = JsonSerializer.Serialize(exclusions);
            File.WriteAllText(exclusionsPath, json);
        }

        public void Add(string path)
        {
            exclusions.Add(path);
            Save();
        }

        public void Remove(string path)
        {
            exclusions.Remove(path);
            Save();
        }

        public bool IsExcluded(string path)
        {
            return exclusions.Contains(path);
        }

        public IEnumerable<string> List() => exclusions;
    }
}
