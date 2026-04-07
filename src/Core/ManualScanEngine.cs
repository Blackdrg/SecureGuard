using System;
using System.Collections.Generic;
using System.IO;

namespace SecureGuard.Core
{
    public class ManualScanEngine
    {
        private readonly SignatureDatabase signatureDb;
        private readonly ScanExclusions exclusions;
        private readonly QuarantineManager quarantine;

        public ManualScanEngine(SignatureDatabase db, ScanExclusions excl, QuarantineManager quarantineManager)
        {
            signatureDb = db;
            exclusions = excl;
            quarantine = quarantineManager;
        }

        public List<string> ScanFolder(string folderPath)
        {
            var threats = new List<string>();
            foreach (var file in Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories))
            {
                if (exclusions.IsExcluded(file)) continue;
                var hash = Hashing.ComputeSHA256(file);
                if (signatureDb.IsThreat(hash))
                {
                    threats.Add(file);
                    quarantine.QuarantineFile(file);
                }
            }
            return threats;
        }
    }
}
