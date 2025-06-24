using System.Collections.Generic;

namespace DomainDetective.PowerShell {
    internal static class OutputHelper {
        public static IEnumerable<DkimRecordInfo> Convert(DkimAnalysis analysis) {
            foreach (var kvp in analysis.AnalysisResults) {
                var result = kvp.Value;
                yield return new DkimRecordInfo {
                    Selector = kvp.Key,
                    Name = result.Name,
                    DkimRecord = result.DkimRecord,
                    DkimRecordExists = result.DkimRecordExists,
                    StartsCorrectly = result.StartsCorrectly,
                    PublicKeyExists = result.PublicKeyExists,
                    KeyTypeExists = result.KeyTypeExists,
                    PublicKey = result.PublicKey,
                    ServiceType = result.ServiceType,
                    Flags = result.Flags,
                    KeyType = result.KeyType,
                    HashAlgorithm = result.HashAlgorithm
                };
            }
        }
    }

    public class DkimRecordInfo {
        public string Selector { get; set; }
        public string Name { get; set; }
        public string DkimRecord { get; set; }
        public bool DkimRecordExists { get; set; }
        public bool StartsCorrectly { get; set; }
        public bool PublicKeyExists { get; set; }
        public bool KeyTypeExists { get; set; }
        public string PublicKey { get; set; }
        public string ServiceType { get; set; }
        public string Flags { get; set; }
        public string KeyType { get; set; }
        public string HashAlgorithm { get; set; }
    }
}
