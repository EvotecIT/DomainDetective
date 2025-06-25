using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    ///     Converts analysis results into simple data objects.
    /// </summary>
    public static partial class OutputHelper {
        /// <summary>
        ///     Converts DKIM analysis results into <see cref="DkimRecordInfo"/> objects.
        /// </summary>
        /// <param name="analysis">Analysis to convert.</param>
        /// <returns>Enumerable of record information.</returns>
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

    /// <summary>
    ///     Data object representing a single DKIM record.
    /// </summary>
    public class DkimRecordInfo {
        /// <summary>Selector used for the record.</summary>
        public string Selector { get; set; }
        /// <summary>Fully qualified domain name of the record.</summary>
        public string Name { get; set; }
        /// <summary>Raw DKIM record text.</summary>
        public string DkimRecord { get; set; }
        /// <summary>Indicates whether a DKIM record exists.</summary>
        public bool DkimRecordExists { get; set; }
        /// <summary>True when the record begins with "v=DKIM1".</summary>
        public bool StartsCorrectly { get; set; }
        /// <summary>Indicates whether the public key was found.</summary>
        public bool PublicKeyExists { get; set; }
        /// <summary>Indicates whether the key type is present.</summary>
        public bool KeyTypeExists { get; set; }
        /// <summary>Public key in base64 format.</summary>
        public string PublicKey { get; set; }
        /// <summary>Specified service type.</summary>
        public string ServiceType { get; set; }
        /// <summary>Any flags specified in the record.</summary>
        public string Flags { get; set; }
        /// <summary>Key type value.</summary>
        public string KeyType { get; set; }
        /// <summary>Hash algorithm used by the key.</summary>
        public string HashAlgorithm { get; set; }
    }
}
