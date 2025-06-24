using System.Collections.Generic;

namespace DomainDetective.PowerShell {
    internal static partial class OutputHelper {
        public static DmarcRecordInfo Convert(DmarcAnalysis analysis) {
            return new DmarcRecordInfo {
                DmarcRecord = analysis.DmarcRecord,
                DmarcRecordExists = analysis.DmarcRecordExists,
                StartsCorrectly = analysis.StartsCorrectly,
                IsPolicyValid = analysis.IsPolicyValid,
                Policy = analysis.Policy,
                SubPolicy = analysis.SubPolicy,
                Percent = analysis.Percent,
                Rua = analysis.Rua,
                Ruf = analysis.Ruf
            };
        }
    }

    public class DmarcRecordInfo {
        public string DmarcRecord { get; set; }
        public bool DmarcRecordExists { get; set; }
        public bool StartsCorrectly { get; set; }
        public bool IsPolicyValid { get; set; }
        public string Policy { get; set; }
        public string SubPolicy { get; set; }
        public string Percent { get; set; }
        public string Rua { get; set; }
        public string Ruf { get; set; }
    }
}