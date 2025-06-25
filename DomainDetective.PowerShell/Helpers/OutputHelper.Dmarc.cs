using System.Collections.Generic;

namespace DomainDetective.PowerShell {
    /// <summary>
    ///     Helper methods for formatting DMARC analysis output.
    /// </summary>
    internal static partial class OutputHelper {
        /// <summary>
        ///     Converts analysis results into a structured record.
        /// </summary>
        /// <param name="analysis">Analysis instance.</param>
        /// <returns>Populated record describing the DMARC configuration.</returns>
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
                Ruf = analysis.Ruf,
                MailtoRua = analysis.MailtoRua,
                HttpRua = analysis.HttpRua,
                MailtoRuf = analysis.MailtoRuf,
                HttpRuf = analysis.HttpRuf,
                ExternalReportAuthorization = analysis.ExternalReportAuthorization,
                InvalidReportUri = analysis.InvalidReportUri
            };
        }
    }

    /// <summary>
    ///     Simplified representation of DMARC record details.
    /// </summary>
    public class DmarcRecordInfo {
        /// <summary>Raw DMARC record string.</summary>
        public string DmarcRecord { get; set; }

        /// <summary>Indicates if a DMARC record was found.</summary>
        public bool DmarcRecordExists { get; set; }

        /// <summary>True when the record begins with "v=DMARC1".</summary>
        public bool StartsCorrectly { get; set; }

        /// <summary>True when the policy values are valid.</summary>
        public bool IsPolicyValid { get; set; }

        /// <summary>Specifies the policy for the "p" tag.</summary>
        public string Policy { get; set; }

        /// <summary>Specifies the sub-domain policy for the "sp" tag.</summary>
        public string SubPolicy { get; set; }

        /// <summary>Percentage applied to the policy.</summary>
        public string Percent { get; set; }

        /// <summary>Aggregate report destination.</summary>
        public string Rua { get; set; }

        /// <summary>Forensic report destination.</summary>
        public string Ruf { get; set; }

        /// <summary>Parsed mailto RUA addresses.</summary>
        public IReadOnlyList<string> MailtoRua { get; set; }

        /// <summary>Parsed HTTP RUA endpoints.</summary>
        public IReadOnlyList<string> HttpRua { get; set; }

        /// <summary>Parsed mailto RUF addresses.</summary>
        public IReadOnlyList<string> MailtoRuf { get; set; }

        /// <summary>Parsed HTTP RUF endpoints.</summary>
        public IReadOnlyList<string> HttpRuf { get; set; }

        /// <summary>External reporting authorization per domain.</summary>
        public IReadOnlyDictionary<string, bool> ExternalReportAuthorization { get; set; }

        /// <summary>Indicates at least one report URI failed validation.</summary>
        public bool InvalidReportUri { get; set; }
    }
}