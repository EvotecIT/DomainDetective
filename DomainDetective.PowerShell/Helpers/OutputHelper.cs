using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.PowerShell {
    /// <summary>
    ///     Provides helper methods for converting analysis results into
    ///     simple PowerShell friendly objects.
    /// </summary>
    internal class OutputHelper {
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
                    ValidPublicKey = result.ValidPublicKey,
                    ValidRsaKeyLength = result.ValidRsaKeyLength,
                    KeyLength = result.KeyLength,
                    WeakKey = result.WeakKey,
                    KeyTypeExists = result.KeyTypeExists,
                    ValidKeyType = result.ValidKeyType,
                    PublicKey = result.PublicKey,
                    ServiceType = result.ServiceType,
                    Flags = result.Flags,
                    ValidFlags = result.ValidFlags,
                    UnknownFlagCharacters = result.UnknownFlagCharacters,
                    Canonicalization = result.Canonicalization,
                    ValidCanonicalization = result.ValidCanonicalization,
                    KeyType = result.KeyType,
                    HashAlgorithm = result.HashAlgorithm,
                    CreationDate = result.CreationDate,
                    OldKey = result.OldKey
                };
            }
        }

        /// <summary>
        ///     Converts DMARC analysis results into a structured record.
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
                DkimAlignment = analysis.DkimAlignment,
                SpfAlignment = analysis.SpfAlignment,
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
    ///     Data object representing a single DKIM record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
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

        /// <summary>Validation result for the public key.</summary>
        public bool ValidPublicKey { get; set; }

        /// <summary>Indicates whether the RSA key length meets policy.</summary>
        public bool ValidRsaKeyLength { get; set; }

        /// <summary>Length of the RSA public key in bits.</summary>
        public int KeyLength { get; set; }

        /// <summary>True when the RSA key length is under 2048 bits.</summary>
        public bool WeakKey { get; set; }

        /// <summary>Indicates whether the key type is present.</summary>
        public bool KeyTypeExists { get; set; }
        /// <summary>Validation result for the key type.</summary>
        public bool ValidKeyType { get; set; }

        /// <summary>Public key in base64 format.</summary>
        public string PublicKey { get; set; }

        /// <summary>Specified service type.</summary>
        public string ServiceType { get; set; }

        /// <summary>Any flags specified in the record.</summary>
        public string Flags { get; set; }
        /// <summary>Indicates whether all flag characters are valid.</summary>
        public bool ValidFlags { get; set; }
        /// <summary>Unexpected characters found in the flags.</summary>
        public string UnknownFlagCharacters { get; set; }
        /// <summary>Canonicalization modes specified.</summary>
        public string Canonicalization { get; set; }
        /// <summary>Validation result for the canonicalization value.</summary>
        public bool ValidCanonicalization { get; set; }

        /// <summary>Key type value.</summary>
        public string KeyType { get; set; }

        /// <summary>Hash algorithm used by the key.</summary>
        public string HashAlgorithm { get; set; }

        /// <summary>Date the record appears to have been created.</summary>
        public DateTime? CreationDate { get; set; }

        /// <summary>True when <see cref="CreationDate"/> is over 12 months old.</summary>
        public bool OldKey { get; set; }
    }

    /// <summary>
    ///     Simplified representation of DMARC record details.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
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

        /// <summary>DKIM alignment mode.</summary>
        public string DkimAlignment { get; set; }

        /// <summary>SPF alignment mode.</summary>
        public string SpfAlignment { get; set; }

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