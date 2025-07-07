using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes SMIMEA records per RFC 8162.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SMIMEAAnalysis {
        /// <summary>Detailed analysis results for each SMIMEA record.</summary>
        public List<SMIMEARecordAnalysis> AnalysisResults { get; private set; } = new();
        public int NumberOfRecords { get; private set; }
        public bool HasDuplicateRecords { get; private set; }
        public bool HasInvalidRecords { get; private set; }

        public void Reset() {
            AnalysisResults = new List<SMIMEARecordAnalysis>();
            NumberOfRecords = 0;
            HasDuplicateRecords = false;
            HasInvalidRecords = false;
        }

        public async Task AnalyzeSMIMEARecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            Reset();
            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }
            var records = dnsResults.ToList();
            var duplicate = records.GroupBy(x => x.Data).Where(g => g.Count() > 1).ToList();
            if (duplicate.Any()) {
                HasDuplicateRecords = true;
            }
            NumberOfRecords = records.Count;
            foreach (var record in records) {
                var analysis = new SMIMEARecordAnalysis {
                    SmimeaRecord = record.Data,
                    EmailAddress = record.Name
                };
                if (!string.IsNullOrEmpty(record.Name)) {
                    var match = System.Text.RegularExpressions.Regex.Match(
                        record.Name,
                        @"^[0-9a-f]{56}\._smimecert\.[^.].*$",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    analysis.ValidServiceAndProtocol = match.Success;
                    if (!match.Success) {
                        logger?.WriteWarning($"SMIMEA host name '{record.Name}' is invalid");
                    }
                }
                logger?.WriteVerbose($"Analyzing SMIMEA record {record.Data}");
                var components = record.Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                analysis.NumberOfFields = components.Length;
                analysis.CorrectNumberOfFields = components.Length == 4;
                if (!analysis.CorrectNumberOfFields) {
                    AnalysisResults.Add(analysis);
                    continue;
                }
                var usagePart = components[0];
                var selectorPart = components[1];
                var matchingPart = components[2];
                var assocData = components[3].Trim();
                bool usageParsed = int.TryParse(usagePart, out int usageVal);
                bool selectorParsed = int.TryParse(selectorPart, out int selectorVal);
                bool matchingParsed = int.TryParse(matchingPart, out int matchingVal);
                analysis.ValidUsage = usageParsed && ValidateUsage(usageVal);
                analysis.ValidSelector = selectorParsed && ValidateSelector(selectorVal);
                analysis.ValidCertificateAssociationData = IsHexadecimal(assocData);
                if (!usageParsed) {
                    logger?.WriteWarning($"SMIMEA usage field '{usagePart}' is not numeric");
                } else if (!ValidateUsage(usageVal)) {
                    logger?.WriteWarning($"SMIMEA usage '{usageVal}' is invalid, expected 0-3");
                }
                if (!selectorParsed) {
                    logger?.WriteWarning($"SMIMEA selector field '{selectorPart}' is not numeric");
                } else if (!ValidateSelector(selectorVal)) {
                    logger?.WriteWarning($"SMIMEA selector value '{selectorVal}' is invalid, expected 0 or 1");
                }
                if (!matchingParsed) {
                    logger?.WriteWarning($"SMIMEA matching type field '{matchingPart}' is not numeric");
                }
                if (!usageParsed || !selectorParsed || !matchingParsed) {
                    analysis.ValidMatchingType = false;
                    AnalysisResults.Add(analysis);
                    continue;
                }
                int expectedLength = matchingVal switch {
                    1 => 64,
                    2 => 128,
                    _ => 0
                };
                analysis.CorrectLengthOfCertificateAssociationData = matchingVal == 0 || assocData.Length == expectedLength;
                analysis.LengthOfCertificateAssociationData = assocData.Length;
                analysis.ValidMatchingType = matchingVal >= 0 && matchingVal <= 2;
                if (!analysis.ValidMatchingType) {
                    logger?.WriteWarning($"SMIMEA matching type '{matchingVal}' is invalid, expected 0, 1 or 2");
                }
                analysis.CertificateUsage = TranslateUsage(usageVal);
                analysis.SelectorField = TranslateSelector(selectorVal);
                analysis.MatchingTypeField = TranslateMatchingType(matchingVal);
                analysis.CertificateAssociationData = assocData;
                analysis.ValidSMIMEARecord = analysis.ValidUsage && analysis.ValidSelector && analysis.ValidMatchingType && analysis.CorrectNumberOfFields && analysis.CorrectLengthOfCertificateAssociationData && analysis.ValidCertificateAssociationData;
                AnalysisResults.Add(analysis);
            }
            HasInvalidRecords = AnalysisResults.Any(x => !x.ValidSMIMEARecord);
        }

        private bool ValidateUsage(int usage) => usage switch { 0 or 1 or 2 or 3 => true, _ => false };
        private bool ValidateSelector(int selector) => selector switch { 0 or 1 => true, _ => false };
        private string TranslateUsage(int usage) => usage switch {
            0 => "PKIX-TA: CA Constraint",
            1 => "PKIX-EE: Service Certificate Constraint",
            2 => "DANE-TA: Trust Anchor Assertion",
            3 => "DANE-EE: Domain Issued Certificate",
            _ => "Unknown",
        };
        private string TranslateSelector(int selector) => selector switch {
            0 => "Cert: Full Certificate",
            1 => "SPKI: SubjectPublicKeyInfo",
            _ => "Unknown",
        };
        private string TranslateMatchingType(int matching) => matching switch {
            0 => "Full: Full Certificate or SPKI",
            1 => "SHA-256: SHA-256 of Certificate or SPKI",
            2 => "SHA-512: SHA-512 of Certificate or SPKI",
            _ => "Unknown",
        };
        private bool IsHexadecimal(string input) => System.Text.RegularExpressions.Regex.IsMatch(input, @"\A\b[0-9a-fA-F]+\b\Z");

        public static string GetQueryName(string emailAddress) {
            if (string.IsNullOrWhiteSpace(emailAddress)) {
                throw new ArgumentNullException(nameof(emailAddress));
            }

            var at = emailAddress.IndexOf('@');
            if (at < 1 || at == emailAddress.Length - 1) {
                throw new ArgumentException("Invalid email address", nameof(emailAddress));
            }

            var local = CanonicalizeLocalPart(emailAddress.Substring(0, at));
            var domain = emailAddress.Substring(at + 1);

            var bytes = Encoding.UTF8.GetBytes(local);
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(bytes);
            var truncated = new byte[28];
            Array.Copy(hash, truncated, 28);
            var hex = BitConverter.ToString(truncated).Replace("-", string.Empty).ToLowerInvariant();
            return $"{hex}._smimecert.{domain}";
        }

        private static string CanonicalizeLocalPart(string localPart) {
            localPart = localPart.Trim();
            if (localPart.StartsWith("\"") && localPart.EndsWith("\"")) {
                localPart = localPart.Substring(1, localPart.Length - 2);
            }
            localPart = System.Text.RegularExpressions.Regex.Replace(localPart, @"\\(.)", "$1");
            localPart = System.Text.RegularExpressions.Regex.Replace(localPart, @"\(.*?\)", string.Empty);
            localPart = System.Text.RegularExpressions.Regex.Replace(localPart, @"\s*\.\s*", ".");
            return localPart;
        }
    }

    /// <summary>Detailed analysis for a single SMIMEA record.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SMIMEARecordAnalysis {
        public string EmailAddress { get; set; }
        public string SmimeaRecord { get; set; }
        public bool ValidSMIMEARecord { get; set; }
        public bool ValidUsage { get; set; }
        public bool ValidSelector { get; set; }
        public bool ValidMatchingType { get; set; }
        public bool ValidCertificateAssociationData { get; set; }
        /// <summary>True when the record name uses the '_smimecert' label without a protocol.</summary>
        public bool ValidServiceAndProtocol { get; set; }
        public string CertificateUsage { get; set; }
        public string SelectorField { get; set; }
        public string MatchingTypeField { get; set; }
        public string CertificateAssociationData { get; set; }
        public bool CorrectNumberOfFields { get; set; }
        public bool CorrectLengthOfCertificateAssociationData { get; set; }
        public int LengthOfCertificateAssociationData { get; set; }
        public int NumberOfFields { get; set; }
    }
}
