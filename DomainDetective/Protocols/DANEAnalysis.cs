using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes DANE (TLSA) records for a domain.
    /// RFC 6698: The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
    /// https://datatracker.ietf.org/doc/html/rfc6698
    /// </summary>

    public class DANEAnalysis {
        public List<DANERecordAnalysis> AnalysisResults { get; private set; } = new List<DANERecordAnalysis>();
        public int NumberOfRecords { get; private set; }
        public bool HasDuplicateRecords { get; private set; }
        public bool HasInvalidRecords { get; set; }


        public void Reset() {
            AnalysisResults = new List<DANERecordAnalysis>();
            NumberOfRecords = 0;
            HasDuplicateRecords = false;
            HasInvalidRecords = false;
        }


        public async Task AnalyzeDANERecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            Reset();

            var daneRecordList = dnsResults.ToList();

            // Group by the correct data property for duplicate detection
            var duplicateRecords = daneRecordList.GroupBy(x => x.Data).Where(g => g.Count() > 1).ToList();
            if (duplicateRecords.Any()) {
                HasDuplicateRecords = true;
            }

            NumberOfRecords = daneRecordList.Count;

            foreach (var record in daneRecordList) {
                var analysis = new DANERecordAnalysis();
                analysis.DomainName = record.Name;
                analysis.DANERecord = record.Data;
                logger.WriteVerbose($"Analyzing DANE record {record.Data}");

                // Split the DANE record into its four components as defined in
                // RFC 6698 section 2: certificate usage, selector, matching
                // type and certificate association data.
                var components = record.Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                analysis.NumberOfFields = components.Length;
                // A TLSA record must contain exactly four fields as per RFC 6698
                // (usage, selector, matching type and certificate data).
                analysis.CorrectNumberOfFields = components.Length == 4;

                if (!analysis.CorrectNumberOfFields) {
                    AnalysisResults.Add(analysis);
                    continue;
                }

                var usagePart = components[0];
                var selectorPart = components[1];
                var matchingPart = components[2];
                var associationData = components[3].Trim();

                bool usageParsed = int.TryParse(usagePart, out int usageValue);
                bool selectorParsed = int.TryParse(selectorPart, out int selectorValue);
                bool matchingParsed = int.TryParse(matchingPart, out int matchingTypeValue);

                analysis.ValidUsage = usageParsed && ValidateUsage(usageValue);
                analysis.ValidSelector = selectorParsed && ValidateSelector(selectorValue);
                analysis.ValidCertificateAssociationData = IsHexadecimal(associationData);

                if (!usageParsed || !selectorParsed || !matchingParsed) {
                    analysis.ValidMatchingType = false;
                    AnalysisResults.Add(analysis);
                    continue;
                }

                // Matching type defines how certificate association data is
                // interpreted.  For digest-based types we verify the expected
                // length of the hexadecimal string (SHA-256 => 64 hex chars,
                // SHA-512 => 128 hex chars).  For type 0 the data is the full
                // certificate and length is implementation specific.
                int expectedLength = matchingTypeValue switch {
                    1 => 64,
                    2 => 128,
                    _ => 0
                };

                analysis.CorrectLengthOfCertificateAssociationData = matchingTypeValue == 0 || associationData.Length == expectedLength;
                analysis.LengthOfCertificateAssociationData = associationData.Length;
                analysis.ValidMatchingType = matchingTypeValue >= 0 && matchingTypeValue <= 2;

                analysis.CertificateUsage = TranslateUsage(usageValue);
                analysis.SelectorField = TranslateSelector(selectorValue);
                analysis.MatchingTypeField = TranslateMatchingType(matchingTypeValue);
                analysis.CertificateAssociationData = associationData; // This is typically a hex string, so no translation is needed

                // RFC 6698 does not restrict selector or matching type based on
                // certificate usage, so all combinations are considered valid.

                // Check if the DANE record is appropriate for SMTP
                // For SMTP, the recommended configuration is:
                // - Usage: 3 (DANE-EE: Domain Issued Certificate)
                // - Selector: 1 (SPKI: SubjectPublicKeyInfo)
                // - Matching Type: 1 (SHA-256: SHA-256 of Certificate or SPKI)
                analysis.IsValidChoiceForSmtp = usageValue == 3 && selectorValue == 1 && matchingTypeValue == 1;

                // TODO: Check for HTTPS recommendations for WWWW services?

                analysis.ValidDANERecord = analysis.ValidUsage && analysis.ValidSelector && analysis.ValidMatchingType && analysis.CorrectNumberOfFields && analysis.CorrectLengthOfCertificateAssociationData && analysis.ValidCertificateAssociationData;

                // Add the analysis to the results
                AnalysisResults.Add(analysis);
            }

            HasInvalidRecords = AnalysisResults.Any(x => !x.ValidDANERecord);
        }

        private bool ValidateUsage(int usageValue) {
            switch (usageValue) {
                case 0:
                case 1:
                case 2:
                case 3:
                    return true;
                default:
                    return false;
            }
        }
        private bool ValidateSelector(int selectorValue) {
            switch (selectorValue) {
                case 0:
                case 1:
                    return true;
                default:
                    return false;
            }
        }
        private string TranslateUsage(int usage) {
            switch (usage) {
                case 0:
                    return "PKIX-TA: CA Constraint";
                case 1:
                    return "PKIX-EE: Service Certificate Constraint";
                case 2:
                    return "DANE-TA: Trust Anchor Assertion";
                case 3:
                    return "DANE-EE: Domain Issued Certificate";
                default:
                    return "Unknown";
            }
        }

        private string TranslateSelector(int selector) {
            switch (selector) {
                case 0:
                    return "Cert: Full Certificate";
                case 1:
                    return "SPKI: SubjectPublicKeyInfo";
                default:
                    return "Unknown";
            }
        }

        private string TranslateMatchingType(int matchingType) {
            switch (matchingType) {
                case 0:
                    return "Full: Full Certificate or SPKI";
                case 1:
                    return "SHA-256: SHA-256 of Certificate or SPKI";
                case 2:
                    return "SHA-512: SHA-512 of Certificate or SPKI";
                default:
                    return "Unknown";
            }
        }

        private bool IsHexadecimal(string input) {
            return System.Text.RegularExpressions.Regex.IsMatch(input, @"\A\b[0-9a-fA-F]+\b\Z");
        }
    }

    /// <summary>
    /// Detailed analysis information for a single DANE record.
    /// </summary>
    public class DANERecordAnalysis {
        /// <summary>Gets or sets the domain name that provided the record.</summary>
        public string DomainName { get; set; }

        /// <summary>Gets or sets the associated service type.</summary>
        public ServiceType ServiceType { get; set; }

        /// <summary>Gets or sets the raw TLSA record.</summary>
        public string DANERecord { get; set; }
        /// <summary>Gets or sets a value indicating whether the record passed all validations.</summary>
        public bool ValidDANERecord { get; set; }
        /// <summary>Gets or sets whether the usage field is valid.</summary>
        public bool ValidUsage { get; set; }
        /// <summary>Gets or sets whether the selector field is valid.</summary>
        public bool ValidSelector { get; set; }
        /// <summary>Gets or sets whether the matching type is valid.</summary>
        public bool ValidMatchingType { get; set; }
        /// <summary>Gets or sets whether the certificate association data is valid hexadecimal.</summary>
        public bool ValidCertificateAssociationData { get; set; }
        /// <summary>Gets or sets a value indicating whether this configuration is recommended for SMTP.</summary>
        public bool IsValidChoiceForSmtp { get; set; }
        /// <summary>Gets or sets the textual description of the certificate usage.</summary>
        public string CertificateUsage { get; set; }
        /// <summary>Gets or sets the textual description of the selector field.</summary>
        public string SelectorField { get; set; }
        /// <summary>Gets or sets the textual description of the matching type.</summary>
        public string MatchingTypeField { get; set; }
        /// <summary>Gets or sets the certificate association data.</summary>
        public string CertificateAssociationData { get; set; }
        /// <summary>Gets or sets a value indicating whether the record contains four fields.</summary>
        public bool CorrectNumberOfFields { get; set; }
        /// <summary>Gets or sets whether the certificate association data has the expected length.</summary>
        public bool CorrectLengthOfCertificateAssociationData { get; set; }
        /// <summary>Gets or sets the length of the association data.</summary>
        public int LengthOfCertificateAssociationData { get; set; }
        /// <summary>Gets or sets the total number of fields in the record.</summary>
        public int NumberOfFields { get; set; }
    }
}