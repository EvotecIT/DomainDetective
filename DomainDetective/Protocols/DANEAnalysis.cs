using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes DANE (TLSA) records for a domain.
    /// HTTPS service type (port 443) is assumed when none is provided.
    /// RFC 6698: The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
    /// https://datatracker.ietf.org/doc/html/rfc6698
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
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

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

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

                if (!string.IsNullOrEmpty(record.Name)) {
                    var match = System.Text.RegularExpressions.Regex.Match(record.Name, @"^_(\d+)\._(tcp|udp)\.");
                    if (match.Success && int.TryParse(match.Groups[1].Value, out var port)) {
                        if (Enum.IsDefined(typeof(ServiceType), port)) {
                            analysis.ServiceType = (ServiceType)port;
                        }
                    }
                }
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

                if (!usageParsed) {
                    logger?.WriteWarning($"TLSA usage field '{usagePart}' is not numeric");
                } else if (!ValidateUsage(usageValue)) {
                    logger?.WriteWarning($"TLSA usage '{usageValue}' is invalid, expected 0-3");
                }

                if (!selectorParsed) {
                    logger?.WriteWarning($"TLSA selector field '{selectorPart}' is not numeric");
                } else if (!ValidateSelector(selectorValue)) {
                    logger?.WriteWarning($"TLSA selector value '{selectorValue}' is invalid, expected 0 or 1");
                }

                if (!matchingParsed) {
                    logger?.WriteWarning($"TLSA matching type field '{matchingPart}' is not numeric");
                }

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
                if (!analysis.ValidMatchingType) {
                    logger?.WriteWarning($"TLSA matching type '{matchingTypeValue}' is invalid, expected 0, 1 or 2");
                }

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
                analysis.IsValidChoiceForSmtp = analysis.ServiceType == ServiceType.SMTP && usageValue == 3 && selectorValue == 1 && matchingTypeValue == 1;
                if (analysis.ServiceType == ServiceType.SMTP && !analysis.IsValidChoiceForSmtp) {
                    logger?.WriteWarning($"TLSA selector {selectorValue} and matching type {matchingTypeValue} are not recommended for SMTP");
                }

                // For HTTPS, RFC 7671 recommends the same parameters
                analysis.IsValidChoiceForHttps = analysis.ServiceType == ServiceType.HTTPS && usageValue == 3 && selectorValue == 1 && matchingTypeValue == 1;
                if (analysis.ServiceType == ServiceType.HTTPS && !analysis.IsValidChoiceForHttps) {
                    logger?.WriteWarning($"TLSA selector {selectorValue} and matching type {matchingTypeValue} are not recommended for HTTPS");
                }

                analysis.ValidDANERecord = analysis.ValidUsage && analysis.ValidSelector && analysis.ValidMatchingType && analysis.CorrectNumberOfFields && analysis.CorrectLengthOfCertificateAssociationData && analysis.ValidCertificateAssociationData;

                // Add the analysis to the results
                AnalysisResults.Add(analysis);
            }

            HasInvalidRecords = AnalysisResults.Any(x => !x.ValidDANERecord);
        }

        private bool ValidateUsage(int usageValue) {
            return usageValue switch {
                0 or 1 or 2 or 3 => true,
                _ => false,
            };
        }
        private bool ValidateSelector(int selectorValue) {
            return selectorValue switch {
                0 or 1 => true,
                _ => false,
            };
        }
        private string TranslateUsage(int usage) {
            return usage switch {
                0 => "PKIX-TA: CA Constraint",
                1 => "PKIX-EE: Service Certificate Constraint",
                2 => "DANE-TA: Trust Anchor Assertion",
                3 => "DANE-EE: Domain Issued Certificate",
                _ => "Unknown",
            };
        }

        private string TranslateSelector(int selector) {
            return selector switch {
                0 => "Cert: Full Certificate",
                1 => "SPKI: SubjectPublicKeyInfo",
                _ => "Unknown",
            };
        }

        private string TranslateMatchingType(int matchingType) {
            return matchingType switch {
                0 => "Full: Full Certificate or SPKI",
                1 => "SHA-256: SHA-256 of Certificate or SPKI",
                2 => "SHA-512: SHA-512 of Certificate or SPKI",
                _ => "Unknown",
            };
        }

        private bool IsHexadecimal(string input) {
            return System.Text.RegularExpressions.Regex.IsMatch(input, @"\A\b[0-9a-fA-F]+\b\Z");
        }
    }

    /// <summary>
    /// Detailed analysis information for a single DANE record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DANERecordAnalysis {
        /// <summary>Gets or sets the domain name that provided the record.</summary>
        public string DomainName { get; set; }

        /// <summary>Gets or sets the associated service type.</summary>
        public ServiceType ServiceType { get; set; } = ServiceType.HTTPS;

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
        /// <summary>Gets or sets a value indicating whether this configuration is recommended for HTTPS.</summary>
        public bool IsValidChoiceForHttps { get; set; }
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