using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes DANE (TLSA) records for a domain.
    /// HTTPS service type (port 443) is assumed when none is provided.
    /// RFC 6698: The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
    /// https://datatracker.ietf.org/doc/html/rfc6698
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// DANE policies are evaluated by querying TLSA records for the specified
    /// host and port combination.
    /// </remarks>
    public class DANEAnalysis : IHasAssessments {
        /// <summary>Optional override for DNS queries.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { get; set; }
        public List<DANERecordAnalysis> AnalysisResults { get; private set; } = new List<DANERecordAnalysis>();
        public int NumberOfRecords { get; private set; }
        public bool HasDuplicateRecords { get; private set; }
        public bool HasInvalidRecords { get; set; }

        /// <summary>Fully qualified TLSA owner names that were queried (e.g., _443._tcp.example.com).</summary>
        public List<string> QueriedNames { get; private set; } = new List<string>();

        /// <summary>Ports that were probed for TLSA lookups.</summary>
        public List<int> QueriedPorts { get; private set; } = new List<int>();

        /// <summary>Service types that were probed.</summary>
        public List<ServiceType> QueriedServiceTypes { get; private set; } = new List<ServiceType>();

        /// <summary>Relevant standards for DANE analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "DANE TLSA", Reference = "RFC 6698", Url = "https://datatracker.ietf.org/doc/html/rfc6698" }
        };

        /// <summary>Structured assessments captured during DANE analysis.</summary>
        public List<Assessment> Assessments { get; } = new();


        public void Reset() {
            AnalysisResults = new List<DANERecordAnalysis>();
            NumberOfRecords = 0;
            HasDuplicateRecords = false;
            HasInvalidRecords = false;
            QueriedNames = new List<string>();
            QueriedPorts = new List<int>();
            QueriedServiceTypes = new List<ServiceType>();
        }


        public async Task AnalyzeDANERecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DANE");
            Reset();

            cancellationToken.ThrowIfCancellationRequested();

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
                cancellationToken.ThrowIfCancellationRequested();
                using var _scope = _collector.PushTarget(record.Name);
                var analysis = new DANERecordAnalysis();
                analysis.DomainName = record.Name;
                analysis.DANERecord = record.Data;

                if (!string.IsNullOrEmpty(record.Name)) {
                    var match = System.Text.RegularExpressions.Regex.Match(record.Name, @"^_(\d+)\._(tcp|udp)\.");
                    if (match.Success && int.TryParse(match.Groups[1].Value, out var port)) {
                        analysis.ServiceType = (ServiceType)port;
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
                    logger?.WriteWarningCode(DaneCodes.UsageNotNumeric, $"TLSA usage field '{usagePart}' is not numeric");
                } else if (!ValidateUsage(usageValue)) {
                    logger?.WriteWarningCode(DaneCodes.UsageInvalid, $"TLSA usage '{usageValue}' is invalid, expected 0-3");
                }

                if (!selectorParsed) {
                    logger?.WriteWarningCode(DaneCodes.SelectorNotNumeric, $"TLSA selector field '{selectorPart}' is not numeric");
                } else if (!ValidateSelector(selectorValue)) {
                    logger?.WriteWarningCode(DaneCodes.SelectorInvalid, $"TLSA selector value '{selectorValue}' is invalid, expected 0 or 1");
                }

                if (!matchingParsed) {
                    logger?.WriteWarningCode(DaneCodes.MatchingTypeNotNumeric, $"TLSA matching type field '{matchingPart}' is not numeric");
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
                analysis.ValidMatchingType = ValidateMatchingType(matchingTypeValue);
                if (!analysis.ValidMatchingType) {
                    logger?.WriteWarningCode(DaneCodes.MatchingTypeInvalid, $"TLSA matching type '{matchingTypeValue}' is invalid, expected 0, 1 or 2");
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
                    logger?.WriteWarningCode(DaneCodes.ComboNotRecommended, $"TLSA selector {selectorValue} and matching type {matchingTypeValue} are not recommended for SMTP");
                }

                // For HTTPS, RFC 7671 recommends the same parameters
                analysis.IsValidChoiceForHttps = analysis.ServiceType == ServiceType.HTTPS && usageValue == 3 && selectorValue == 1 && matchingTypeValue == 1;
                if (analysis.ServiceType == ServiceType.HTTPS && !analysis.IsValidChoiceForHttps) {
                    logger?.WriteWarningCode(DaneCodes.ComboNotRecommended, $"TLSA selector {selectorValue} and matching type {matchingTypeValue} are not recommended for HTTPS");
                }

                analysis.ValidDANERecord = analysis.ValidUsage && analysis.ValidSelector && analysis.ValidMatchingType && analysis.CorrectNumberOfFields && analysis.CorrectLengthOfCertificateAssociationData && analysis.ValidCertificateAssociationData;

                // Add the analysis to the results
                AnalysisResults.Add(analysis);
            }

            cancellationToken.ThrowIfCancellationRequested();
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
        private bool ValidateMatchingType(int matchingValue) {
            return matchingValue switch {
                0 or 1 or 2 => true,
                _ => false,
            };
        }

        private TlsaUsage TranslateUsage(int usage) {
            return usage switch {
                0 => TlsaUsage.PkixTa,
                1 => TlsaUsage.PkixEe,
                2 => TlsaUsage.DaneTa,
                3 => TlsaUsage.DaneEe,
                _ => TlsaUsage.Unknown,
            };
        }

        private TlsaSelector TranslateSelector(int selector) {
            return selector switch {
                0 => TlsaSelector.Cert,
                1 => TlsaSelector.Spki,
                _ => TlsaSelector.Unknown,
            };
        }

        private TlsaMatchingType TranslateMatchingType(int matchingType) {
            return matchingType switch {
                0 => TlsaMatchingType.Full,
                1 => TlsaMatchingType.Sha256,
                2 => TlsaMatchingType.Sha512,
                _ => TlsaMatchingType.Unknown,
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
        /// <summary>Gets or sets the certificate usage value.</summary>
        public TlsaUsage CertificateUsage { get; set; }
        /// <summary>Gets or sets the selector value.</summary>
        public TlsaSelector SelectorField { get; set; }
        /// <summary>Gets or sets the matching type value.</summary>
        public TlsaMatchingType MatchingTypeField { get; set; }
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
