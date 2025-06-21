using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClientX;

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


        public async Task AnalyzeDANERecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            // reset all properties so repeated calls don't accumulate data
            AnalysisResults = new List<DANERecordAnalysis>();
            NumberOfRecords = 0;
            HasDuplicateRecords = false;
            HasInvalidRecords = false;

            var daneRecordList = dnsResults.ToList();

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
                var associationData = components[3];

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

                // Check for correct usage of the Cert and SPKI selectors
                if ((analysis.SelectorField == "Cert" && (analysis.CertificateUsage != "PKIX-TA" && analysis.CertificateUsage != "PKIX-EE")) ||
                    (analysis.SelectorField == "SPKI" && (analysis.CertificateUsage != "DANE-TA" && analysis.CertificateUsage != "DANE-EE"))) {
                    analysis.ValidSelector = false;
                }

                // Check for correct usage of the Full, SHA-256, and SHA-512 matching types
                if ((analysis.MatchingTypeField == "Full" && (analysis.CertificateUsage != "PKIX-TA" && analysis.CertificateUsage != "PKIX-EE")) ||
                    ((analysis.MatchingTypeField == "SHA-256" || analysis.MatchingTypeField == "SHA-512") && (analysis.CertificateUsage != "DANE-TA" && analysis.CertificateUsage != "DANE-EE"))) {
                    analysis.ValidMatchingType = false;
                }

                //analysis.ServiceType = record.ServiceType;

                //// Check if the DANE record is appropriate for the service type
                //switch (record.ServiceType) {
                //    case ServiceType.SMTP:
                //        // Perform checks specific to MX services
                //        analysis.IsValidChoiceForSmtp = usageValue == 3 && selectorValue == 1 && matchingTypeValue == 1;
                //        break;
                //    case ServiceType.HTTPS:
                //        // Perform checks specific to WWW services

                //        break;
                //    default:
                //        //throw new Exception($"Unsupported service type: {record.ServiceType}");
                //        break;
                //}


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

    public class DANERecordAnalysis {
        public string DomainName { get; set; }

        public ServiceType ServiceType { get; set; }

        public string DANERecord { get; set; }
        public bool ValidDANERecord { get; set; }
        public bool ValidUsage { get; set; }
        public bool ValidSelector { get; set; }
        public bool ValidMatchingType { get; set; }
        public bool ValidCertificateAssociationData { get; set; }
        public bool IsValidChoiceForSmtp { get; set; }
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
