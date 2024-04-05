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

                // Split the DANE record into its components
                var components = record.Data.Split(' ');

                // Validate the components according to the rules defined in RFC 6698
                // For example, the first component should be a usage field, the second should be a selector field, etc.
                // You would need to implement these validation methods
                analysis.ValidUsage = ValidateUsage(components[0]);
                analysis.ValidSelector = ValidateSelector(components[1]);

                // Check if the DANE record has the correct number of fields
                analysis.CorrectNumberOfFields = components.Length == 4;

                // Check if the Certificate Association Data is a valid hexadecimal string
                analysis.ValidCertificateAssociationData = IsHexadecimal(components[3]);

                // Check the length of the Certificate Association Data
                int expectedLength;
                switch (int.Parse(components[2])) {
                    case 0:
                        expectedLength = 256;
                        break;
                    case 1:
                        expectedLength = 64;
                        break;
                    case 2:
                        expectedLength = 128;
                        break;
                    default:
                        expectedLength = 0;
                        break;
                }
                analysis.CorrectLengthOfCertificateAssociationData = components[3].Length == expectedLength;
                analysis.LengthOfCertificateAssociationData = components[3].Length;
                analysis.ValidMatchingType = int.Parse(components[2]) >= 0 && int.Parse(components[2]) <= 2;
                analysis.NumberOfFields = components.Length;

                var usageValue = int.Parse(components[0]);
                var selectorValue = int.Parse(components[1]);
                var matchingTypeValue = int.Parse(components[2]);

                analysis.CertificateUsage = TranslateUsage(int.Parse(components[0]));
                analysis.SelectorField = TranslateSelector(int.Parse(components[1]));
                analysis.MatchingTypeField = TranslateMatchingType(int.Parse(components[2]));
                analysis.CertificateAssociationData = components[3]; // This is typically a hex string, so no translation is needed

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

        private bool ValidateUsage(string usage) {
            bool isNumeric = int.TryParse(usage, out var usageValue);

            if (!isNumeric) {
                return false;
            }

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
        private bool ValidateSelector(string selector) {
            bool isNumeric = int.TryParse(selector, out var selectorValue);

            if (!isNumeric) {
                return false;
            }

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
