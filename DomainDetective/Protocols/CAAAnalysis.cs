using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective {

    public class CAAAnalysis {
        public string DomainName { get; set; }

        public string Description { get; set; } =
            @"A Certification Authority Authorization (CAA) record allows a domain to specify which certificate authorities (CAs)
are permitted to issue certificates for it.

By using CAA records, domain owners have the ability to state which certificate authorities can issue a certificate for their domain.
These records also offer a way to set notification rules in case a certificate is requested from a certificate authority that is not authorized.

In the absence of a CAA record, any CA has the permission to issue a certificate for the domain.
However, if a CAA record exists, only the CAs listed in that record(s) have the authorization to issue certificates for the hostname.

CAA records can establish policy for the entire domain or for specific hostnames, and these policies are inherited by subdomains.
As an illustration, a CAA record that is set on example.com is also applicable to subdomain.example.com.";
        public int ValidRecords { get; private set; }
        public int InvalidRecords { get; private set; }
        public List<string> CanIssueCertificatesForDomain { get; set; } = new List<string>();
        public List<string> CanIssueWildcardCertificatesForDomain { get; set; } = new List<string>();

        public List<string> CanIssueMail { get; set; } = new List<string>();

        public List<string> ReportViolationEmail { get; set; } = new List<string>();

        public bool Conflicting { get; set; }

        public bool ConflictingMailIssuance { get; set; }
        public bool ConflictingCertificateIssuance { get; set; }
        public bool ConflictingWildcardCertificateIssuance { get; set; }

        public bool Valid {
            get {
                if (!Conflicting && InvalidRecords == 0) {
                    return true;
                } else {
                    return false;
                }
            }
        }

        public List<CAARecordAnalysis> AnalysisResults { get; private set; } = new List<CAARecordAnalysis>();

        public async Task AnalyzeCAARecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            // reset all properties so repeated calls don't accumulate data
            DomainName = null;
            ValidRecords = 0;
            InvalidRecords = 0;
            CanIssueCertificatesForDomain = new List<string>();
            CanIssueWildcardCertificatesForDomain = new List<string>();
            CanIssueMail = new List<string>();
            ReportViolationEmail = new List<string>();
            Conflicting = false;
            ConflictingMailIssuance = false;
            ConflictingCertificateIssuance = false;
            ConflictingWildcardCertificateIssuance = false;
            AnalysisResults = new List<CAARecordAnalysis>();

            var caaRecordList = dnsResults.ToList();

            DomainName = caaRecordList.First().Name;

            foreach (var record in caaRecordList) {
                var analysis = new CAARecordAnalysis();

                var caaRecord = record.Data;

                logger.WriteVerbose($"Analyzing CAA record {caaRecord}");

                analysis.CAARecord = caaRecord;

                var properties = caaRecord.Split(new[] { ' ' }, 3); // Split into 3 parts at most
                // RFC 6844 section 5 specifies that the flag field must be a
                // single unsigned octet in the range 0-255.  We validate the
                // numeric value before processing the remaining parts.
                if (properties.Length == 3 && int.TryParse(properties[0].Trim(), out var flag)) {
                    var tag = properties[1].Trim();
                    var value = properties[2];

                    // Validate flag
                    analysis.Flag = flag.ToString();
                    if (flag < 0 || flag > 255) {
                        analysis.InvalidFlag = true;
                    }

                    // Validate tag and set the Tag property
                    var validTags = new Dictionary<string, CAATagType> {
                            { "issue", CAATagType.Issue },
                            { "issuewild", CAATagType.IssueWildcard },
                            { "iodef", CAATagType.Iodef },
                            { "issuemail", CAATagType.IssueMail }
                        };
                    if (validTags.TryGetValue(tag, out var tagType)) {
                        analysis.Tag = tagType;
                    } else {
                        analysis.Tag = CAATagType.Unknown;
                        analysis.InvalidTag = true;
                        //continue;
                    }

                    // Validate value
                    // Validate value
                    bool isValueQuoted = value.Length >= 2 && value[0] == '"' && value[value.Length - 1] == '"';
                    if (isValueQuoted || !value.Contains(" ")) {
                        if (isValueQuoted) {
                            // Remove the wrapping double quotes
                            value = value.Substring(1, value.Length - 2);

                            // Check for unescaped inner double quotes
                            if (value.Contains("\"")) {
                                analysis.InvalidValueUnescapedQuotes = true;
                                //  continue;
                            }

                            // Replace escaped double quotes with actual double quotes
                            value = value.Replace("\\\"", "\"");
                        }

                        // Existing code for additional validation...
                        analysis.Value = value; // Move this line outside the if block
                    } else {
                        analysis.InvalidValueUnescapedQuotes = true;
                        //continue;
                    }

                    // Additional validation for issue, issuewild, and issuemail tags
                    if (tagType == CAATagType.Issue || tagType == CAATagType.IssueWildcard || tagType == CAATagType.IssueMail) {
                        var isValueOnlySemicolon = value == ";";
                        if (isValueOnlySemicolon) {
                            analysis.Value = value;
                            continue;
                        }
                        var parts = value.Split(new[] { ';' }, 2); // Split into 2 parts at most
                        var domainName = parts[0].Trim();
                        if (string.IsNullOrEmpty(domainName)) {
                            // The domain name can be left empty, which must be indicated providing just ";" as a value
                            if (parts.Length > 1) {
                                analysis.InvalidValueWrongParameters = true;
                                // continue;
                            }

                        } else {
                            // It must contain a domain name
                            if (!Uri.TryCreate($"http://{domainName}", UriKind.Absolute, out _)) {
                                analysis.InvalidValueWrongDomain = true;
                                // continue;
                            }
                        }

                        analysis.Issuer = domainName;

                        // Parse additional parameters
                        var parameters = new Dictionary<string, string>();
                        if (parts.Length > 1) {
                            var paramParts = parts[1].Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                            for (int i = 0; i < paramParts.Length; i++) {
                                var trimmedPart = paramParts[i].Trim();
                                var keyValue = trimmedPart.Split('=');
                                if (keyValue.Length == 2) {
                                    parameters[keyValue[0].Trim()] = keyValue[1].Trim(); // Trim the keys and values
                                } else {
                                    analysis.InvalidValueWrongParameters = true;
                                    // continue;
                                }
                            }
                        }

                        analysis.Parameters = parameters;
                    }
                    analysis.Value = value;
                } else {
                    analysis.InvalidFlag = true;
                    analysis.InvalidTag = true;
                    analysis.InvalidValueUnescapedQuotes = true;
                }

                if (analysis.InvalidFlag || analysis.InvalidTag || analysis.InvalidValueUnescapedQuotes || analysis.InvalidValueWrongDomain || analysis.InvalidValueWrongParameters) {
                    InvalidRecords++;
                    analysis.Invalid = true;
                } else {
                    ValidRecords++;
                    analysis.Invalid = false;
                }

                if (analysis.Tag == CAATagType.IssueMail) {
                    if (analysis.Value == ";") {
                        analysis.DenyMailCertificateIssuance = true;
                    } else {
                        analysis.AllowMailCertificateIssuance = true;
                    }
                } else if (analysis.Tag == CAATagType.Issue) {
                    if (analysis.Value == ";") {
                        analysis.DenyCertificateIssuance = true;
                    } else {
                        analysis.AllowCertificateIssuance = true;
                    }
                } else if (analysis.Tag == CAATagType.IssueWildcard) {
                    if (analysis.Value == ";") {
                        analysis.DenyWildcardCertificateIssuance = true;
                    } else {
                        analysis.AllowWildcardCertificateIssuance = true;
                    }
                } else if (analysis.Tag == CAATagType.Iodef) {
                    analysis.IsContactRecord = true;
                }

                AnalysisResults.Add(analysis);
            }

            CheckForConflicts();
            GenerateLists();
        }
        public void GenerateLists() {
            foreach (var analysis in AnalysisResults.Where(a => !a.InvalidFlag && !a.InvalidTag && !a.InvalidValueUnescapedQuotes && !a.InvalidValueWrongDomain && !a.InvalidValueWrongParameters && a.Tag == CAATagType.Issue)) {
                if (analysis.Value == ";") {
                    // Do nothing
                } else {
                    CanIssueCertificatesForDomain.Add(analysis.Issuer);
                }
            }
            foreach (var analysis in AnalysisResults.Where(a => !a.InvalidFlag && !a.InvalidTag && !a.InvalidValueUnescapedQuotes && !a.InvalidValueWrongDomain && !a.InvalidValueWrongParameters && a.Tag == CAATagType.IssueWildcard)) {
                if (analysis.Value == ";") {
                    // Do nothing
                } else {
                    CanIssueWildcardCertificatesForDomain.Add(analysis.Issuer);
                }
            }
            foreach (var analysis in AnalysisResults.Where(a => !a.InvalidFlag && !a.InvalidTag && !a.InvalidValueUnescapedQuotes && !a.InvalidValueWrongDomain && !a.InvalidValueWrongParameters && a.Tag == CAATagType.IssueMail)) {
                if (analysis.Value == ";") {

                } else {
                    CanIssueMail.Add(analysis.Value);
                }
            }
            foreach (var analysis in AnalysisResults.Where(a => a.IsContactRecord)) {
                ReportViolationEmail.Add(analysis.Value);
            }
        }

        public void CheckForConflicts() {
            var allowCertificateIssuanceRecords = AnalysisResults.Where(a => a.AllowCertificateIssuance);
            var denyCertificateIssuanceRecords = AnalysisResults.Where(a => a.DenyCertificateIssuance);
            var conflictingCertificateIssuance = allowCertificateIssuanceRecords.Any() && denyCertificateIssuanceRecords.Any();

            var allowWildcardCertificateIssuanceRecords = AnalysisResults.Where(a => a.AllowWildcardCertificateIssuance);
            var denyWildcardCertificateIssuanceRecords = AnalysisResults.Where(a => a.DenyWildcardCertificateIssuance);
            var conflictingWildcardCertificateIssuance = allowWildcardCertificateIssuanceRecords.Any() && denyWildcardCertificateIssuanceRecords.Any();

            var allowMailCertificateIssuanceRecords = AnalysisResults.Where(a => a.AllowMailCertificateIssuance);
            var denyMailCertificateIssuanceRecords = AnalysisResults.Where(a => a.DenyMailCertificateIssuance);
            var conflictingMailCertificateIssuance = allowMailCertificateIssuanceRecords.Any() && denyMailCertificateIssuanceRecords.Any();

            if (conflictingCertificateIssuance || conflictingWildcardCertificateIssuance || conflictingMailCertificateIssuance) {
                Conflicting = true;
            }

            if (conflictingCertificateIssuance) {
                ConflictingCertificateIssuance = true;
            }

            if (conflictingWildcardCertificateIssuance) {
                ConflictingWildcardCertificateIssuance = true;
            }

            if (conflictingMailCertificateIssuance) {
                ConflictingMailIssuance = true;
            }
        }


    }

    public class CAARecordAnalysis {
        public string CAARecord { get; set; }
        public string Flag { get; set; }
        public CAATagType Tag { get; set; }
        public string Value { get; set; }
        public string Issuer { get; set; }
        public bool Invalid { get; set; }
        public bool InvalidFlag { get; set; }
        public bool InvalidTag { get; set; }
        public bool InvalidValueUnescapedQuotes { get; set; }
        public bool InvalidValueWrongDomain { get; set; }
        public bool InvalidValueWrongParameters { get; set; }
        public bool DenyCertificateIssuance { get; set; }
        public bool DenyWildcardCertificateIssuance { get; set; }
        public bool DenyMailCertificateIssuance { get; set; }
        public bool AllowCertificateIssuance { get; set; }
        public bool AllowWildcardCertificateIssuance { get; set; }
        public bool AllowMailCertificateIssuance { get; set; }
        public bool IsContactRecord { get; set; }
        public Dictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();
    }

    public enum CAATagType {
        Unknown,
        Issue,
        IssueWildcard,
        Iodef,
        IssueMail
    }
}
