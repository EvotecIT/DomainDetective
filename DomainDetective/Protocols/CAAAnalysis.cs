// Ensure these using statements are present at the top of CAAAnalysis.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks; // Ensure this is not commented out
using DnsClientX; // Make sure this is available

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
    await Task.Yield();

    var caaRecordList = dnsResults.ToList();

    if (caaRecordList.Any() && !string.IsNullOrEmpty(caaRecordList.First().Name)) {
        DomainName = caaRecordList.First().Name;
    } else if (string.IsNullOrEmpty(DomainName) && logger != null) {
        DomainName = "Unknown";
        logger.WriteVerbose("CAAAnalysis.DomainName initialized to 'Unknown' as it was not set and not available from DNS results.");
    }

    foreach (var record in caaRecordList) {
        var analysis = new CAARecordAnalysis();
        string caaRecordString = null;

        if (record.Data != null && record.Data.Any()) {
            caaRecordString = string.Join("", record.Data);
        }
        else if (!string.IsNullOrEmpty(record.DataRaw)) {
            caaRecordString = record.DataRaw;
        }

        if (string.IsNullOrEmpty(caaRecordString)) {
            if (logger != null) logger.WriteWarning($"CAA record string is null or empty for record name '{record.Name}'. Skipping analysis.");
            analysis.Invalid = true;
            analysis.CAARecord = "[EMPTY OR INVALID RECORD DATA]";
            analysis.InvalidTag = true;
            AnalysisResults.Add(analysis);
            InvalidRecords++;
            continue;
        }

        if (logger != null) logger.WriteVerbose($"Analyzing CAA record '{caaRecordString}' for domain '{DomainName}'");
        analysis.CAARecord = caaRecordString;
        var properties = caaRecordString.Split(new[] { ' ' }, 3);

        if (properties.Length == 3 && int.TryParse(properties[0].Trim(), out var flagValue)) {
            if (flagValue < 0 || flagValue > 255) {
                analysis.InvalidFlag = true;
            }

            var tag = properties[1].Trim();
            var value = properties[2]; // Keep original value with quotes for unquoting logic

            var validTags = new Dictionary<string, CAATagType> {
                { "issue", CAATagType.Issue }, { "issuewild", CAATagType.IssueWildcard },
                { "iodef", CAATagType.Iodef }, { "issuemail", CAATagType.IssueMail }
            };
            if (validTags.TryGetValue(tag.ToLowerInvariant(), out var tagType)) {
                analysis.Tag = tagType;
            } else {
                analysis.Tag = CAATagType.Unknown;
                analysis.InvalidTag = true;
            }

            bool isValueQuoted = value.Length >= 2 && value.StartsWith("\"") && value.EndsWith("\"");
            if (isValueQuoted) {
                 value = value.Substring(1, value.Length - 2); // Remove quotes
                 if (value.Contains("\"")) { analysis.InvalidValueUnescapedQuotes = true; }
                 value = value.Replace("\\\"", "\""); // Handle escaped quotes
            }
            // No further trim on 'value' here, allow spaces if quoted.
            analysis.Value = value;

            if (analysis.Tag == CAATagType.Issue || analysis.Tag == CAATagType.IssueWildcard || analysis.Tag == CAATagType.IssueMail) {
                if (value == ";") {
                    analysis.Issuer = null;
                } else {
                    var valueParts = value.Split(new[] { ';' }, 2);
                    var domainNameStr = valueParts[0].Trim();
                    if (string.IsNullOrEmpty(domainNameStr)) {
                         analysis.InvalidValueWrongDomain = true;
                    } else {
                        // For issue/issuewild, issuer must be a domain.
                        // For issuemail, it's a "policy URL", could be mailto or https.
                        if (analysis.Tag == CAATagType.IssueMail) {
                            Uri mailUri = null; // Declare mailUri here
                            if (!domainNameStr.ToLowerInvariant().StartsWith("mailto:") && !Uri.TryCreate(domainNameStr, UriKind.Absolute, out mailUri) || (mailUri?.Scheme != Uri.UriSchemeHttps)) {
                                // Simplified: if not mailto:, assume it should be https for issuemail policy URL if not a domain.
                                // This part might need more nuance based on exact RFC interpretation for issuemail values.
                                // Consider adding analysis.InvalidValueWrongDomain = true; here if condition is met.
                            }
                        } else { // issue, issuewild
                           if (!domainNameStr.Contains(".") || domainNameStr.Contains(" ") || domainNameStr.Contains(":")) { // Basic domain check
                                analysis.InvalidValueWrongDomain = true;
                           }
                        }
                        analysis.Issuer = domainNameStr; // Store it regardless of validity for now
                    }

                    if (valueParts.Length > 1) {
                        var paramString = valueParts[1];
                        var paramPartsArray = paramString.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var paramPairStr in paramPartsArray) {
                            var kv = paramPairStr.Trim().Split(new[] { '=' }, 2);
                            if (kv.Length == 2) {
                                analysis.Parameters[kv[0].Trim().ToLowerInvariant()] = kv[1].Trim();
                            } else {
                                analysis.InvalidValueWrongParameters = true;
                            }
                        }
                    }
                }
            } else if (analysis.Tag == CAATagType.Iodef) {
                if (string.IsNullOrWhiteSpace(value) ||
                    (!value.ToLowerInvariant().StartsWith("mailto:") &&
                     !(Uri.TryCreate(value, UriKind.Absolute, out var uriResultIodef) &&
                       (uriResultIodef.Scheme == Uri.UriSchemeHttp || uriResultIodef.Scheme == Uri.UriSchemeHttps)))) {
                    analysis.InvalidValueWrongDomain = true;
                }
            }
        } else {
            analysis.InvalidFlag = true;
            analysis.InvalidTag = true;
        }

        if (analysis.InvalidFlag || analysis.InvalidTag || analysis.InvalidValueUnescapedQuotes || analysis.InvalidValueWrongDomain || analysis.InvalidValueWrongParameters) {
            analysis.Invalid = true;
        }

        if (!analysis.Invalid) {
            if (analysis.Tag == CAATagType.Issue) { analysis.AllowCertificateIssuance = (analysis.Value != ";"); analysis.DenyCertificateIssuance = (analysis.Value == ";");}
            else if (analysis.Tag == CAATagType.IssueWildcard) { analysis.AllowWildcardCertificateIssuance = (analysis.Value != ";"); analysis.DenyWildcardCertificateIssuance = (analysis.Value == ";");}
            else if (analysis.Tag == CAATagType.IssueMail) { analysis.AllowMailCertificateIssuance = (analysis.Value != ";"); analysis.DenyMailCertificateIssuance = (analysis.Value == ";");}
            else if (analysis.Tag == CAATagType.Iodef) analysis.IsContactRecord = true;
        }

        AnalysisResults.Add(analysis);
        if (analysis.Invalid) InvalidRecords++; else ValidRecords++;
    }

    CheckForConflicts();
    GenerateLists();
}

public void GenerateLists() {
    CanIssueCertificatesForDomain.Clear();
    CanIssueWildcardCertificatesForDomain.Clear();
    CanIssueMail.Clear();
    ReportViolationEmail.Clear();

    // Corrected: Use 'a.AllowCertificateIssuance' (lambda variable)
    foreach (var analysisEntry in AnalysisResults.Where(a => !a.Invalid && a.Tag == CAATagType.Issue && a.AllowCertificateIssuance)) {
        if (!string.IsNullOrEmpty(analysisEntry.Issuer)) {
            CanIssueCertificatesForDomain.Add(analysisEntry.Issuer);
        }
    }
    // Corrected: Use 'a.AllowWildcardCertificateIssuance'
    foreach (var analysisEntry in AnalysisResults.Where(a => !a.Invalid && a.Tag == CAATagType.IssueWildcard && a.AllowWildcardCertificateIssuance)) {
         if (!string.IsNullOrEmpty(analysisEntry.Issuer)) {
            CanIssueWildcardCertificatesForDomain.Add(analysisEntry.Issuer);
        }
    }
    // Corrected: Use 'a.AllowMailCertificateIssuance' and 'analysisEntry.Issuer'
    foreach (var analysisEntry in AnalysisResults.Where(a => !a.Invalid && a.Tag == CAATagType.IssueMail && a.AllowMailCertificateIssuance)) {
         if (!string.IsNullOrEmpty(analysisEntry.Issuer)) {
            CanIssueMail.Add(analysisEntry.Issuer);
        }
    }
    foreach (var analysisEntry in AnalysisResults.Where(a => !a.Invalid && a.IsContactRecord && a.Tag == CAATagType.Iodef)) {
        if (!string.IsNullOrEmpty(analysisEntry.Value)) {
            ReportViolationEmail.Add(analysisEntry.Value);
        }
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
    public string CAARecord { get; set; } = string.Empty;
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
