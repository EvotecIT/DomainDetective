using DnsClientX;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective {

    /// <summary>
    /// Performs analysis of CAA DNS records for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class CAAAnalysis {
        /// <summary>Gets or sets the domain name that provided the record.</summary>
        public string? DomainName { get; set; }

        /// <summary>
        /// Gets a short explanation of CAA record purpose.
        /// </summary>
        public string Description { get; set; } =
            @"A Certification Authority Authorization (CAA) record allows a domain to specify which certificate authorities (CAs)
are permitted to issue certificates for it.

By using CAA records, domain owners have the ability to state which certificate authorities can issue a certificate for their domain.
These records also offer a way to set notification rules in case a certificate is requested from a certificate authority that is not authorized.

In the absence of a CAA record, any CA has the permission to issue a certificate for the domain.
However, if a CAA record exists, only the CAs listed in that record(s) have the authorization to issue certificates for the hostname.

CAA records can establish policy for the entire domain or for specific hostnames, and these policies are inherited by subdomains.
As an illustration, a CAA record that is set on example.com is also applicable to subdomain.example.com.";
        /// <summary>Gets the number of syntactically valid records.</summary>
        public int ValidRecords { get; private set; }
        /// <summary>Gets the number of syntactically invalid records.</summary>
        public int InvalidRecords { get; private set; }
        /// <summary>Gets issuers allowed to issue certificates for the domain.</summary>
        public List<string> CanIssueCertificatesForDomain { get; set; } = new List<string>();
        /// <summary>Gets issuers allowed to issue wildcard certificates.</summary>
        public List<string> CanIssueWildcardCertificatesForDomain { get; set; } = new List<string>();

        /// <summary>Gets issuers authorised to issue S/MIME certificates.</summary>
        public List<string> CanIssueMail { get; set; } = new List<string>();

        /// <summary>Gets email addresses for CAA violation reports.</summary>
        public List<string> ReportViolationEmail { get; set; } = new List<string>();

        /// <summary>Gets or sets a value indicating whether conflicting directives were detected.</summary>
        public bool Conflicting { get; set; }

        /// <summary>Gets a value indicating whether duplicate issuers were found.</summary>
        public bool HasDuplicateIssuers { get; private set; }

        /// <summary>Gets or sets a value indicating conflicting mail issuance rules.</summary>
        public bool ConflictingMailIssuance { get; set; }
        /// <summary>Gets or sets a value indicating conflicting certificate issuance rules.</summary>
        public bool ConflictingCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating conflicting wildcard certificate issuance rules.</summary>
        public bool ConflictingWildcardCertificateIssuance { get; set; }

        /// <summary>Gets a value indicating whether the overall CAA configuration appears valid.</summary>
        public bool Valid {
            get {
                if (!Conflicting && InvalidRecords == 0) {
                    return true;
                } else {
                    return false;
                }
            }
        }

        /// <summary>Gets the per-record analysis results.</summary>
        public List<CAARecordAnalysis> AnalysisResults { get; private set; } = new List<CAARecordAnalysis>();

        /// <summary>
        /// Parses the supplied CAA records and populates analysis properties.
        /// </summary>
        /// <param name="dnsResults">DNS query results containing CAA records.</param>
        /// <param name="logger">Logger used for warnings and errors.</param>
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
            HasDuplicateIssuers = false;
            AnalysisResults = new List<CAARecordAnalysis>();

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var caaRecordList = dnsResults.ToList();

            if (!caaRecordList.Any()) {
                logger?.WriteVerbose("No CAA record found.");
                return;
            }

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
                if (properties.Length == 3 && int.TryParse(properties[0].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var flag)) {
                    var tag = properties[1].Trim();
                    var value = properties[2];

                    // Validate flag
                    analysis.Flag = flag.ToString();
                    if (flag < 0 || flag > 255) {
                        analysis.InvalidFlag = true;
                    } else if ((flag & 0x7F) != 0 && flag != 128) {
                        analysis.InvalidFlag = true;
                        logger?.WriteWarning($"CAA record uses reserved flag bits: {flag}");
                    }
                    analysis.Critical = (flag & 0x80) == 0x80;

                    // Validate tag and set the Tag property
                    var validTags = new Dictionary<string, CAATagType>(StringComparer.OrdinalIgnoreCase) {
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
                        if (analysis.Critical) {
                            logger?.WriteWarning("Unknown CAA property tag '{0}' flagged as critical", tag);
                        }
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
                            // Don't continue here - we still need to add this analysis to the results
                        } else {
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
            GenerateLists(logger);
        }
        /// <summary>
        /// Builds summary lists of issuers and contact addresses from <see cref="AnalysisResults"/>.
        /// </summary>
        /// <param name="logger">Logger used for duplicate warnings.</param>
        public void GenerateLists(InternalLogger logger) {
            var certificateIssuers = AnalysisResults
                .Where(a => !a.InvalidFlag && !a.InvalidTag && !a.InvalidValueUnescapedQuotes && !a.InvalidValueWrongDomain && !a.InvalidValueWrongParameters && a.Tag == CAATagType.Issue && a.Value != ";")
                .Select(a => a.Issuer)
                .ToList();

            var wildcardIssuers = AnalysisResults
                .Where(a => !a.InvalidFlag && !a.InvalidTag && !a.InvalidValueUnescapedQuotes && !a.InvalidValueWrongDomain && !a.InvalidValueWrongParameters && a.Tag == CAATagType.IssueWildcard && a.Value != ";")
                .Select(a => a.Issuer)
                .ToList();

            var mailIssuers = AnalysisResults
                .Where(a => !a.InvalidFlag && !a.InvalidTag && !a.InvalidValueUnescapedQuotes && !a.InvalidValueWrongDomain && !a.InvalidValueWrongParameters && a.Tag == CAATagType.IssueMail && a.Value != ";")
                .Select(a => a.Value)
                .ToList();

            var emails = AnalysisResults
                .Where(a => a.IsContactRecord)
                .Select(a => a.Value)
                .ToList();

            HasDuplicateIssuers =
                certificateIssuers.Count != certificateIssuers.Distinct(StringComparer.OrdinalIgnoreCase).Count() ||
                wildcardIssuers.Count != wildcardIssuers.Distinct(StringComparer.OrdinalIgnoreCase).Count() ||
                mailIssuers.Count != mailIssuers.Distinct(StringComparer.OrdinalIgnoreCase).Count();

            if (HasDuplicateIssuers) {
                logger.WriteWarning($"Duplicate CAA issuers detected for {DomainName}");
            }

            CanIssueCertificatesForDomain = certificateIssuers.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            CanIssueWildcardCertificatesForDomain = wildcardIssuers.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            CanIssueMail = mailIssuers.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            ReportViolationEmail = emails.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>
        /// Sets conflict flags based on <see cref="AnalysisResults"/> content.
        /// </summary>
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

    /// <summary>
    /// Detailed breakdown of a single CAA DNS record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class CAARecordAnalysis {
        /// <summary>Gets or sets the raw CAA record text.</summary>
        public string CAARecord { get; set; }
        /// <summary>Gets or sets the flag field.</summary>
        public string Flag { get; set; }
        /// <summary>Gets or sets a value indicating whether the critical bit is set.</summary>
        public bool Critical { get; set; }
        /// <summary>Gets or sets the parsed tag type.</summary>
        public CAATagType Tag { get; set; }
        /// <summary>Gets or sets the record value.</summary>
        public string Value { get; set; }
        /// <summary>Gets or sets the issuer domain name.</summary>
        public string Issuer { get; set; }
        /// <summary>Gets or sets a value indicating whether the record failed validation.</summary>
        public bool Invalid { get; set; }
        /// <summary>Gets or sets a value indicating an invalid flag field.</summary>
        public bool InvalidFlag { get; set; }
        /// <summary>Gets or sets a value indicating an unrecognised tag.</summary>
        public bool InvalidTag { get; set; }
        /// <summary>Gets or sets a value indicating unescaped quotes in the value field.</summary>
        public bool InvalidValueUnescapedQuotes { get; set; }
        /// <summary>Gets or sets a value indicating that the value contained an invalid domain.</summary>
        public bool InvalidValueWrongDomain { get; set; }
        /// <summary>Gets or sets a value indicating malformed additional parameters.</summary>
        public bool InvalidValueWrongParameters { get; set; }
        /// <summary>Gets or sets a value indicating that certificate issuance is denied.</summary>
        public bool DenyCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating that wildcard certificate issuance is denied.</summary>
        public bool DenyWildcardCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating that S/MIME certificate issuance is denied.</summary>
        public bool DenyMailCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating that certificate issuance is allowed.</summary>
        public bool AllowCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating that wildcard certificate issuance is allowed.</summary>
        public bool AllowWildcardCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating that S/MIME certificate issuance is allowed.</summary>
        public bool AllowMailCertificateIssuance { get; set; }
        /// <summary>Gets or sets a value indicating that the record is a contact record.</summary>
        public bool IsContactRecord { get; set; }
        /// <summary>Gets or sets additional key/value parameters.</summary>
        public Dictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();
    }

}