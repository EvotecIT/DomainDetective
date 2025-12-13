using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    ///
    ///
    /// To analyze DMARC records, you would need to follow the DMARC specification(RFC 7489). Here are some of the key points:
    /// 1.	The DMARC record must start with "v=DMARC1".
    /// 2.	The DMARC record should not have more than 255 characters.
    /// 3.	The DMARC record should have a valid "p" tag, which is the policy tag.It can have three values: "none", "quarantine", or "reject".
    /// 4.	The DMARC record can have an optional "rua" tag, which is the URI for aggregate reports.
    /// 5.	The DMARC record can have an optional "ruf" tag, which is the URI for forensic reports.
    /// 6.	The DMARC record can have an optional "pct" tag, which is the percentage of messages subjected to filtering.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// DMARC TXT records are parsed and validated according to RFC 7489 with
    /// additional checks for common mistakes such as missing rua addresses.
    /// DMARCbis handling follows draft-ietf-dmarcbis-base:
    /// https://datatracker.ietf.org/doc/html/draft-ietf-dmarcbis-base
    /// </remarks>
    public class DmarcAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        private const string TagVersion = "v";
        private const string TagPolicy = "p";
        private const string TagSubPolicy = "sp";
        private const string TagReportingInterval = "ri";
        private const string TagFailureOptions = "fo";
        private const string TagPercent = "pct"; // deprecated in DMARCbis draft (draft-ietf-dmarcbis-base)
        private const string TagDkimAlignment = "adkim";
        private const string TagSpfAlignment = "aspf";
        private const string TagRua = "rua";
        private const string TagRuf = "ruf";
        // DMARCbis tags defined in draft-ietf-dmarcbis-base
        // https://datatracker.ietf.org/doc/html/draft-ietf-dmarcbis-base
        private const string TagNonexistentPolicy = "np";
        private const string TagPublicSuffixPolicy = "psd";
        private const string TagReportFeedback = "rfb";
        private const string TagReportFormat = "rf"; // deprecated in DMARCbis draft (draft-ietf-dmarcbis-base)
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        public Dictionary<string, bool> ExternalReportAuthorization { get; private set; } = new();
        public string DmarcRecord { get; private set; } = string.Empty;
        public bool DmarcRecordExists { get; private set; } // should be true
        public bool MultipleRecords { get; private set; }
        public bool StartsCorrectly { get; private set; } // should be true
        public bool ExceedsCharacterLimit { get; private set; } // should be false
        public bool HasMandatoryTags { get; private set; }
        public bool IsPolicyValid { get; private set; }

        public string Policy => TranslatePolicy(PolicyShort);
        public string SubPolicy => TranslateSubPolicy();
        public string ReportingInterval => TranslateReportingInterval(ReportingIntervalShort);
        public string Percent => TranslatePercentage();
        public string SpfAlignment => TranslateAlignment(SpfAShort);
        public string DkimAlignment => TranslateAlignment(DkimAShort);
        public string FailureReportingOptions => TranslateFailureReportingOptions(FoShort);
        public string NonexistentPolicy => TranslatePolicy(NonexistentPolicyShort);
        public string PublicSuffixPolicy => TranslatePolicy(PublicSuffixPolicyShort);
        public string ReportFeedback => RfbShort;

        public bool ValidDkimAlignment { get; private set; }
        public bool ValidSpfAlignment { get; private set; }

        /// <summary>True when <c>p=none</c> or <c>sp=none</c> is detected.</summary>
        public bool WeakPolicy { get; private set; }

        /// <summary>Recommendation message when a weak policy is found.</summary>
        public string? PolicyRecommendation { get; private set; }

        /// <summary>Summary message describing DMARC status.</summary>
        public string Advisory { get; private set; } = string.Empty;

        /// <summary>Indicates whether the SPF domain aligns with the policy.</summary>
        public bool SpfAligned { get; private set; }
        /// <summary>Indicates whether the DKIM domain aligns with the policy.</summary>
        public bool DkimAligned { get; private set; }

        public bool InvalidReportUri { get; private set; }

        public string Rua { get; private set; } = string.Empty;
        public List<string> MailtoRua { get; private set; } = new List<string>();
        public List<string> HttpRua { get; private set; } = new List<string>();
        public string Ruf { get; private set; } = string.Empty;
        public List<string> MailtoRuf { get; private set; } = new List<string>();
        public List<string> HttpRuf { get; private set; } = new List<string>();
        public List<long?> RufSizeLimits { get; private set; } = new List<long?>();
        public List<string> UnknownTags { get; private set; } = new List<string>();
        public List<string> DeprecatedTags { get; private set; } = new List<string>();

        // short versions of the tags
        public string SubPolicyShort { get; private set; }
        public string PolicyShort { get; private set; }
        public string FoShort { get; private set; }
        public string DkimAShort { get; private set; }
        public string SpfAShort { get; private set; }
        public string NonexistentPolicyShort { get; private set; }
        public string PublicSuffixPolicyShort { get; private set; }
        public string RfbShort { get; private set; }
        public int? Pct { get; private set; }
        public int? OriginalPct { get; private set; }
        public bool IsPctValid { get; private set; }
        public string ReportingIntervalShort { get; private set; }

        private const int DefaultReportingInterval = 86400;

        /// <summary>Structured assessments observed during DMARC analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        public async Task AnalyzeDmarcRecords(
            IEnumerable<DnsAnswer> dnsResults,
            InternalLogger logger,
            string? domainName = null,
            Func<string, string>? getOrgDomain = null) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DMARC", target: domainName);
            // reset all properties so repeated calls don't accumulate data
            DnsConfiguration ??= new DnsConfiguration();
            DmarcRecord = string.Empty;
            DmarcRecordExists = false;
            MultipleRecords = false;
            StartsCorrectly = false;
            ExceedsCharacterLimit = false;
            HasMandatoryTags = false;
            IsPolicyValid = false;
            IsPctValid = true;
            Rua = string.Empty;
            MailtoRua = new List<string>();
            HttpRua = new List<string>();
            Ruf = string.Empty;
            MailtoRuf = new List<string>();
            HttpRuf = new List<string>();
            RufSizeLimits = new List<long?>();
            UnknownTags = new List<string>();
            DeprecatedTags = new List<string>();
            SubPolicyShort = string.Empty;
            PolicyShort = string.Empty;
            FoShort = string.Empty;
            DkimAShort = string.Empty;
            SpfAShort = string.Empty;
            NonexistentPolicyShort = string.Empty;
            PublicSuffixPolicyShort = string.Empty;
            RfbShort = string.Empty;
            ValidDkimAlignment = true;
            ValidSpfAlignment = true;
            InvalidReportUri = false;
            Pct = null;
            OriginalPct = null;
            ReportingIntervalShort = string.Empty;
            ExternalReportAuthorization = new Dictionary<string, bool>();
            Advisory = string.Empty;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var dmarcRecordList = dnsResults.ToList();
            DmarcRecordExists = dmarcRecordList.Any();
            MultipleRecords = dmarcRecordList.Count > 1;

            // concatenate all TXT chunks into a single string separated by spaces
            DmarcRecord = string.Join(" ", dmarcRecordList.Select(record => record.Data));

            if (!DmarcRecordExists || DmarcRecord == null) {
                logger.WriteVerbose("No DMARC record found.");
                logger?.WriteWarningCode(DmarcCodes.MissingRecord, "No DMARC record found.");
                return;
            }

            logger.WriteVerbose($"Analyzing DMARC record {DmarcRecord}");

            // check the character limit
            ExceedsCharacterLimit = DmarcRecord.Trim().Length > 255;
            if (ExceedsCharacterLimit) {
                logger?.WriteWarningCode(DmarcCodes.RecordLengthExceeds, "DMARC record exceeds 255 characters.");
            }

            // check the DMARC record starts correctly
            StartsCorrectly = DmarcRecord.StartsWith("v=DMARC1");
            if (!StartsCorrectly) {
                logger?.WriteWarningCode(DmarcCodes.StartsInvalid, "DMARC record does not start with v=DMARC1.");
            }

            if (MultipleRecords) {
                logger?.WriteWarningCode(DmarcCodes.MultipleRecords, "Multiple DMARC records published.");
            }

            // loop through the tags of the DMARC record
            var tags = DmarcRecord.Split(';');
            var policyTagFound = false;
            foreach (var tag in tags) {
                var keyValue = tag.Split('=');
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case TagVersion:
                            break;
                        case TagPolicy:
                            PolicyShort = value;
                            policyTagFound = true;
                            IsPolicyValid = value == "none" || value == "quarantine" || value == "reject";
                            break;
                        case TagSubPolicy:
                            SubPolicyShort = value;
                            break;
                        case TagReportingInterval:
                            // RFC 7489 section 6.3 defines 'ri' as the reporting
                            // interval in seconds. The raw value is stored here.
                            // TranslateReportingInterval will warn and default to
                            // 86400 seconds if parsing fails or the value is zero.
                            ReportingIntervalShort = value;
                            _ = TranslateReportingInterval(ReportingIntervalShort, logger);
                            break;
                        case TagFailureOptions:
                            FoShort = value;
                            break;
                        case TagPercent:
                            // RFC 7489 section 6.3 defines 'pct' as the
                            // percentage of messages to which the DMARC policy
                            // applies.  It should be a number between 0 and 100.
                            if (int.TryParse(value, out var pct)) {
                                OriginalPct = pct;
                                IsPctValid = pct >= 0 && pct <= 100;
                                Pct = pct;
                                if (Pct < 0) {
                                    Pct = 0;
                                }
                                if (Pct > 100) {
                                    Pct = 100;
                                }
                            } else {
                                IsPctValid = false;
                            }
                            var pctPair = $"{key}={value}";
                            if (!DeprecatedTags.Contains(pctPair)) {
                                DeprecatedTags.Add(pctPair);
                                logger?.WriteWarningCode(DmarcCodes.TagDeprecated, "Tag {0} is deprecated in DMARCbis draft (draft-ietf-dmarcbis-base).", key);
                            }
                            break;
                        case TagDkimAlignment:
                            DkimAShort = value;
                            ValidDkimAlignment = value == "s" || value == "r";
                            if (!ValidDkimAlignment) {
                                logger?.WriteWarningCode(DmarcCodes.AlignmentInvalid, $"Invalid adkim value '{value}', expected 's' or 'r'");
                            }
                            break;
                        case TagSpfAlignment:
                            SpfAShort = value;
                            ValidSpfAlignment = value == "s" || value == "r";
                            if (!ValidSpfAlignment) {
                                logger?.WriteWarningCode(DmarcCodes.AlignmentInvalid, $"Invalid aspf value '{value}', expected 's' or 'r'");
                            }
                            break;
                        case TagRua:
                            Rua = value;
                            AddUriToList(value, MailtoRua, HttpRua, logger);
                            break;
                        case TagRuf:
                            Ruf = value;
                            AddUriToList(value, MailtoRuf, HttpRuf, logger, true);
                            break;
                        case TagNonexistentPolicy:
                            NonexistentPolicyShort = value;
                            break;
                        case TagPublicSuffixPolicy:
                            PublicSuffixPolicyShort = value;
                            break;
                        case TagReportFeedback:
                            RfbShort = value;
                            break;
                        case TagReportFormat:
                            var rfPair = $"{key}={value}";
                            if (!DeprecatedTags.Contains(rfPair)) {
                                DeprecatedTags.Add(rfPair);
                                logger?.WriteWarningCode(DmarcCodes.TagDeprecated, "Tag {0} is deprecated in DMARCbis draft (draft-ietf-dmarcbis-base).", key);
                            }
                            break;
                        default:
                            var tagPair = $"{key}={value}";
                            if (!UnknownTags.Contains(tagPair)) {
                                UnknownTags.Add(tagPair);
                            }
                            break;
                    }
                } else if (!string.IsNullOrWhiteSpace(tag)) {
                    var unknown = tag.Trim();
                    if (!UnknownTags.Contains(unknown)) {
                        UnknownTags.Add(unknown);
                    }
                }
            }

            var reportDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? orgDomain = null;
            if (domainName != null && getOrgDomain != null) {
                orgDomain = getOrgDomain(domainName);
            }
            foreach (var mail in MailtoRua.Concat(MailtoRuf)) {
                var at = mail.IndexOf('@');
                if (at > -1 && at < mail.Length - 1) {
                    var domain = mail.Substring(at + 1);
                    reportDomains.Add(domain);
                    if (orgDomain != null && getOrgDomain != null &&
                        !string.Equals(getOrgDomain(domain), orgDomain, StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteWarningCode(DmarcCodes.AlignmentMismatch, "Report address {0} is not aligned with {1}.", mail, domainName);
                    }
                }
            }
            foreach (var http in HttpRua.Concat(HttpRuf)) {
                if (Uri.TryCreate(http, UriKind.Absolute, out var uri)) {
                    reportDomains.Add(uri.Host);
                    if (orgDomain != null && getOrgDomain != null &&
                        !string.Equals(getOrgDomain(uri.Host), orgDomain, StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteWarningCode(DmarcCodes.AlignmentMismatch, "Report address {0} is not aligned with {1}.", http, domainName);
                    }
                }
            }

            foreach (var domain in reportDomains) {
                if (domainName != null && domain.Equals(domainName, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                var records = await QueryDns($"_report._dmarc.{domain}", DnsRecordType.TXT);
                var authorized = records != null && records.Any(r => r.Data.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
                ExternalReportAuthorization[domain] = authorized;
            }
            // verify mandatory tags
            HasMandatoryTags = StartsCorrectly && policyTagFound;
            // set the default value for the pct tag if it is not present
            Pct ??= 100;
            UpdateAdvisory();
            // Add high-level advisories as info assessments for consumers
            if (!string.IsNullOrWhiteSpace(PolicyRecommendation)) {
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Info,
                    Category = "DMARC",
                    Target = domainName,
                    Code = "DMARC.Policy.Recommendation",
                    Message = PolicyRecommendation
                });
            }

            // Info-level positives (posture signals)
            if (DmarcRecordExists)
                logger?.WriteInformationCode(DmarcCodes.Present, "DMARC record present");
            if (StartsCorrectly)
                logger?.WriteInformationCode(DmarcCodes.StartsV1, "DMARC starts with v=DMARC1");
            if (string.Equals(PolicyShort, "reject", StringComparison.OrdinalIgnoreCase))
                logger?.WriteInformationCode(DmarcCodes.PolicyReject, "DMARC policy reject in effect");
            else if (string.Equals(PolicyShort, "quarantine", StringComparison.OrdinalIgnoreCase))
                logger?.WriteInformationCode(DmarcCodes.PolicyQuarantine, "DMARC policy quarantine in effect");
            var ruaCount = MailtoRua?.Count ?? 0;
            if (ruaCount > 0)
                logger?.WriteInformationCode(DmarcCodes.RuaPresent, $"Aggregate reporting (rua) configured: {ruaCount} address(es)");
            var rufCount = (MailtoRuf?.Count ?? 0) + (HttpRuf?.Count ?? 0);
            if (rufCount > 0)
                logger?.WriteInformationCode(DmarcCodes.RufPresent, $"Forensic reporting (ruf) configured: {rufCount} address(es)");
            if (string.Equals(DkimAShort, "s", StringComparison.OrdinalIgnoreCase))
                logger?.WriteInformationCode(DmarcCodes.AlignmentStrictDkim, "DKIM alignment strict (adkim=s)");
            if (string.Equals(SpfAShort, "s", StringComparison.OrdinalIgnoreCase))
                logger?.WriteInformationCode(DmarcCodes.AlignmentStrictSpf, "SPF alignment strict (aspf=s)");
            if (Pct.HasValue && Pct.Value >= 100)
                logger?.WriteInformationCode(DmarcCodes.Percent100, "pct=100 (full enforcement)");
        }

        private void AddUriToList(string uri, List<string> mailtoList, List<string> httpList, InternalLogger? logger = null, bool isRuf = false) {
            var uris = uri.Split(',');
            foreach (var raw in uris) {
                var u = raw.Trim();
                long? sizeLimit = null;
                var exIdx = u.LastIndexOf('!');
                if (exIdx > -1 && exIdx < u.Length - 1) {
                    var sizePart = u.Substring(exIdx + 1);
                    var parsedSize = ParseSize(sizePart);
                    if (parsedSize.HasValue) {
                        sizeLimit = parsedSize.Value;
                        u = u.Substring(0, exIdx);
                    }
                }
                if (u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                    var addressPart = u.Substring(7);
                    try {
                        var decoded = Uri.UnescapeDataString(addressPart);
                        _ = new System.Net.Mail.MailAddress(decoded);
                        mailtoList.Add(decoded);
                    } catch {
                        InvalidReportUri = true;
                        logger?.WriteWarningCode(DmarcCodes.UriInvalid, "Report URI {0} is not a valid email address.", u);
                    }
                    if (isRuf) {
                        RufSizeLimits.Add(sizeLimit);
                        if (sizeLimit.HasValue && sizeLimit.Value > 10 * 1024 * 1024) {
                            logger?.WriteWarningCode(DmarcCodes.RufTooLarge, "Forensic report size {0} exceeds 10MB.", sizeLimit.Value);
                        }
                    }
                    continue;
                }

                if (!Uri.TryCreate(u, UriKind.Absolute, out var parsed)) {
                    logger?.WriteWarningCode(DmarcCodes.UriMissingScheme, "Report URI {0} is missing a scheme.", u);
                    InvalidReportUri = true;
                    continue;
                }

                if (parsed.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) {
                    httpList.Add(u);
                } else if (parsed.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    logger?.WriteWarningCode(DmarcCodes.UriInsecure, "Report URI {0} uses HTTP instead of HTTPS.", u);
                    httpList.Add(u);
                } else {
                    logger?.WriteWarningCode(DmarcCodes.UriMissingScheme, "Report URI {0} is missing a scheme.", u);
                    InvalidReportUri = true;
                }
                if (isRuf) {
                    RufSizeLimits.Add(sizeLimit);
                    if (sizeLimit.HasValue && sizeLimit.Value > 10 * 1024 * 1024) {
                        logger?.WriteWarningCode(DmarcCodes.RufTooLarge, "Forensic report size {0} exceeds 10MB.", sizeLimit.Value);
                    }
                }
            }
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }
            try {
                return await DnsConfiguration.QueryDNS(name, type);
            } catch (Exception ex) when (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException) {
                // Log and continue with empty results to avoid flaky failures in constrained CI/network
                Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DMARC",
                    Target = name,
                    Code = DmarcCodes.QueryFailed,
                    Message = $"DMARC DNS query failed: {ex.Message}"
                });
                return Array.Empty<DnsAnswer>();
            }
        }
        private string TranslateAlignment(string alignment) {
            return alignment switch {
                "s" => "Strict",
                "r" => "Relaxed",
                null or "" => "Relaxed (defaulted)", // default to relaxed if no value is provided
                _ => "Unknown",
            };
        }

        private string TranslatePolicy(string policy) {
            return policy switch {
                "none" => "No policy",
                "quarantine" => "Quarantine",
                "reject" => "Reject",
                _ => "Unknown policy",
            };
        }

        private string TranslateSubPolicy() {
            if (!string.IsNullOrWhiteSpace(SubPolicyShort)) {
                return TranslatePolicy(SubPolicyShort);
            }

            if (!string.IsNullOrWhiteSpace(PolicyShort)) {
                return $"{TranslatePolicy(PolicyShort)} (inherited)";
            }

            return "Unknown policy";
        }

        private string TranslateFailureReportingOptions(string option) {
            return option switch {
                "0" => "Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned 'pass' result.",
                "1" => "Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned 'pass' result.",
                "d" => "Generate a DKIM failure report if the message had a signature that failed evaluation.",
                "s" => "Generate an SPF failure report if the message failed SPF evaluation.",
                _ => "Unknown option",
            };
        }

        private string TranslatePercentage() {
            if (!IsPctValid) {
                return "Percentage value must be between 0 and 100.";
            }

            return $"{Pct}% of messages are subjected to filtering.";
        }

        private string TranslateReportingInterval(string interval, InternalLogger? logger = null) {
            // convert the raw 'ri' tag value to days
            if (!int.TryParse(interval, out var seconds)) {
                logger?.WriteWarningCode(
                    DmarcCodes.ReportingIntervalInvalid,
                    "Invalid reporting interval '{0}'. Defaulting to {1} seconds.",
                    interval,
                    DefaultReportingInterval);
                seconds = DefaultReportingInterval;
                ReportingIntervalShort = DefaultReportingInterval.ToString();
            }

            if (seconds <= 0) {
                logger?.WriteWarningCode(
                    DmarcCodes.ReportingIntervalZeroOrNegative,
                    "Reporting interval is zero or negative. Resetting to default value of {0} seconds.",
                    DefaultReportingInterval);
                seconds = DefaultReportingInterval;
                ReportingIntervalShort = DefaultReportingInterval.ToString();
            }

            return $"{seconds / 86400} days";
        }

        private static long? ParseSize(string sizePart) {
            if (string.IsNullOrWhiteSpace(sizePart)) {
                return null;
            }

            var match = Regex.Match(sizePart, "^([0-9]+)([kKmMgGtT])?$");
            if (!match.Success) {
                return null;
            }

            var value = long.Parse(match.Groups[1].Value);
            return match.Groups[2].Value.ToLowerInvariant() switch {
                "k" => value * 1024L,
                "m" => value * 1024L * 1024L,
                "g" => value * 1024L * 1024L * 1024L,
                "t" => value * 1024L * 1024L * 1024L * 1024L,
                _ => value,
            };
        }

        /// <summary>
        /// Evaluates SPF and DKIM alignment for the provided domains.
        /// </summary>
        /// <param name="fromDomain">Domain from the RFC5322.From header.</param>
        /// <param name="spfDomain">Domain authenticated via SPF.</param>
        /// <param name="dkimDomain">Domain from the DKIM signature.</param>
        /// <param name="getOrgDomain">Function returning the organisational domain for a given input.</param>
        public void EvaluateAlignment(string fromDomain, string? spfDomain, string? dkimDomain, Func<string, string> getOrgDomain) {
            if (fromDomain == null) {
                throw new ArgumentNullException(nameof(fromDomain));
            }
            if (getOrgDomain == null) {
                throw new ArgumentNullException(nameof(getOrgDomain));
            }

            var fromOrg = getOrgDomain(fromDomain);
            var spfPolicy = string.IsNullOrEmpty(SpfAShort) ? "r" : SpfAShort;
            var dkimPolicy = string.IsNullOrEmpty(DkimAShort) ? "r" : DkimAShort;

            if (!string.IsNullOrWhiteSpace(spfDomain)) {
                var spfOrg = getOrgDomain(spfDomain);
                SpfAligned = spfPolicy == "s"
                    ? string.Equals(fromDomain, spfDomain, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(fromOrg, spfOrg, StringComparison.OrdinalIgnoreCase);
            } else {
                SpfAligned = false;
            }

            if (!string.IsNullOrWhiteSpace(dkimDomain)) {
                var dkimOrg = getOrgDomain(dkimDomain);
                DkimAligned = dkimPolicy == "s"
                    ? string.Equals(fromDomain, dkimDomain, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(fromOrg, dkimOrg, StringComparison.OrdinalIgnoreCase);
            } else {
                DkimAligned = false;
            }
        }

        /// <summary>
        /// Flags DMARC policies set to <c>none</c> and suggests a stronger policy.
        /// </summary>
        /// <param name="checkSubdomainPolicy">Evaluates the <c>sp</c> tag when true.</param>
        public void EvaluatePolicyStrength(bool checkSubdomainPolicy = false) {
            var policy = checkSubdomainPolicy && !string.IsNullOrWhiteSpace(SubPolicyShort)
                ? SubPolicyShort
                : PolicyShort;

            WeakPolicy = string.Equals(policy, "none", StringComparison.OrdinalIgnoreCase);
            PolicyRecommendation = WeakPolicy ? "Consider quarantine or reject." : string.Empty;
            UpdateAdvisory();
        }

        private void UpdateAdvisory() {
            if (!DmarcRecordExists) {
                Advisory = "No DMARC record found.";
            } else if (!StartsCorrectly || !HasMandatoryTags || !IsPolicyValid) {
                Advisory = "DMARC record misconfigured.";
            } else if (WeakPolicy) {
                Advisory = "DMARC policy is weak.";
            } else {
                Advisory = $"DMARC policy {PolicyShort} in effect.";
            }
        }



    }
}
