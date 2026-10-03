using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Threading;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    /// Analyzes DMARC policy tags, reporting destinations, and authenticated identifier alignment.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// RFC 9989 discovery and alignment use DNS organizational boundaries. The resolver-supplied
    /// synchronous alignment API retains explicit RFC 7489 public-suffix compatibility.
    /// TXT character strings are concatenated without imposing a 255-byte limit on the complete policy.
    /// </remarks>
    public partial class DmarcAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>DNS TTL (seconds) of the DMARC TXT record as returned by DNS.</summary>
        public int? DnsRecordTtl { get; private set; }
        /// <summary>TTL (seconds) of the CNAME record when this record was resolved via CNAME alias.</summary>
        public int? CnameTtl { get; private set; }
        /// <summary>True when the DMARC record was resolved through a CNAME alias.</summary>
        public bool IsCnameResolved { get; private set; }
        private const string TagVersion = "v";
        private const string TagPolicy = "p";
        private const string TagSubPolicy = "sp";
        private const string TagReportingInterval = "ri";
        private const string TagFailureOptions = "fo";
        private const string TagPercent = "pct"; // obsolete in RFC 9989
        private const string TagDkimAlignment = "adkim";
        private const string TagSpfAlignment = "aspf";
        private const string TagRua = "rua";
        private const string TagRuf = "ruf";
        // Current DMARC policy tags, with older reporting tags retained for diagnostics.
        private const string TagNonexistentPolicy = "np";
        private const string TagPublicSuffixPolicy = "psd";
        private const string TagTestMode = "t";
        private const string TagReportFeedback = "rfb";
        private const string TagReportFormat = "rf"; // obsolete in RFC 9989
        /// <summary>Gets or sets the dns configuration value.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();
        /// <summary>Represents the query dns override value.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        /// <summary>Gets or sets the external report authorization value.</summary>
        public Dictionary<string, bool> ExternalReportAuthorization { get; private set; } = new();
        /// <summary>Gets or sets the dmarc record value.</summary>
        public string DmarcRecord { get; private set; } = string.Empty;
        /// <summary>Gets or sets the dmarc record exists value.</summary>
        public bool DmarcRecordExists { get; private set; } // should be true
        /// <summary>Gets or sets the multiple records value.</summary>
        public bool MultipleRecords { get; private set; }
        /// <summary>Domain at which the applied DMARC policy was discovered.</summary>
        public string? PolicyDomain { get; private set; }
        /// <summary>Gets or sets the starts correctly value.</summary>
        public bool StartsCorrectly { get; private set; } // should be true
        /// <summary>Gets or sets the exceeds character limit value.</summary>
        public bool ExceedsCharacterLimit { get; private set; } // should be false
        /// <summary>Gets or sets the has mandatory tags value.</summary>
        public bool HasMandatoryTags { get; private set; }
        /// <summary>Gets or sets the is policy valid value.</summary>
        public bool IsPolicyValid { get; private set; }

        /// <summary>Represents the policy value.</summary>
        public string Policy => TranslatePolicy(PolicyShort);
        /// <summary>Represents the sub policy value.</summary>
        public string SubPolicy => TranslateSubPolicy();
        /// <summary>Represents the reporting interval value.</summary>
        public string ReportingInterval => TranslateReportingInterval(ReportingIntervalShort);
        /// <summary>Represents the percent value.</summary>
        public string Percent => TranslatePercentage();
        /// <summary>Represents the spf alignment value.</summary>
        public string SpfAlignment => TranslateAlignment(SpfAShort);
        /// <summary>Represents the dkim alignment value.</summary>
        public string DkimAlignment => TranslateAlignment(DkimAShort);
        /// <summary>Represents the failure reporting options value.</summary>
        public string FailureReportingOptions => TranslateFailureReportingOptions(FoShort);
        /// <summary>Represents the nonexistent policy value.</summary>
        public string NonexistentPolicy => TranslatePolicy(NonexistentPolicyShort);
        /// <summary>Represents the public suffix policy value.</summary>
        public string PublicSuffixPolicy => PublicSuffixPolicyShort switch {
            "y" => "Public suffix domain",
            "n" => "Organizational domain",
            _ => "No declared organizational boundary"
        };
        /// <summary>Represents the report feedback value.</summary>
        public string ReportFeedback => RfbShort;

        /// <summary>Gets or sets the valid dkim alignment value.</summary>
        public bool ValidDkimAlignment { get; private set; }
        /// <summary>Gets or sets the valid spf alignment value.</summary>
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

        /// <summary>Gets or sets the invalid report uri value.</summary>
        public bool InvalidReportUri { get; private set; }

        /// <summary>Gets or sets the rua value.</summary>
        public string Rua { get; private set; } = string.Empty;
        /// <summary>Gets or sets the mailto rua value.</summary>
        public List<string> MailtoRua { get; private set; } = new List<string>();
        /// <summary>Gets or sets the http rua value.</summary>
        public List<string> HttpRua { get; private set; } = new List<string>();
        /// <summary>Gets or sets the ruf value.</summary>
        public string Ruf { get; private set; } = string.Empty;
        /// <summary>Gets or sets the mailto ruf value.</summary>
        public List<string> MailtoRuf { get; private set; } = new List<string>();
        /// <summary>Gets or sets the http ruf value.</summary>
        public List<string> HttpRuf { get; private set; } = new List<string>();
        /// <summary>Gets or sets the ruf size limits value.</summary>
        public List<long?> RufSizeLimits { get; private set; } = new List<long?>();
        /// <summary>Gets or sets the unknown tags value.</summary>
        public List<string> UnknownTags { get; private set; } = new List<string>();
        /// <summary>Gets or sets the deprecated tags value.</summary>
        public List<string> DeprecatedTags { get; private set; } = new List<string>();

        // short versions of the tags
        /// <summary>Gets or sets the sub policy short value.</summary>
        public string SubPolicyShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the policy short value.</summary>
        public string PolicyShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the fo short value.</summary>
        public string FoShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the dkim a short value.</summary>
        public string DkimAShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the spf a short value.</summary>
        public string SpfAShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the nonexistent policy short value.</summary>
        public string NonexistentPolicyShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the public suffix policy short value.</summary>
        public string PublicSuffixPolicyShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the rfb short value.</summary>
        public string RfbShort { get; private set; } = string.Empty;
        /// <summary>Gets or sets the pct value.</summary>
        public int? Pct { get; private set; }
        /// <summary>Gets or sets the original pct value.</summary>
        public int? OriginalPct { get; private set; }
        /// <summary>Gets or sets the is pct valid value.</summary>
        public bool IsPctValid { get; private set; }
        /// <summary>Gets or sets the reporting interval short value.</summary>
        public string ReportingIntervalShort { get; private set; } = string.Empty;

        private const int DefaultReportingInterval = 86400;

        /// <summary>Structured assessments observed during DMARC analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>Analyzes a DMARC policy with an optional synchronous organizational-domain resolver.</summary>
        public Task AnalyzeDmarcRecords(
            IEnumerable<DnsAnswer>? dnsResults,
            InternalLogger logger,
            string? domainName = null,
            Func<string, string>? getOrgDomain = null,
            string? policyDomainName = null) => AnalyzeDmarcRecords(dnsResults, logger, domainName,
                getOrgDomain, policyDomainName, null, default);

        /// <summary>Analyzes a DMARC policy using cancellable organizational-domain discovery.</summary>
        /// <param name="dnsResults">TXT answers and optional CNAME evidence for the discovered policy.</param>
        /// <param name="logger">Analysis logger.</param>
        /// <param name="domainName">Author domain being evaluated.</param>
        /// <param name="getOrgDomain">Synchronous organizational-domain resolver for legacy compatibility.</param>
        /// <param name="policyDomainName">Domain at which the governing policy was discovered.</param>
        /// <param name="getOrgDomainAsync">Asynchronous organizational-domain resolver; takes precedence when supplied.</param>
        /// <param name="cancellationToken">Cancellation for discovery and reporting authorization queries.</param>
        public async Task AnalyzeDmarcRecords(
            IEnumerable<DnsAnswer>? dnsResults,
            InternalLogger logger,
            string? domainName,
            Func<string, string>? getOrgDomain,
            string? policyDomainName,
            Func<string, CancellationToken, Task<string>>? getOrgDomainAsync,
            CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DMARC", target: domainName);
            // reset all properties so repeated calls don't accumulate data
            Assessments.Clear();
            DnsConfiguration ??= new DnsConfiguration();
            DmarcRecord = string.Empty;
            DmarcRecordExists = false;
            MultipleRecords = false;
            PolicyDomain = policyDomainName ?? domainName;
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
            DnsRecordTtl = null;
            CnameTtl = null;
            IsCnameResolved = false;
            DnsQueryFailed = false;
            DnsQueryError = null;
            OrganizationalDomain = null;
            SubjectDomainExists = null;
            EffectivePolicyShort = string.Empty;
            IsTestMode = false;
            ReportingQueryFailed = false;
            ReportingQueryError = null;
            WeakPolicy = false;
            PolicyRecommendation = string.Empty;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var dmarcRecordList = dnsResults.ToList();

            // Capture CNAME TTL before filtering
            var cnameRecords = dmarcRecordList.Where(r => r.Type == DnsRecordType.CNAME).ToList();
            if (cnameRecords.Any()) {
                IsCnameResolved = true;
                CnameTtl = cnameRecords.Min(r => r.TTL);
            }

            var allTxtRecords = dmarcRecordList.Where(r => r.Type == DnsRecordType.TXT).ToList();
            var txtRecords = allTxtRecords
                .Where(r => r.Type == DnsRecordType.TXT && IsDmarcPolicyRecord(r.TxtConcatenatedData))
                .ToList();
            DnsRecordTtl = DnsAnswerTtlHelper.MinPositiveTtl(allTxtRecords, expectedType: DnsRecordType.TXT);
            DmarcRecordExists = txtRecords.Any();
            MultipleRecords = txtRecords.Count > 1;

            DmarcRecord = txtRecords.Count > 0 ? txtRecords[0].TxtConcatenatedData : string.Empty;

            if (!DmarcRecordExists) {
                logger.WriteVerbose("No DMARC record found.");
                logger?.WriteWarningCode(DmarcCodes.MissingRecord, "No DMARC record found.");
                return;
            }

            logger.WriteVerbose($"Analyzing DMARC record {DmarcRecord}");

            // DNS character strings are limited individually; the concatenated policy has no 255-byte ceiling.

            // check the DMARC record starts correctly
            StartsCorrectly = IsDmarcPolicyRecord(DmarcRecord);
            if (!StartsCorrectly) {
                logger?.WriteWarningCode(DmarcCodes.StartsInvalid, "DMARC record does not start with v=DMARC1.");
            }

            if (MultipleRecords) {
                logger?.WriteWarningCode(DmarcCodes.MultipleRecords, "Multiple DMARC records published.");
                UpdateAdvisory();
                return;
            }
            if (!DmarcPolicyTags.TryRead(DmarcRecord, out var parsedTags)) {
                logger?.WriteWarningCode("DMARC.Record.SyntaxInvalid", "DMARC tag syntax is invalid or a tag is duplicated.");
                UpdateAdvisory();
                return;
            }

            // loop through the tags of the DMARC record
            var tags = DmarcRecord.Split(';');
            var policyTagFound = false;
            foreach (var tag in tags) {
                var keyValue = tag.Split(new[] { '=' }, 2);
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
                                logger?.WriteWarningCode(DmarcCodes.TagDeprecated, "Tag {0} is obsolete in RFC 9989.", key);
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
                        case TagTestMode:
                            IsTestMode = value == "y";
                            break;
                        case TagReportFeedback:
                            RfbShort = value;
                            break;
                        case TagReportFormat:
                            var rfPair = $"{key}={value}";
                            if (!DeprecatedTags.Contains(rfPair)) {
                                DeprecatedTags.Add(rfPair);
                                logger?.WriteWarningCode(DmarcCodes.TagDeprecated, "Tag {0} is obsolete in RFC 9989.", key);
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

            // verify mandatory tags
            HasMandatoryTags = StartsCorrectly && policyTagFound;
            IsPolicyValid &= DmarcPolicyTags.HasValidPolicy(parsedTags);
            EffectivePolicyShort = IsPolicyValid ? PolicyShort : DmarcPolicyTags.HasReportingFallback(parsedTags) ? "none" : string.Empty;
            // set the default value for the pct tag if it is not present
            Pct ??= 100;
            EvaluatePolicyStrength(domainName != null && !string.Equals(domainName, PolicyDomain, StringComparison.OrdinalIgnoreCase));
            await CheckReportingAuthorizationAsync(domainName, getOrgDomain, getOrgDomainAsync, logger, cancellationToken).ConfigureAwait(false);
            // Info-level positives (posture signals)
            if (DmarcRecordExists)
                logger?.WriteInformationCode(DmarcCodes.Present, "DMARC record present");
            if (StartsCorrectly)
                logger?.WriteInformationCode(DmarcCodes.StartsV1, "DMARC starts with v=DMARC1");
            var ruaCount = (MailtoRua?.Count ?? 0) + (HttpRua?.Count ?? 0);
            if (ruaCount > 0)
                logger?.WriteInformationCode(DmarcCodes.RuaPresent, $"Aggregate reporting (rua) configured: {ruaCount} address(es)");
            var rufCount = (MailtoRuf?.Count ?? 0) + (HttpRuf?.Count ?? 0);
            if (rufCount > 0)
                logger?.WriteInformationCode(DmarcCodes.RufPresent, $"Forensic reporting (ruf) configured: {rufCount} address(es)");
            if (string.Equals(DkimAShort, "s", StringComparison.OrdinalIgnoreCase))
                logger?.WriteInformationCode(DmarcCodes.AlignmentStrictDkim, "DKIM alignment strict (adkim=s)");
            if (string.Equals(SpfAShort, "s", StringComparison.OrdinalIgnoreCase))
                logger?.WriteInformationCode(DmarcCodes.AlignmentStrictSpf, "SPF alignment strict (aspf=s)");
            if (parsedTags.ContainsKey(TagPercent) && Pct.HasValue && Pct.Value >= 100)
                logger?.WriteInformationCode(DmarcCodes.Percent100, "Legacy percentage tag pct=100 published");
        }

        internal static bool IsDmarcPolicyRecord(string? value) {
            if (string.IsNullOrWhiteSpace(value)) return false;
            var separator = value!.IndexOf(';');
            if (separator < 0) return false;
            var versionTag = value.Substring(0, separator).Split(new[] { '=' }, 2);
            return versionTag.Length == 2 &&
                   versionTag[0].Trim().Equals("v", StringComparison.OrdinalIgnoreCase) &&
                   versionTag[1].Trim().Equals("DMARC1", StringComparison.Ordinal);
        }

        private static bool IsDmarcReportAuthorizationRecord(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            var candidate = value!.Trim();
            var separator = candidate.IndexOf(';');
            var firstTag = separator >= 0 ? candidate.Substring(0, separator) : candidate;
            var versionTag = firstTag.Split(new[] { '=' }, 2);
            return versionTag.Length == 2 &&
                   versionTag[0].Trim().Equals("v", StringComparison.OrdinalIgnoreCase) &&
                   versionTag[1].Trim().Equals("DMARC1", StringComparison.Ordinal);
        }

        private void AddUriToList(string uri, List<string> mailtoList, List<string> httpList, InternalLogger? logger = null, bool isRuf = false) {
            var uris = uri.Split(',');
            foreach (var raw in uris) {
                var u = raw.Trim();
                long? sizeLimit = null;
                var exIdx = u.LastIndexOf('!');
                if (exIdx > -1 && exIdx < u.Length - 1) {
                    var sizePart = u.Substring(exIdx + 1);
                    var parsedSize = DmarcReportUri.ParseSize(sizePart);
                    if (parsedSize.HasValue) {
                        sizeLimit = parsedSize.Value;
                        u = u.Substring(0, exIdx);
                    }
                }
                if (u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                    var addressPart = u.Substring(7);
                    if (DmarcReportUri.TryReadMailbox(addressPart, out var decoded)) {
                        mailtoList.Add(decoded);
                    } else {
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

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }
            return await DnsConfiguration.QueryPolicyDNS(name, type, includeAliasesInFilter: true,
                cancellationToken: cancellationToken).ConfigureAwait(false);
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

        /// <summary>
        /// Flags DMARC policies set to <c>none</c> and suggests a stronger policy.
        /// </summary>
        /// <param name="checkSubdomainPolicy">Evaluates the <c>sp</c> tag when true.</param>
        public void EvaluatePolicyStrength(bool checkSubdomainPolicy = false) {
            if (DnsQueryFailed) {
                EffectivePolicyShort = string.Empty;
            } else if (IsPolicyValid) {
                string governing = checkSubdomainPolicy && SubjectDomainExists == false && !string.IsNullOrWhiteSpace(NonexistentPolicyShort)
                    ? NonexistentPolicyShort : checkSubdomainPolicy && !string.IsNullOrWhiteSpace(SubPolicyShort) ? SubPolicyShort : PolicyShort;
                EffectivePolicyShort = PolicyWithTestMode(governing);
            } else if (!string.IsNullOrEmpty(EffectivePolicyShort)) {
                EffectivePolicyShort = "none"; // Valid reporting fallback cannot gain enforcement from sp or test mode.
            }
            WeakPolicy = string.Equals(EffectivePolicyShort, "none", StringComparison.OrdinalIgnoreCase);
            PolicyRecommendation = WeakPolicy ? "Consider quarantine or reject." : string.Empty;
            Assessments.RemoveAll(assessment => assessment.Code == DmarcCodes.PolicyReject || assessment.Code == DmarcCodes.PolicyQuarantine
                || assessment.Code == "DMARC.Policy.Recommendation");
            string? code = EffectivePolicyShort == "reject" ? DmarcCodes.PolicyReject
                : EffectivePolicyShort == "quarantine" ? DmarcCodes.PolicyQuarantine : null;
            if (code != null && !MultipleRecords) Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info, Category = "DMARC", Target = Subject, Code = code,
                Message = $"DMARC policy {EffectivePolicyShort} in effect"
            });
            if (WeakPolicy) Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info, Category = "DMARC", Target = Subject,
                Code = "DMARC.Policy.Recommendation", Message = PolicyRecommendation
            });
            UpdateAdvisory();
        }

        private void UpdateAdvisory() {
            if (DnsQueryFailed) {
                Advisory = "Applicable DMARC policy could not be determined; policy absence was not established.";
            } else if (!DmarcRecordExists) {
                Advisory = "No DMARC record found.";
            } else if (MultipleRecords) {
                Advisory = "Multiple DMARC records found; no policy can be applied.";
            } else if (!StartsCorrectly || string.IsNullOrEmpty(EffectivePolicyShort)) {
                Advisory = "DMARC record misconfigured.";
            } else if (WeakPolicy) {
                Advisory = "DMARC policy is weak.";
            } else {
                Advisory = $"DMARC policy {EffectivePolicyShort} in effect.";
            }
        }



    }
}
