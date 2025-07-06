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
    public class DmarcAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        public Dictionary<string, bool> ExternalReportAuthorization { get; private set; } = new();
        public string DmarcRecord { get; private set; }
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

        public bool ValidDkimAlignment { get; private set; }
        public bool ValidSpfAlignment { get; private set; }

        /// <summary>True when <c>p=none</c> or <c>sp=none</c> is detected.</summary>
        public bool WeakPolicy { get; private set; }

        /// <summary>Recommendation message when a weak policy is found.</summary>
        public string? PolicyRecommendation { get; private set; }

        /// <summary>Indicates whether the SPF domain aligns with the policy.</summary>
        public bool SpfAligned { get; private set; }
        /// <summary>Indicates whether the DKIM domain aligns with the policy.</summary>
        public bool DkimAligned { get; private set; }

        public bool InvalidReportUri { get; private set; }

        public string Rua { get; private set; }
        public List<string> MailtoRua { get; private set; } = new List<string>();
        public List<string> HttpRua { get; private set; } = new List<string>();
        public string Ruf { get; private set; }
        public List<string> MailtoRuf { get; private set; } = new List<string>();
        public List<string> HttpRuf { get; private set; } = new List<string>();
        public List<long?> RufSizeLimits { get; private set; } = new List<long?>();
        public List<string> UnknownTags { get; private set; } = new List<string>();

        // short versions of the tags
        public string SubPolicyShort { get; private set; }
        public string PolicyShort { get; private set; }
        public string FoShort { get; private set; }
        public string DkimAShort { get; private set; }
        public string SpfAShort { get; private set; }
        public int? Pct { get; private set; }
        public int? OriginalPct { get; private set; }
        public bool IsPctValid { get; private set; }
        public int ReportingIntervalShort { get; private set; }

        public async Task AnalyzeDmarcRecords(
            IEnumerable<DnsAnswer> dnsResults,
            InternalLogger logger,
            string? domainName = null,
            Func<string, string>? getOrgDomain = null) {
            // reset all properties so repeated calls don't accumulate data
            DnsConfiguration ??= new DnsConfiguration();
            DmarcRecord = null;
            DmarcRecordExists = false;
            MultipleRecords = false;
            StartsCorrectly = false;
            ExceedsCharacterLimit = false;
            HasMandatoryTags = false;
            IsPolicyValid = false;
            IsPctValid = true;
            Rua = null;
            MailtoRua = new List<string>();
            HttpRua = new List<string>();
            Ruf = null;
            MailtoRuf = new List<string>();
            HttpRuf = new List<string>();
            RufSizeLimits = new List<long?>();
            UnknownTags = new List<string>();
            SubPolicyShort = null;
            PolicyShort = null;
            FoShort = null;
            DkimAShort = null;
            SpfAShort = null;
            ValidDkimAlignment = true;
            ValidSpfAlignment = true;
            InvalidReportUri = false;
            Pct = null;
            OriginalPct = null;
            ReportingIntervalShort = 0;
            ExternalReportAuthorization = new Dictionary<string, bool>();

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var dmarcRecordList = dnsResults.ToList();
            DmarcRecordExists = dmarcRecordList.Any();
            MultipleRecords = dmarcRecordList.Count > 1;

            // concatenate all TXT chunks into a single string separated by spaces
            DmarcRecord = string.Join(" ", dmarcRecordList.Select(record => record.Data));

            if (DmarcRecord == null) {
                logger.WriteVerbose("No DMARC record found.");
                return;
            }

            logger.WriteVerbose($"Analyzing DMARC record {DmarcRecord}");

            // check the character limit
            ExceedsCharacterLimit = DmarcRecord.Trim().Length > 255;

            // check the DMARC record starts correctly
            StartsCorrectly = DmarcRecord.StartsWith("v=DMARC1");

            // loop through the tags of the DMARC record
            var tags = DmarcRecord.Split(';');
            var policyTagFound = false;
            foreach (var tag in tags) {
                var keyValue = tag.Split('=');
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "v":
                            break;
                        case "p":
                            PolicyShort = value;
                            policyTagFound = true;
                            IsPolicyValid = value == "none" || value == "quarantine" || value == "reject";
                            break;
                        case "sp":
                            SubPolicyShort = value;
                            break;
                        case "ri":
                            // RFC 7489 section 6.3 defines 'ri' as the reporting
                            // interval in seconds.  It must be a numeric value.
                            if (int.TryParse(value, out var ri)) {
                                ReportingIntervalShort = ri;
                            }
                            break;
                        case "fo":
                            FoShort = value;
                            break;
                        case "pct":
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
                            break;
                        case "adkim":
                            DkimAShort = value;
                            ValidDkimAlignment = value == "s" || value == "r";
                            if (!ValidDkimAlignment) {
                                logger?.WriteWarning($"Invalid adkim value '{value}', expected 's' or 'r'");
                            }
                            break;
                        case "aspf":
                            SpfAShort = value;
                            ValidSpfAlignment = value == "s" || value == "r";
                            if (!ValidSpfAlignment) {
                                logger?.WriteWarning($"Invalid aspf value '{value}', expected 's' or 'r'");
                            }
                            break;
                        case "rua":
                            Rua = value;
                            AddUriToList(value, MailtoRua, HttpRua, logger);
                            break;
                        case "ruf":
                            Ruf = value;
                            AddUriToList(value, MailtoRuf, HttpRuf, logger, true);
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
                        logger?.WriteWarning("Report address {0} is not aligned with {1}.", mail, domainName);
                    }
                }
            }
            foreach (var http in HttpRua.Concat(HttpRuf)) {
                if (Uri.TryCreate(http, UriKind.Absolute, out var uri)) {
                    reportDomains.Add(uri.Host);
                    if (orgDomain != null && getOrgDomain != null &&
                        !string.Equals(getOrgDomain(uri.Host), orgDomain, StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteWarning("Report address {0} is not aligned with {1}.", http, domainName);
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
                        logger?.WriteWarning("Report URI {0} is not a valid email address.", u);
                    }
                    if (isRuf) {
                        RufSizeLimits.Add(sizeLimit);
                        if (sizeLimit.HasValue && sizeLimit.Value > 10 * 1024 * 1024) {
                            logger?.WriteWarning("Forensic report size {0} exceeds 10MB.", sizeLimit.Value);
                        }
                    }
                    continue;
                }

                if (!Uri.TryCreate(u, UriKind.Absolute, out var parsed)) {
                    logger?.WriteWarning("Report URI {0} is missing a scheme.", u);
                    InvalidReportUri = true;
                    continue;
                }

                if (parsed.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) {
                    httpList.Add(u);
                } else if (parsed.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    logger?.WriteWarning("Report URI {0} uses HTTP instead of HTTPS.", u);
                    httpList.Add(u);
                } else {
                    logger?.WriteWarning("Report URI {0} is missing a scheme.", u);
                    InvalidReportUri = true;
                }
                if (isRuf) {
                    RufSizeLimits.Add(sizeLimit);
                    if (sizeLimit.HasValue && sizeLimit.Value > 10 * 1024 * 1024) {
                        logger?.WriteWarning("Forensic report size {0} exceeds 10MB.", sizeLimit.Value);
                    }
                }
            }
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
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

        private string TranslateReportingInterval(int interval) {
            return $"{interval / 86400} days";
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
        }



    }
}