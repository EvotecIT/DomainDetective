using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
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
        public string SubPolicy => TranslatePolicy(SubPolicyShort);
        public string ReportingInterval => TranslateReportingInterval(ReportingIntervalShort);
        public string Percent => TranslatePercentage();
        public string SpfAlignment => TranslateAlignment(SpfAShort);
        public string DkimAlignment => TranslateAlignment(DkimAShort);
        public string FailureReportingOptions => TranslateFailureReportingOptions(FoShort);

        public bool ValidDkimAlignment { get; private set; }
        public bool ValidSpfAlignment { get; private set; }

        public bool InvalidReportUri { get; private set; }

        public string Rua { get; private set; }
        public List<string> MailtoRua { get; private set; } = new List<string>();
        public List<string> HttpRua { get; private set; } = new List<string>();
        public string Ruf { get; private set; }
        public List<string> MailtoRuf { get; private set; } = new List<string>();
        public List<string> HttpRuf { get; private set; } = new List<string>();
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

        public async Task AnalyzeDmarcRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, string? domainName = null) {
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
            ExceedsCharacterLimit = DmarcRecord.Length > 255;

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
                            AddUriToList(value, MailtoRua, HttpRua);
                            break;
                        case "ruf":
                            Ruf = value;
                            AddUriToList(value, MailtoRuf, HttpRuf);
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
            foreach (var mail in MailtoRua.Concat(MailtoRuf)) {
                var at = mail.IndexOf('@');
                if (at > -1 && at < mail.Length - 1) {
                    reportDomains.Add(mail.Substring(at + 1));
                }
            }
            foreach (var http in HttpRua.Concat(HttpRuf)) {
                if (Uri.TryCreate(http, UriKind.Absolute, out var uri)) {
                    reportDomains.Add(uri.Host);
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

        private void AddUriToList(string uri, List<string> mailtoList, List<string> httpList) {
            var uris = uri.Split(',');
            foreach (var raw in uris) {
                var u = raw.Trim();
                if (u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                    var address = u.Substring(7);
                    try {
                        _ = new System.Net.Mail.MailAddress(address);
                        mailtoList.Add(address);
                    } catch {
                        InvalidReportUri = true;
                    }
                } else if (u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                    if (Uri.TryCreate(u, UriKind.Absolute, out var parsed) && parsed.Scheme == Uri.UriSchemeHttps) {
                        httpList.Add(u);
                    } else {
                        InvalidReportUri = true;
                    }
                } else {
                    InvalidReportUri = true;
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
                null or "" => "Relaxed (default)", // default to relaxed if no value is provided
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

    }
}