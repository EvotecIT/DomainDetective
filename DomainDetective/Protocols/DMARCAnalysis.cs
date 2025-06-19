using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClientX;

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
        public string DmarcRecord { get; private set; }
        public bool DmarcRecordExists { get; private set; } // should be true
        public bool StartsCorrectly { get; private set; } // should be true
        public bool ExceedsCharacterLimit { get; private set; } // should be false

        public string Policy => TranslatePolicy(PolicyShort);
        public string SubPolicy => TranslatePolicy(SubPolicyShort);
        public string ReportingInterval => TranslateReportingInterval(ReportingIntervalShort);
        public string Percent => TranslatePercentage(Pct.ToString());
        public string SpfAlignment => TranslateAlignment(SpfAShort);
        public string DkimAlignment => TranslateAlignment(DkimAShort);
        public string FailureReportingOptions => TranslateFailureReportingOptions(FoShort);

        public string Rua { get; private set; }
        public List<string> MailtoRua { get; private set; } = new List<string>();
        public List<string> HttpRua { get; private set; } = new List<string>();
        public string Ruf { get; private set; }
        public List<string> MailtoRuf { get; private set; } = new List<string>();
        public List<string> HttpRuf { get; private set; } = new List<string>();

        // short versions of the tags
        public string SubPolicyShort { get; private set; }
        public string PolicyShort { get; private set; }
        public string FoShort { get; private set; }
        public string DkimAShort { get; private set; }
        public string SpfAShort { get; private set; }
        public int? Pct { get; private set; }
        public int ReportingIntervalShort { get; private set; }

        public async Task AnalyzeDmarcRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            var dmarcRecordList = dnsResults.ToList();
            DmarcRecordExists = dmarcRecordList.Any();

            // create a single string from the list of DnsResult objects
            // TODO: check this logic for creating a single string from the list of DnsResult objects
            foreach (var record in dmarcRecordList) {
                DmarcRecord = record.Data;
            }

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
            foreach (var tag in tags) {
                var keyValue = tag.Split('=');
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "p":
                            PolicyShort = value;
                            break;
                        case "sp":
                            SubPolicyShort = value;
                            break;
                        case "ri":
                            ReportingIntervalShort = int.Parse(value);
                            break;
                        case "fo":
                            FoShort = value;
                            break;
                        case "pct":
                            Pct = int.Parse(value);
                            break;
                        case "adkim":
                            DkimAShort = value;
                            break;
                        case "aspf":
                            SpfAShort = value;
                            break;
                        case "rua":
                            Rua = value;
                            AddUriToList(value, MailtoRua, HttpRua);
                            break;
                        case "ruf":
                            Ruf = value;
                            AddUriToList(value, MailtoRuf, HttpRuf);
                            break;
                    }
                }
            }
            // set the default value for the pct tag if it is not present
            Pct ??= 100;
        }

        private void AddUriToList(string uri, List<string> mailtoList, List<string> httpList) {
            var uris = uri.Split(',');
            foreach (var u in uris) {
                if (u.StartsWith("mailto:")) {
                    mailtoList.Add(u.Substring(7));
                } else if (u.StartsWith("http:")) {
                    httpList.Add(u);
                }
            }
        }
        private string TranslateAlignment(string alignment) {
            switch (alignment) {
                case "s":
                    return "Strict";
                case "r":
                    return "Relaxed";
                case null:
                case "":
                    return "Relaxed (default)"; // default to relaxed if no value is provided
                default:
                    return "Unknown";
            }
        }

        private string TranslatePolicy(string policy) {
            switch (policy) {
                case "none":
                    return "No policy";
                case "quarantine":
                    return "Quarantine";
                case "reject":
                    return "Reject";
                default:
                    return "Unknown policy";
            }
        }

        private string TranslateFailureReportingOptions(string option) {
            switch (option) {
                case "0":
                    return "Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned 'pass' result.";
                case "1":
                    return "Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned 'pass' result.";
                case "d":
                    return "Generate a DKIM failure report if the message had a signature that failed evaluation.";
                case "s":
                    return "Generate an SPF failure report if the message failed SPF evaluation.";
                default:
                    return "Unknown option";
            }
        }

        private string TranslatePercentage(string pct) {
            int pctValue;
            if (int.TryParse(pct, out pctValue)) {
                if (pctValue < 0 || pctValue > 100) {
                    return "Percentage value must be between 0 and 100.";
                }

                return $"{pctValue}% of messages are subjected to filtering.";
            }

            return "Invalid percentage value.";
        }

        private string TranslateReportingInterval(int interval) {
            return $"{interval / 86400} days";
        }

    }
}
