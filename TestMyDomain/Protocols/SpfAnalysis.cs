using System.Collections.Generic;
using System.Linq;

namespace TestMyDomain.Protocols {
    /// <summary>
    ///
    /// To validate an SPF record according to the RFC 7208 standard, you would need to check for several things.Here are some of the key points:
    /// 1.	The SPF record must start with "v=spf1".
    /// 2.	The SPF record should not exceed 10 DNS lookups - SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check, including any lookups caused by the use of the "include" mechanism or the "redirect" modifier.  If this number is exceeded during a check, a PermError MUST be returned.  The "include", "a", "mx", "ptr", and "exists" mechanisms as well as the "redirect" modifier do count against this limit.  The "all", "ip4", and "ip6" mechanisms do not require DNS lookups and therefore do not count against this limit. The "exp" modifier does not count against this limit because the DNS lookup to fetch the explanation string occurs after the SPF record has been evaluated.
    /// 3.	The SPF record should not have more than one "all" mechanism.
    /// 4.	The SPF record should not have more than 450 characters.
    /// 5.  The SPF record should not have more than 255 characters in a single string.
    /// </summary>
    public class SpfAnalysis {
        public string SpfRecord { get; private set; }
        public List<string> SpfRecords { get; private set; } = new List<string>();
        public bool SpfRecordExists { get; private set; } // should be true
        public bool MultipleSpfRecords { get; private set; } // should be false
        public bool StartsCorrectly { get; private set; } // should be true
        public bool ExceedsTotalCharacterLimit { get; private set; } // should be false
        public bool ExceedsCharacterLimit { get; private set; } // should be false
        public bool ExceedsDnsLookups { get; private set; } // should be false
        public bool MultipleAllMechanisms { get; private set; } // should be false
        public bool ContainsCharactersAfterAll { get; private set; }
        public bool HasPtrType { get; private set; }
        public bool HasNullDnsLookups { get; private set; }
        public bool HasRedirect { get; private set; }
        public bool HasExp { get; private set; }
        public List<string> ARecords { get; private set; } = new List<string>();
        public List<string> Ipv4Records { get; private set; } = new List<string>();
        public List<string> Ipv6Records { get; private set; } = new List<string>();
        public List<string> MxRecords { get; private set; } = new List<string>();
        public List<string> PtrRecords { get; private set; } = new List<string>();
        public List<string> IncludeRecords { get; private set; } = new List<string>();
        public List<string> ExistsRecords { get; private set; } = new List<string>();
        public string ExpValue { get; private set; }
        public string RedirectValue { get; private set; }
        public string AllMechanism { get; private set; }


        public List<SpfPartAnalysis> SpfPartAnalyses { get; private set; } = new List<SpfPartAnalysis>();
        public List<SpfTestResult> SpfTestResults { get; private set; } = new List<SpfTestResult>();

        public void AnalyzeSpfRecords(IEnumerable<DnsResult> dnsResults) {
            var spfRecordList = dnsResults.ToList();
            SpfRecordExists = spfRecordList.Any();
            MultipleSpfRecords = spfRecordList.Count > 1;

            // create a list of strings from the list of DnsResult objects
            foreach (var record in spfRecordList) {
                foreach (var data in record.Data) {
                    SpfRecords.Add(data);
                }
            }
            // create a single string from the list of strings so that we give user a single string to work with
            SpfRecord = string.Join("", SpfRecords);

            // check the character limits
            CheckCharacterLimits(spfRecordList);

            // check the SPF record starts correctly
            StartsCorrectly = StartsCorrectly || SpfRecord.StartsWith("v=spf1");

            var parts = SpfRecord.Split(' ');

            // check that the SPF record does not exceed 10 DNS lookups
            ExceedsDnsLookups = ExceedsDnsLookups || CountDnsLookups(parts) > 10;

            // check that the SPF record does not have more than one "all" mechanism
            MultipleAllMechanisms = MultipleAllMechanisms || CountAllMechanisms(parts) > 1;

            // add the parts to the appropriate lists
            foreach (var part in parts) {
                AddPartToList(part);
            }

            // check if the SPF record contains characters after "all"
            ContainsCharactersAfterAll = parts.Any(part => part.EndsWith("all") && !part.Equals(parts.Last()) && !part.StartsWith("+all") && !part.StartsWith("-all") && !part.StartsWith("~all") && !part.StartsWith("?all"));

            // check if the SPF record contains a PTR type
            HasPtrType = PtrRecords.Any();

            // check if the SPF record contains exists: with no domain
            HasNullDnsLookups = parts.Any(part => part.StartsWith("exists:") && part.Length == 7);
        }


        private int CountDnsLookups(string[] parts) {
            return parts.Count(part => part.StartsWith("a") || part.StartsWith("mx") || part.StartsWith("ptr") || part.StartsWith("include") || part.StartsWith("exists"));
        }

        private int CountAllMechanisms(string[] parts) {
            return parts.Count(part => part.EndsWith("all"));
        }

        private void CheckCharacterLimits(IEnumerable<DnsResult> spfRecords) {
            int totalLength = 0;
            foreach (var record in spfRecords) {
                foreach (var data in record.Data) {
                    totalLength += data.Length;
                    ExceedsCharacterLimit = ExceedsCharacterLimit || data.Length > 255;
                }
            }
            ExceedsTotalCharacterLimit = totalLength > 2048;
        }

        private void AddPartToList(string part) {
            if (part.StartsWith("a")) {
                ARecords.Add(part);
            } else if (part.StartsWith("mx")) {
                MxRecords.Add(part);
            } else if (part.StartsWith("ptr")) {
                PtrRecords.Add(part);
            } else if (part.StartsWith("exists")) {
                ExistsRecords.Add(part);
            } else if (part.StartsWith("ip4:")) {
                Ipv4Records.Add(part.Substring(4));
            } else if (part.StartsWith("ip6:")) {
                Ipv6Records.Add(part.Substring(4));
            } else if (part.StartsWith("include:")) {
                IncludeRecords.Add(part.Substring(8));
            } else if (part.StartsWith("redirect=")) {
                RedirectValue = part.Substring(9);
            } else if (part.StartsWith("exp=")) {
                ExpValue = part.Substring(4);
            } else if (part.EndsWith("all")) {
                AllMechanism = part;
            }
        }
    }

    public class SpfPartAnalysis {
        public string Prefix { get; set; }
        public string Type { get; set; }
        public string Value { get; set; }
        public string PrefixDesc { get; set; }
        public string Description { get; set; }
    }

    public class SpfTestResult {
        public string Test { get; set; }
        public string Result { get; set; }
        public string Assessment { get; set; }
    }
}
