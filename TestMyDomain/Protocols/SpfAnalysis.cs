using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestMyDomain.Protocols {
    /// <summary>
    ///
    /// To validate an SPF record according to the RFC 7208 standard, you would need to check for several things.Here are some of the key points:
    /// 1.	The SPF record must start with "v=spf1".
    /// 2.	The SPF record should not exceed 10 DNS lookups.
    /// 3.	The SPF record should not have more than one "all" mechanism.
    /// 4.	The SPF record should not have more than 450 characters.
    /// 5.  The SPF record should not have more than 255 characters in a single string.
    /// </summary>
    public class SpfAnalysis {
        public string SpfRecord { get; private set; }
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
        public List<string> SpfRecords { get; private set; } = new List<string>();
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

        public void AnalyzeSpfRecords(IEnumerable<DnsResult> spfRecords) {
            var spfRecordList = spfRecords.ToList();
            SpfRecordExists = spfRecordList.Any();
            MultipleSpfRecords = spfRecordList.Count > 1;

            SpfRecord = string.Join(" ", spfRecordList.Select(record => record.DataJoined));

            int totalLength = 0;
            foreach (var record in spfRecordList) {
                foreach (var data in record.Data) {
                    totalLength += data.Length;
                }
            }

            AnalyzeSpfRecord(SpfRecord);
            ExceedsTotalCharacterLimit = totalLength > 2048;
        }
        private void AnalyzeSpfRecord(string data) {
            SpfRecords.Add(data);
            StartsCorrectly = StartsCorrectly || data.StartsWith("v=spf1");
            ExceedsCharacterLimit = ExceedsCharacterLimit || data.Length > 255;

            var parts = data.Split(' ');
            ExceedsDnsLookups = ExceedsDnsLookups || CountDnsLookups(parts) > 10;
            MultipleAllMechanisms = MultipleAllMechanisms || CountAllMechanisms(parts) > 1;

            foreach (var part in parts) {
                AddPartToList(part);
            }

            ContainsCharactersAfterAll = parts.Any(part => part.EndsWith("all") && part.Length > 3 && !part.Equals(parts.Last()));
            HasPtrType = PtrRecords.Any();
            HasNullDnsLookups = parts.Any(part => part.StartsWith("exists:") && part.Length == 7);
        }



        private int CountDnsLookups(string[] parts) {
            return parts.Count(part => part.StartsWith("a") || part.StartsWith("mx") || part.StartsWith("ptr") || part.StartsWith("include") || part.StartsWith("exists"));
        }

        private int CountAllMechanisms(string[] parts) {
            return parts.Count(part => part.EndsWith("all"));
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
}
