using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    ///
    /// To validate an SPF record according to the RFC 7208 standard, you would need to check for several things.Here are some of the key points:
    /// 1.	The SPF record must start with "v=spf1".
    /// 2.	The SPF record should not exceed 10 DNS lookups - SPF implementations MUST limit the number of mechanisms and modifiers that do DNS lookups to at most 10 per SPF check, including any lookups caused by the use of the "include" mechanism or the "redirect" modifier.  If this number is exceeded during a check, a PermError MUST be returned.  The "include", "a", "mx", "ptr", and "exists" mechanisms as well as the "redirect" modifier do count against this limit.  The "all", "ip4", and "ip6" mechanisms do not require DNS lookups and therefore do not count against this limit. The "exp" modifier does not count against this limit because the DNS lookup to fetch the explanation string occurs after the SPF record has been evaluated.
    /// 3.	The SPF record should not have more than one "all" mechanism.
    /// 4.	The total length of the SPF record should stay below 512 bytes when possible.
    /// 5.	Each TXT chunk of the SPF record must be 255 bytes or less.
    /// </summary>
    public class SpfAnalysis {
        internal DnsConfiguration DnsConfiguration { get; set; }
        public string SpfRecord { get; private set; }
        public List<string> SpfRecords { get; private set; } = new List<string>();
        public bool SpfRecordExists { get; private set; } // should be true
        public bool MultipleSpfRecords { get; private set; } // should be false
        public bool StartsCorrectly { get; private set; } // should be true
        public bool ExceedsTotalCharacterLimit { get; private set; } // should be false
        public bool ExceedsCharacterLimit { get; private set; } // should be false
        public List<string> DnsLookups { get; private set; } = new List<string>();
        public int DnsLookupsCount { get; private set; }
        public bool ExceedsDnsLookups { get; private set; } // should be false
        public bool MultipleAllMechanisms { get; private set; } // should be false
        public bool ContainsCharactersAfterAll { get; private set; }
        public bool HasPtrType { get; private set; }
        public bool HasNullLookups { get; private set; }
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

        public List<string> ResolvedARecords { get; private set; } = new List<string>();
        public List<string> ResolvedIpv4Records { get; private set; } = new List<string>();
        public List<string> ResolvedIpv6Records { get; private set; } = new List<string>();
        public List<string> ResolvedMxRecords { get; private set; } = new List<string>();
        public List<string> ResolvedPtrRecords { get; private set; } = new List<string>();
        public List<string> ResolvedIncludeRecords { get; private set; } = new List<string>();
        public List<string> ResolvedExistsRecords { get; private set; } = new List<string>();

        public Dictionary<string, string> TestSpfRecords { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public bool CycleDetected { get; private set; }
        private HashSet<string> _visitedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);


        public List<SpfPartAnalysis> SpfPartAnalyses { get; private set; } = new List<SpfPartAnalysis>();
        public List<SpfTestResult> SpfTestResults { get; private set; } = new List<SpfTestResult>();

        public void Reset() {
            SpfRecord = null;
            SpfRecords = new List<string>();
            SpfRecordExists = false;
            MultipleSpfRecords = false;
            StartsCorrectly = false;
            ExceedsTotalCharacterLimit = false;
            ExceedsCharacterLimit = false;
            DnsLookups = new List<string>();
            DnsLookupsCount = 0;
            ExceedsDnsLookups = false;
            MultipleAllMechanisms = false;
            ContainsCharactersAfterAll = false;
            HasPtrType = false;
            HasNullLookups = false;
            HasRedirect = false;
            HasExp = false;
            CycleDetected = false;
            _visitedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ARecords = new List<string>();
            Ipv4Records = new List<string>();
            Ipv6Records = new List<string>();
            MxRecords = new List<string>();
            PtrRecords = new List<string>();
            IncludeRecords = new List<string>();
            ExistsRecords = new List<string>();
            ResolvedARecords = new List<string>();
            ResolvedIpv4Records = new List<string>();
            ResolvedIpv6Records = new List<string>();
            ResolvedMxRecords = new List<string>();
            ResolvedPtrRecords = new List<string>();
            ResolvedIncludeRecords = new List<string>();
            ResolvedExistsRecords = new List<string>();
            ExpValue = null;
            RedirectValue = null;
            AllMechanism = null;
            SpfPartAnalyses = new List<SpfPartAnalysis>();
            SpfTestResults = new List<SpfTestResult>();
        }

        public async Task AnalyzeSpfRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            TestSpfRecords.Clear();
            Reset();
            var spfRecordList = dnsResults.ToList();
            SpfRecordExists = spfRecordList.Any();
            MultipleSpfRecords = spfRecordList.Count > 1;

            // create a list of strings from the list of DnsResult objects
            // we use DataStringsEscaped to get the escaped strings, as provided by DnsClientX
            // this will allow us to test if the record length exceeds 255 characters
            foreach (var record in spfRecordList) {
                SpfRecords.AddRange(record.DataStringsEscaped);
            }
            // However for analysis we only need the Data, as provided by DnsClientX
            if (dnsResults.Count() == 1) {
                SpfRecord = dnsResults.First().Data;
            } else {
                // if there are multiple records, we need to join them together to analyze them
                SpfRecord = string.Join(" ", SpfRecords);
            }

            logger.WriteVerbose($"Analyzing SPF record {SpfRecord}");

            // check the character limits
            CheckCharacterLimits(spfRecordList);

            // check the SPF record starts correctly
            StartsCorrectly = StartsCorrectly || SpfRecord.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase);

            // loop through the parts of the SPF record for remaining checks
            var parts = TokenizeSpfRecord(SpfRecord).ToArray();

            // check that the SPF record does not exceed 10 DNS lookups
            int dnsLookups = await CountDnsLookups(parts, _visitedDomains);
            DnsLookupsCount = dnsLookups;
            ExceedsDnsLookups = ExceedsDnsLookups || DnsLookupsCount > 10;

            // check that the SPF record does not have more than one "all" mechanism
            MultipleAllMechanisms = MultipleAllMechanisms || CountAllMechanisms(parts) > 1;

            // add the parts to the appropriate lists
            foreach (var part in parts) {
                AddPartToList(part);
            }

            // check if the SPF record contains characters after "all"
            ContainsCharactersAfterAll = parts
                .Where(part => IsAllMechanism(part))
                .Any(part => !part.Equals(parts.Last(), StringComparison.OrdinalIgnoreCase));

            // check if the SPF record contains a PTR type
            HasPtrType = PtrRecords.Any();

            // check if the SPF record contains exists: with no domain
            CheckForNullDnsLookups(parts);
        }


        private async Task<int> CountDnsLookups(string[] parts, HashSet<string> visitedDomains) {
            int dnsLookups = 0;
            foreach (var part in parts) {
                if (part.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                    var domain = part.Substring("include:".Length);
                    if (domain != string.Empty) {
                        if (!visitedDomains.Add(domain)) {
                            CycleDetected = true;
                            continue;
                        }

                        DnsLookups.Add(domain);
                        if (TestSpfRecords.TryGetValue(domain, out var fakeRecord)) {
                            dnsLookups++;
                            var resultParts = TokenizeSpfRecord(fakeRecord).ToArray();
                            foreach (var rp in resultParts) {
                                AddPartToResolvedLists(rp);
                            }
                            dnsLookups += await CountDnsLookups(resultParts, visitedDomains);
                        } else {
                            var dnsResults = await DnsConfiguration.QueryDNS(domain, DnsRecordType.TXT, "SPF1");
                            dnsLookups++;
                            if (dnsResults != null) {
                                foreach (var dnsResult in dnsResults) {
                                    var resultParts = TokenizeSpfRecord(dnsResult.Data).ToArray();
                                    foreach (var rp in resultParts) {
                                        AddPartToResolvedLists(rp);
                                    }
                                    dnsLookups += await CountDnsLookups(resultParts, visitedDomains);
                                }
                            }
                        }
                    }
                } else if (part.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                    var domain = part.Substring("redirect=".Length);
                    if (domain != string.Empty) {
                        if (!visitedDomains.Add(domain)) {
                            CycleDetected = true;
                            continue;
                        }

                        DnsLookups.Add(domain);
                        if (TestSpfRecords.TryGetValue(domain, out var fakeRedirect)) {
                            dnsLookups++;
                            var resultParts = TokenizeSpfRecord(fakeRedirect).ToArray();
                            foreach (var rp in resultParts) {
                                AddPartToResolvedLists(rp);
                            }
                            dnsLookups += await CountDnsLookups(resultParts, visitedDomains);
                        } else {
                            var dnsResults = await DnsConfiguration.QueryDNS(domain, DnsRecordType.TXT, "SPF1");
                            dnsLookups++;
                            if (dnsResults != null) {
                                foreach (var dnsResult in dnsResults) {
                                    var resultParts = TokenizeSpfRecord(dnsResult.Data).ToArray();
                                    foreach (var rp in resultParts) {
                                        AddPartToResolvedLists(rp);
                                    }
                                    dnsLookups += await CountDnsLookups(resultParts, visitedDomains);
                                }
                            }
                        }
                    }
                } else if (part.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                    var domain = part.Substring("exists:".Length);
                    if (domain != string.Empty) {
                        DnsLookups.Add(domain);
                    }
                    dnsLookups++;
                } else if (part.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                    var domain = part.Substring(part.IndexOf(":") + 1);
                    if (domain != string.Empty) {
                        DnsLookups.Add(domain);
                    }
                    dnsLookups++;
                }
            }
            return dnsLookups;
        }

        private int CountAllMechanisms(string[] parts) {
            return parts.Count(part => IsAllMechanism(part));
        }

        private void CheckForNullDnsLookups(string[] parts) {
            foreach (var part in parts) {
                if ((part.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("include:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("exists:", StringComparison.OrdinalIgnoreCase) || part.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) && part.EndsWith(":", StringComparison.Ordinal)) {
                    HasNullLookups = true;
                }
            }
        }

        private void CheckCharacterLimits(IEnumerable<DnsAnswer> spfRecords) {
            int totalLength = 0;
            foreach (var record in spfRecords) {
                foreach (var chunk in record.DataStringsEscaped) {
                    totalLength += chunk.Length;
                    ExceedsCharacterLimit = ExceedsCharacterLimit || chunk.Length > 255;
                }
            }
            ExceedsTotalCharacterLimit = totalLength > 512;
        }

        private void AddPartToList(string part) {
            var token = part.Trim('"');
            if (token.StartsWith("a:", StringComparison.OrdinalIgnoreCase)) {
                ARecords.Add(token.Substring(2).Trim('"'));
            } else if (token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)) {
                MxRecords.Add(token.Substring(3).Trim('"'));
            } else if (token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                PtrRecords.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                ExistsRecords.Add(token.Substring(7).Trim('"'));
            } else if (token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) {
                Ipv4Records.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                Ipv6Records.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                IncludeRecords.Add(token.Substring(8).Trim('"'));
            } else if (token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                RedirectValue = token.Substring(9).Trim('"');
                HasRedirect = true;
            } else if (token.StartsWith("exp=", StringComparison.OrdinalIgnoreCase)) {
                ExpValue = token.Substring(4).Trim('"');
                HasExp = true;
            } else if (IsAllMechanism(token)) {
                AllMechanism = token.Trim('"');
            }

            AddPartToResolvedLists(part);
        }

        private void AddPartToResolvedLists(string part) {
            var token = part.Trim('"');
            if (token.StartsWith("a:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedARecords.Add(token.Substring(2).Trim('"'));
            } else if (token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedMxRecords.Add(token.Substring(3).Trim('"'));
            } else if (token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedPtrRecords.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedExistsRecords.Add(token.Substring(7).Trim('"'));
            } else if (token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedIpv4Records.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedIpv6Records.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                ResolvedIncludeRecords.Add(token.Substring(8).Trim('"'));
            }
        }

        private static bool IsAllMechanism(string part) {
            return part.Equals("all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("+all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("~all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("?all", StringComparison.OrdinalIgnoreCase)
                   || part.Equals("-all", StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> TokenizeSpfRecord(string record) {
            var tokens = new List<string>();
            if (string.IsNullOrEmpty(record)) {
                return tokens;
            }

            var current = new System.Text.StringBuilder();
            var inQuotes = false;
            foreach (var c in record) {
                if (c == '"') {
                    if (inQuotes) {
                        tokens.Add(current.ToString());
                        current.Clear();
                        inQuotes = false;
                    } else {
                        if (current.Length > 0) {
                            tokens.Add(current.ToString());
                            current.Clear();
                        }
                        inQuotes = true;
                    }
                } else if (char.IsWhiteSpace(c) && !inQuotes) {
                    if (current.Length > 0) {
                        tokens.Add(current.ToString());
                        current.Clear();
                    }
                } else {
                    current.Append(c);
                }
            }

            if (current.Length > 0) {
                tokens.Add(current.ToString());
            }

            return tokens;
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