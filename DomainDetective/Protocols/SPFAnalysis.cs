using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Globalization;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

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
    /// <para>Part of the DomainDetective project.</para>
    public class SpfAnalysis {
        internal DnsConfiguration DnsConfiguration { get; set; }

        /// <summary>Combined SPF record text.</summary>
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
        public bool InvalidIpSyntax { get; private set; }
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

        public List<string> UnknownMechanisms { get; private set; } = new List<string>();

        public Dictionary<string, string> TestSpfRecords { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public bool CycleDetected { get; private set; }
        public string CyclePath { get; private set; }
        public bool PermError { get; private set; }
        public List<string> RedirectVisitedDomains { get; private set; } = new List<string>();
        private HashSet<string> _visitedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);


        public List<SpfPartAnalysis> SpfPartAnalyses { get; private set; } = new List<SpfPartAnalysis>();
        public List<SpfTestResult> SpfTestResults { get; private set; } = new List<SpfTestResult>();
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        private const int MaxDnsLookups = 10;
        public int ExpDnsLookupsCount { get; private set; }
        public bool ExpExceedsDnsLookups { get; private set; }
        private readonly List<string> _warnings = new();
        public IReadOnlyList<string> Warnings => _warnings;

        private static readonly Regex MacroRegex = new(
            @"%\{(?<letter>[slodipvhcrt])(?<digits>\d{1,2})?(?<reverse>r)?(?<delims>[.\-+,/_=]*)\}",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

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
            InvalidIpSyntax = false;
            CycleDetected = false;
            CyclePath = null;
            PermError = false;
            RedirectVisitedDomains = new List<string>();
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
            UnknownMechanisms = new List<string>();
            ExpValue = null;
            RedirectValue = null;
            AllMechanism = null;
            SpfPartAnalyses = new List<SpfPartAnalysis>();
            SpfTestResults = new List<SpfTestResult>();
            _warnings.Clear();
            ExpDnsLookupsCount = 0;
            ExpExceedsDnsLookups = false;
        }

        public async Task AnalyzeSpfRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            Reset();
            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }
            var spfRecordList = dnsResults.ToList();
            SpfRecordExists = spfRecordList.Any();
            MultipleSpfRecords = spfRecordList.Count > 1;

            // create a list of strings from the list of DnsResult objects
            // we use DataStringsEscaped to get the escaped strings, as provided by DnsClientX
            // this will allow us to test if the record length exceeds 255 characters
            foreach (var record in spfRecordList) {
                foreach (var chunk in record.DataStringsEscaped) {
                    SpfRecords.Add(TrimQuotes(chunk));
                }
            }
            WarnIfSpfRecordChunksTooLong(logger);
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
            int dnsLookups = await CountDnsLookups(parts, _visitedDomains, new List<string>(), logger);
            DnsLookupsCount = dnsLookups;
            ExceedsDnsLookups = ExceedsDnsLookups || DnsLookupsCount > 10;

            // check that the SPF record does not have more than one "all" mechanism
            MultipleAllMechanisms = MultipleAllMechanisms || CountAllMechanisms(parts) > 1;

            // add the parts to the appropriate lists
            foreach (var part in parts) {
                AddPartToList(part, logger);
            }

            // check if the SPF record contains characters after "all"
            ContainsCharactersAfterAll = parts
                .Where(part => IsAllMechanism(part))
                .Any(part => !part.Equals(parts.Last(), StringComparison.OrdinalIgnoreCase));

            // check if the SPF record contains a PTR type
            HasPtrType = PtrRecords.Any();

            // check if the SPF record contains exists: with no domain
            CheckForNullDnsLookups(parts);

            // keep TestSpfRecords intact so subsequent operations like
            // GetFlattenedSpf can resolve fake DNS records in unit tests

            WarnIfExceedsDnsLookups(logger);
        }


        private async Task<int> CountDnsLookups(string[] parts, HashSet<string> visitedDomains, List<string> path, InternalLogger? logger) {
            int dnsLookups = 0;
            foreach (var part in parts) {
                if (part.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                    var domain = part.Substring("include:".Length);
                    if (domain != string.Empty) {
                        if (!visitedDomains.Add(domain)) {
                            CycleDetected = true;
                            CyclePath ??= string.Join(" -> ", path.Concat(new[] { domain }));
                            PermError = true;
                            return dnsLookups;
                        }

                        DnsLookups.Add(domain);
                        path.Add(domain);
                        if (TestSpfRecords.TryGetValue(domain, out var fakeRecord)) {
                            dnsLookups++;
                            var resultParts = TokenizeSpfRecord(fakeRecord).ToArray();
                            foreach (var rp in resultParts) {
                                AddPartToResolvedLists(rp, logger);
                            }
                            dnsLookups += await CountDnsLookups(resultParts, visitedDomains, path, logger);
                        } else {
                            var dnsResults = await DnsConfiguration.QueryDNS(domain, DnsRecordType.TXT, "SPF1");
                            dnsLookups++;
                            if (dnsResults != null) {
                                foreach (var dnsResult in dnsResults) {
                                    var resultParts = TokenizeSpfRecord(dnsResult.Data).ToArray();
                                    foreach (var rp in resultParts) {
                                        AddPartToResolvedLists(rp, logger);
                                    }
                                    dnsLookups += await CountDnsLookups(resultParts, visitedDomains, path, logger);
                                }
                            }
                        }
                        path.RemoveAt(path.Count - 1);
                    }
                } else if (part.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                    var domain = part.Substring("redirect=".Length);
                    if (domain != string.Empty) {
                        RedirectVisitedDomains.Add(domain);
                        if (!visitedDomains.Add(domain)) {
                            CycleDetected = true;
                            CyclePath ??= string.Join(" -> ", path.Concat(new[] { domain }));
                            PermError = true;
                            return dnsLookups;
                        }

                        DnsLookups.Add(domain);
                        path.Add(domain);
                        if (TestSpfRecords.TryGetValue(domain, out var fakeRedirect)) {
                            dnsLookups++;
                            var resultParts = TokenizeSpfRecord(fakeRedirect).ToArray();
                            foreach (var rp in resultParts) {
                                AddPartToResolvedLists(rp, logger);
                            }
                            dnsLookups += await CountDnsLookups(resultParts, visitedDomains, path, logger);
                        } else {
                            var dnsResults = await DnsConfiguration.QueryDNS(domain, DnsRecordType.TXT, "SPF1");
                            dnsLookups++;
                            if (dnsResults != null) {
                                foreach (var dnsResult in dnsResults) {
                                    var resultParts = TokenizeSpfRecord(dnsResult.Data).ToArray();
                                    foreach (var rp in resultParts) {
                                        AddPartToResolvedLists(rp, logger);
                                    }
                                    dnsLookups += await CountDnsLookups(resultParts, visitedDomains, path, logger);
                                }
                            }
                        }
                        path.RemoveAt(path.Count - 1);
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
                    var sanitized = TrimQuotes(chunk);
                    totalLength += sanitized.Length;
                    ExceedsCharacterLimit = ExceedsCharacterLimit || sanitized.Length > 255;
                }
            }
            ExceedsTotalCharacterLimit = totalLength > 512;
        }

        /// <summary>Adds warnings for SPF TXT chunks over 255 characters.</summary>
        private void WarnIfSpfRecordChunksTooLong(InternalLogger? logger) {
            for (int i = 0; i < SpfRecords.Count; i++) {
                if (SpfRecords[i].Length > 255) {
                    _warnings.Add($"SPF record chunk {i + 1} exceeds 255 characters.");
                    logger?.WriteWarning($"SPF record chunk {i + 1} exceeds 255 characters.");
                }
            }
        }

        private void WarnIfExceedsDnsLookups(InternalLogger? logger) {
            if (ExceedsDnsLookups) {
                var message = $"SPF record requires {DnsLookupsCount} DNS lookups which exceeds the limit of {MaxDnsLookups}.";
                if (!_warnings.Contains(message)) {
                    _warnings.Add(message);
                }
                logger?.WriteWarning(message);
            }
        }

        private static string TrimQuotes(string value) {
            var trimmed = value.Trim();
            if (trimmed.Length == 0) {
                return trimmed;
            }

            if (trimmed.StartsWith("\\\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(2);
            } else if (trimmed.StartsWith("\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(1);
            }

            if (trimmed.EndsWith("\\\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(0, trimmed.Length - 2);
            } else if (trimmed.EndsWith("\"", StringComparison.Ordinal)) {
                trimmed = trimmed.Substring(0, trimmed.Length - 1);
            }

            return trimmed;
        }

        private void AddPartToList(string part, InternalLogger? logger) {
            var token = part.Trim('"');
            var normalized = token.TrimStart('+', '-', '~', '?');
            ValidateMacros(token, logger);
            if (token.StartsWith("a:", StringComparison.OrdinalIgnoreCase)) {
                ARecords.Add(token.Substring(2).Trim('"'));
            } else if (token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)) {
                MxRecords.Add(token.Substring(3).Trim('"'));
            } else if (token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)) {
                PtrRecords.Add(token.Substring(4).Trim('"'));
            } else if (token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)) {
                ExistsRecords.Add(token.Substring(7).Trim('"'));
            } else if (token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) {
                var value = token.Substring(4).Trim('"');
                Ipv4Records.Add(value);
                if (!TryParseCidr(value, 32)) {
                    InvalidIpSyntax = true;
                }
            } else if (token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                var value = token.Substring(4).Trim('"');
                Ipv6Records.Add(value);
                if (!TryParseCidr(value, 128)) {
                    InvalidIpSyntax = true;
                }
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
            } else if (!IsAllowedMechanismOrModifier(normalized)) {
                if (!UnknownMechanisms.Contains(token)) {
                    UnknownMechanisms.Add(token);
                }
            }

            AddPartToResolvedLists(part, logger);
        }

        private void AddPartToResolvedLists(string part, InternalLogger? logger) {
            var token = part.Trim('"');
            var normalized = token.TrimStart('+', '-', '~', '?');
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
            } else if (!IsAllowedMechanismOrModifier(normalized) && !IsAllMechanism(normalized)) {
                if (!UnknownMechanisms.Contains(token)) {
                    UnknownMechanisms.Add(token);
                }
            }
            ValidateMacros(token, logger);
        }

        private void ValidateMacros(string token, InternalLogger? logger) {
            var index = token.IndexOf('%');
            while (index >= 0 && index < token.Length) {
                if (index + 1 >= token.Length) {
                    _warnings.Add($"Invalid percent escape in token '{token}'");
                    logger?.WriteWarning($"Invalid percent escape in token '{token}'");
                    break;
                }

                var next = token[index + 1];
                if (next == '%') {
                    index = token.IndexOf('%', index + 2);
                    continue;
                }

                if (next == '_' || next == '-') {
                    index = token.IndexOf('%', index + 2);
                    continue;
                }

                if (next == '{') {
                    var end = token.IndexOf('}', index + 2);
                    if (end == -1) {
                        _warnings.Add($"Invalid SPF macro syntax in token '{token}'");
                        logger?.WriteWarning($"Invalid SPF macro syntax in token '{token}'");
                        break;
                    }

                    var macro = token.Substring(index, end - index + 1);
                    if (!IsValidMacro(macro)) {
                        _warnings.Add($"Invalid SPF macro syntax: {macro}");
                        logger?.WriteWarning($"Invalid SPF macro syntax: {macro}");
                    }
                    index = token.IndexOf('%', end + 1);
                    continue;
                }

                _warnings.Add($"Invalid percent escape in token '{token}'");
                logger?.WriteWarning($"Invalid percent escape in token '{token}'");
                index = token.IndexOf('%', index + 1);
            }
        }

        private static bool IsValidMacro(string macro) {
            var match = MacroRegex.Match(macro);
            if (!match.Success) {
                return false;
            }

            if (match.Groups["digits"].Success &&
                (!int.TryParse(match.Groups["digits"].Value, out var digits) || digits > 99)) {
                return false;
            }

            return true;
        }

        private static bool IsAllowedMechanismOrModifier(string token) {
            return token.StartsWith("a:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("exists:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("ptr:", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)
                   || token.StartsWith("exp=", StringComparison.OrdinalIgnoreCase)
                   || token.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)
                   || IsAllMechanism(token);
        }
      
        private static bool TryParseCidr(string value, int maxPrefixLength) {
            var segments = value.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0 || segments.Length > 2) {
                return false;
            }

            if (!IPAddress.TryParse(segments[0], out _)) {
                return false;
            }

            if (segments.Length == 2) {
                if (!int.TryParse(segments[1], NumberStyles.None, CultureInfo.InvariantCulture, out var mask)) {
                    return false;
                }

                if (mask > maxPrefixLength) {
                    return false;
                }
            }

            return true;
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
            var escapeNext = false;
            var commentDepth = 0;

            foreach (var c in record) {
                if (escapeNext) {
                    if (commentDepth == 0) {
                        current.Append(c);
                    }
                    escapeNext = false;
                    continue;
                }

                if (c == '\\') {
                    escapeNext = true;
                    continue;
                }

                if (commentDepth > 0) {
                    if (c == '(') {
                        commentDepth++;
                    } else if (c == ')') {
                        commentDepth--;
                    }
                    continue;
                }

                if (!inQuotes && c == '(') {
                    commentDepth = 1;
                    continue;
                }

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

        /// <summary>
        /// Produces a flattened SPF record by resolving include and redirect modifiers.
        /// </summary>
        public async Task<string> GetFlattenedSpf(InternalLogger? logger = null) {
            if (string.IsNullOrEmpty(SpfRecord)) {
                return string.Empty;
            }

            _warnings.Clear();

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var tokens = TokenizeSpfRecord(SpfRecord);
            var flattened = await FlattenTokens(tokens, visited, logger);
            var record = string.Join(" ", flattened);

            if (record.Length > 512) {
                _warnings.Add("Flattened SPF record exceeds 512 characters.");
                logger?.WriteWarning("Flattened SPF record exceeds 512 characters.");
            } else if (record.Length > 255) {
                _warnings.Add("Flattened SPF record exceeds 255 characters.");
                logger?.WriteWarning("Flattened SPF record exceeds 255 characters.");
            }

            return record;
        }

        /// <summary>
        /// Returns all IP addresses referenced by the SPF record after resolving includes and redirects.
        /// </summary>
        /// <param name="domainName">Base domain used when an a or mx mechanism omits a domain.</param>
        public async Task<List<string>> GetFlattenedIpAddresses(string domainName, InternalLogger? logger = null) {
            if (string.IsNullOrEmpty(SpfRecord)) {
                return new List<string>();
            }

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var tokens = await FlattenTokens(TokenizeSpfRecord(SpfRecord), visited, logger);
            var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var t in tokens) {
                var token = t.Trim('"');
                if (token.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) {
                    addresses.Add(token.Substring(4));
                } else if (token.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
                    addresses.Add(token.Substring(4));
                } else if (token.Equals("a", StringComparison.OrdinalIgnoreCase) || token.StartsWith("a:", StringComparison.OrdinalIgnoreCase)) {
                    var host = token.Length > 2 ? token.Substring(2) : domainName;
                    var a = await QueryDns(host, DnsRecordType.A);
                    var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                    foreach (var ans in a.Concat(aaaa)) {
                        addresses.Add(ans.Data);
                    }
                } else if (token.Equals("mx", StringComparison.OrdinalIgnoreCase) || token.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)) {
                    var hostDomain = token.Length > 3 ? token.Substring(3) : domainName;
                    var mxRecords = await QueryDns(hostDomain, DnsRecordType.MX);
                    foreach (var mx in mxRecords) {
                        var parts = mx.Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var host = parts.Length == 2 ? parts[1].TrimEnd('.') : mx.Data.TrimEnd('.');
                        var a = await QueryDns(host, DnsRecordType.A);
                        var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                        foreach (var ans in a.Concat(aaaa)) {
                            addresses.Add(ans.Data);
                        }
                    }
                }
            }

            return addresses.ToList();
        }

        private async Task<List<string>> FlattenTokens(IEnumerable<string> tokens, HashSet<string> visited, InternalLogger? logger) {
            List<string> result = new();
            foreach (var t in tokens) {
                var token = t.Trim('"');
                if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                    var domain = token.Substring(8);
                    if (!string.IsNullOrEmpty(domain)) {
                        if (!visited.Add(domain)) {
                            CycleDetected = true;
                            _warnings.Add($"Cycle detected when flattening include {domain}");
                            logger?.WriteWarning($"Cycle detected when flattening include {domain}");
                            continue;
                        }

                        string? includeRecord = null;
                        if (TestSpfRecords.TryGetValue(domain, out var fakeRecord)) {
                            includeRecord = fakeRecord;
                        } else {
                            var answers = await DnsConfiguration.QueryDNS(domain, DnsRecordType.TXT, "SPF1");
                            if (answers != null && answers.Length > 0) {
                                includeRecord = answers[0].Data;
                            }
                        }

                        if (!string.IsNullOrEmpty(includeRecord)) {
                            var flattened = await FlattenTokens(TokenizeSpfRecord(includeRecord), visited, logger);
                            result.AddRange(flattened.Where(x =>
                                !x.Equals("v=spf1", StringComparison.OrdinalIgnoreCase) &&
                                !IsAllMechanism(x)));
                        }

                        visited.Remove(domain);
                    }
                } else if (token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) {
                    var domain = token.Substring(9);
                    if (!string.IsNullOrEmpty(domain)) {
                        string? redirectRecord = null;
                        if (TestSpfRecords.TryGetValue(domain, out var fakeRecord)) {
                            redirectRecord = fakeRecord;
                        } else {
                            var answers = await DnsConfiguration.QueryDNS(domain, DnsRecordType.TXT, "SPF1");
                            if (answers != null && answers.Length > 0) {
                                redirectRecord = answers[0].Data;
                            }
                        }

                        if (!string.IsNullOrEmpty(redirectRecord)) {
                            return await FlattenTokens(TokenizeSpfRecord(redirectRecord), visited, logger);
                        }
                    }
                } else {
                    if (!token.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)) {
                        result.Add(token);
                    }
                }
            }

            result.Insert(0, "v=spf1");
            return result;
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
        {
            if (QueryDnsOverride != null)
            {
                return await QueryDnsOverride(name, type);
            }

            if (type == DnsRecordType.TXT && TestSpfRecords.TryGetValue(name, out var txt))
            {
                return new[] { new DnsAnswer { DataRaw = txt, Type = DnsRecordType.TXT } };
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        private static string ApplyTransform(string value, string digits, bool reverse, string delims)
        {
            var separators = string.IsNullOrEmpty(delims) ? new[] { '.' } : delims.ToCharArray();
            var parts = value.Split(separators, StringSplitOptions.None);
            if (reverse)
            {
                Array.Reverse(parts);
            }

            if (!string.IsNullOrEmpty(digits) && int.TryParse(digits, out var count))
            {
                if (count < parts.Length)
                {
                    parts = parts.Skip(parts.Length - count).ToArray();
                }
            }

            return string.Join(".", parts);
        }

        private async Task<string> ExpandMacrosAsync(string text, IPAddress ip, string sender, string helo, string domain, InternalLogger? logger)
        {
            var result = new System.Text.StringBuilder();
            for (int i = 0; i < text.Length;)
            {
                var idx = text.IndexOf('%', i);
                if (idx == -1 || idx == text.Length - 1)
                {
                    result.Append(text.Substring(i));
                    break;
                }

                result.Append(text.Substring(i, idx - i));
                var next = text[idx + 1];
                if (next == '%')
                {
                    result.Append('%');
                    i = idx + 2;
                    continue;
                }

                if (next == '_')
                {
                    result.Append(' ');
                    i = idx + 2;
                    continue;
                }

                if (next == '-')
                {
                    result.Append("%20");
                    i = idx + 2;
                    continue;
                }

                if (next != '{')
                {
                    result.Append('%');
                    i = idx + 1;
                    continue;
                }

                var end = text.IndexOf('}', idx + 2);
                if (end == -1)
                {
                    result.Append(text.Substring(idx));
                    break;
                }

                var macro = text.Substring(idx, end - idx + 1);
                var match = MacroRegex.Match(macro);
                if (!match.Success)
                {
                    result.Append(macro);
                    i = end + 1;
                    continue;
                }

                if (ExpDnsLookupsCount > MaxDnsLookups)
                {
                    ExpExceedsDnsLookups = true;
                    return string.Empty;
                }

                var letter = match.Groups["letter"].Value[0];
                var digits = match.Groups["digits"].Value;
                var rev = match.Groups["reverse"].Success;
                var delims = match.Groups["delims"].Value;
                var upper = char.IsUpper(letter);
                letter = char.ToLowerInvariant(letter);

                string value = letter switch
                {
                    's' => sender,
                    'l' => sender.Split('@')[0],
                    'o' => sender.Contains('@') ? sender.Split('@')[1] : domain,
                    'd' => domain,
                    'i' => ip.ToString(),
                    'h' => helo,
                    'v' => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "in-addr" : "ip6",
                    'c' => ip.ToString(),
                    'r' => helo,
                    't' => DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                    'p' => await GetPtrDomain(ip, logger),
                    _ => string.Empty
                };

                value = ApplyTransform(value, digits, rev, delims);
                if (upper)
                {
                    value = Uri.EscapeDataString(value);
                }

                result.Append(value);
                i = end + 1;
            }

            return result.ToString();
        }

        private async Task<string> GetPtrDomain(IPAddress ip, InternalLogger? logger)
        {
            ExpDnsLookupsCount++;
            var ptrName = ip.ToPtrFormat() + (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? ".in-addr.arpa" : ".ip6.arpa");
            var ptr = await QueryDns(ptrName, DnsRecordType.PTR);
            ExpDnsLookupsCount += 2; // A and AAAA lookups are counted even if PTR fails
            if (ptr.Length == 0)
            {
                return "unknown";
            }

            var host = ptr[0].Data.TrimEnd('.');
            var a = await QueryDns(host, DnsRecordType.A);
            var aaaa = await QueryDns(host, DnsRecordType.AAAA);
            if (a.Concat(aaaa).Any(r => r.Data == ip.ToString()))
            {
                return host;
            }

            return "unknown";
        }

        public async Task<string?> GetExplanationText(IPAddress ip, string sender, string helo, string domain, InternalLogger? logger = null)
        {
            if (string.IsNullOrEmpty(ExpValue))
            {
                return null;
            }

            ExpDnsLookupsCount = 0;
            ExpExceedsDnsLookups = false;
            var target = await ExpandMacrosAsync(ExpValue, ip, sender, helo, domain, logger);
            if (ExpExceedsDnsLookups || ExpDnsLookupsCount > MaxDnsLookups)
            {
                ExpExceedsDnsLookups = true;
                return null;
            }

            ExpDnsLookupsCount++;
            var txt = await QueryDns(target, DnsRecordType.TXT);
            if (txt.Length != 1)
            {
                return null;
            }

            var explanationTemplate = string.Concat(txt[0].DataStringsEscaped);
            var explanation = await ExpandMacrosAsync(explanationTemplate, ip, sender, helo, domain, logger);
            if (ExpExceedsDnsLookups || ExpDnsLookupsCount > MaxDnsLookups)
            {
                ExpExceedsDnsLookups = true;
                return null;
            }

            return explanation;
        }

    }

    /// <summary>
    /// Holds details about a parsed part of an SPF record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SpfPartAnalysis {
        public string Prefix { get; set; }
        public string Type { get; set; }
        public string Value { get; set; }
        public string PrefixDesc { get; set; }
        public string Description { get; set; }
    }

    /// <summary>
    /// Result of a single SPF validation test.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SpfTestResult {
        public string Test { get; set; }
        public string Result { get; set; }
        public string Assessment { get; set; }
    }
}