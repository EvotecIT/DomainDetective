using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Globalization;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using DomainDetective.Helpers;

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
    public partial class SpfAnalysis : IHasAssessments {
        /// <summary>Gets flattened spf.</summary>
        public async Task<string> GetFlattenedSpf(InternalLogger? logger = null) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "SPF") : null;
            if (string.IsNullOrEmpty(SpfRecord)) {
                return string.Empty;
            }

            _warnings.Clear();
            _flatteningLimitations.Clear();
            if (!TryValidateSpfSyntax(SpfRecord, out _, out _, out _)) {
                RetainFlatteningDependency("original policy", "invalid syntax prevents equivalent flattening", logger);
                return SpfRecord;
            }

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var tokens = TokenizeSpfRecord(SpfRecord);
            var flattened = await FlattenTokens(tokens, visited, logger);
            var record = string.Join(" ", flattened);

            if (record.Length > 512) {
                _warnings.Add("Flattened SPF record exceeds 512 characters.");
                logger?.WriteWarningCode(SpfCodes.FlattenedLengthExceeds512, "Flattened SPF record exceeds 512 characters.");
            } else if (record.Length > 255) {
                _warnings.Add("Flattened SPF record exceeds 255 characters.");
                logger?.WriteWarningCode(SpfCodes.FlattenedLengthExceeds255, "Flattened SPF record exceeds 255 characters.");
            }

            return record;
        }

        /// <summary>
        /// Generates a detailed analysis of flattened SPF IP addresses.
        /// </summary>
        /// <param name="domainName">Base domain used when an a or mx mechanism omits a domain.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        public async Task<FlattenedSpfResult> GetFlattenedIpAnalysis(string domainName, InternalLogger? logger = null) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "SPF", target: domainName) : null;
            if (string.IsNullOrEmpty(SpfRecord)) {
                _flatteningLimitations.Clear();
                _flatteningLimitations.Add(DnsQueryFailed
                    ? "SPF DNS query failed; policy presence and authorized addresses are unknown."
                    : "No SPF policy is available for address projection.");
                FlattenedIpAnalysis = new FlattenedSpfResult {
                    Subject = domainName, Complete = false, Limitations = _flatteningLimitations.ToArray()
                };
                return FlattenedIpAnalysis;
            }

            _flatteningLimitations.Clear();
            if (PermError || MultipleSpfRecords) {
                RetainFlatteningDependency("original policy", "invalid syntax or multiple policies prevents IP authorization analysis", logger);
                FlattenedIpAnalysis = new FlattenedSpfResult {
                    Subject = domainName, Complete = false, Limitations = _flatteningLimitations.ToArray()
                };
                return FlattenedIpAnalysis;
            }

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var tokens = await FlattenTokens(TokenizeSpfRecord(SpfRecord), visited, logger);
            var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var duplicates = new List<string>();
            var tokenIpMap = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var t in ReachableSpfTerms(tokens)) {
                var token = t.Trim('"');
                var resolved = await ResolveSpfAddressTermAsync(token, domainName, logger);

                if (resolved.Count > 0) {
                    tokenIpMap[token] = resolved;
                    foreach (var ip in resolved) {
                        if (!addresses.Add(ip) && !duplicates.Contains(ip)) {
                            duplicates.Add(ip);
                        }
                    }
                }
            }

            FlattenedIpAnalysis = new FlattenedSpfResult {
                Subject = domainName,
                Tokens = tokens,
                TokenIpMap = tokenIpMap,
                UniqueIps = addresses.ToList(),
                DuplicateIps = duplicates,
                Complete = FlatteningComplete,
                Limitations = _flatteningLimitations.ToArray()
            };

            if (duplicates.Count == 0 && addresses.Count > 0) {
                logger?.WriteInformationCode(SpfCodes.FlattenedIpSetOptimized, "Flattened SPF IP set has no duplicates");
            }

            return FlattenedIpAnalysis;
        }

        /// <summary>
        /// Returns all IP addresses referenced by the SPF record after resolving includes and redirects.
        /// </summary>
        /// <param name="domainName">Base domain used when an a or mx mechanism omits a domain.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        public async Task<List<string>> GetFlattenedIpAddresses(string domainName, InternalLogger? logger = null) {
            var analysis = await GetFlattenedIpAnalysis(domainName, logger);
            return analysis.UniqueIps;
        }

        /// <summary>
        /// Builds a flattened SPF tree representation with indentation showing include and redirect branches.
        /// </summary>
        public async Task<List<string>> GetFlattenedSpfTree(InternalLogger? logger = null) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "SPF") : null;
            if (string.IsNullOrEmpty(SpfRecord)) {
                return new List<string>();
            }

            _warnings.Clear();
            _flatteningLimitations.Clear();

            var lines = new List<string> { "v=spf1" };
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await BuildTree(TokenizeSpfRecord(SpfRecord), visited, 0, lines, logger);

            var flatTokens = await FlattenTokens(TokenizeSpfRecord(SpfRecord), new HashSet<string>(StringComparer.OrdinalIgnoreCase), logger);
            var record = string.Join(" ", flatTokens);
            if (record.Length > 512) {
                _warnings.Add("Flattened SPF record exceeds 512 characters.");
                logger?.WriteWarningCode(SpfCodes.FlattenedLengthExceeds512, "Flattened SPF record exceeds 512 characters.");
            } else if (record.Length > 255) {
                _warnings.Add("Flattened SPF record exceeds 255 characters.");
                logger?.WriteWarningCode(SpfCodes.FlattenedLengthExceeds255, "Flattened SPF record exceeds 255 characters.");
            }

            return lines;
        }

        /// <summary>
        /// Computes whether SPF effectively authorizes outbound sending after
        /// resolving include/redirect chains and updates <see cref="EffectiveSpfSends"/>.
        /// </summary>
        public async Task ComputeEffectiveSpfSendsAsync(InternalLogger? logger = null) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "SPF") : null;
            EffectiveSpfSends = false;
            if (!SpfRecordExists || string.IsNullOrWhiteSpace(SpfRecord) || !StartsCorrectly) {
                return;
            }
            if (PermError || ExceedsDnsLookups || MultipleSpfRecords) {
                return;
            }

            EffectiveSpfSends = await MayAuthorizeSendingAsync(SpfRecord, logger);
        }

        private async Task BuildTree(IEnumerable<string> tokens, HashSet<string> visited, int depth, List<string> lines, InternalLogger? logger) {
            if (depth > MaxDnsLookups) return;
            foreach (var term in ReachableSpfTerms(tokens)) {
                string token = term.Trim('"');
                if (token.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)) continue;
                lines.Add(new string(' ', depth * 2) + token);
                string mechanism = token.Length > 0 && "+-~?".IndexOf(token[0]) >= 0 ? token.Substring(1) : token;
                bool include = mechanism.StartsWith("include:", StringComparison.OrdinalIgnoreCase);
                bool redirect = mechanism.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase);
                if (!include && !redirect) continue;
                string domain = mechanism.Substring(include ? 8 : 9);
                if (domain.Length == 0 || domain.IndexOf('%') >= 0 || !visited.Add(domain)) continue;
                try {
                    var record = await ResolveSpfRecordForCounting(domain, logger, include ? "include" : "redirect");
                    if (!string.IsNullOrEmpty(record)) await BuildTree(TokenizeSpfRecord(record!), visited, depth + 1, lines, logger);
                } finally {
                    visited.Remove(domain);
                }
            }
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

            if (type == DnsRecordType.TXT) {
                return await DnsConfiguration.QueryDNS(
                    name,
                    type,
                    filter: string.Empty,
                    includeAliasesInFilter: true);
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

        /// <summary>Gets explanation text.</summary>
        public async Task<string?> GetExplanationText(IPAddress ip, string sender, string helo, string domain, InternalLogger? logger = null)
        {
            var expValue = ExpValue;
            if (expValue == null || expValue.Length == 0)
            {
                return null;
            }

            ExpDnsLookupsCount = 0;
            ExpExceedsDnsLookups = false;
            var target = await ExpandMacrosAsync(expValue, ip, sender, helo, domain, logger);
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
}
