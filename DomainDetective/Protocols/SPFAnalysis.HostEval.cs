using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective
{
    public partial class SpfAnalysis
    {
        /// <summary>
        /// Evaluates the SPF policy for the specified domain against an IP/sender/HELO.
        /// </summary>
        /// <param name="domain">Domain whose SPF policy is evaluated.</param>
        /// <param name="ip">IP address to test.</param>
        /// <param name="sender">RFC 5322 Sender used in macro expansion; defaults to <c>postmaster@domain</c>.</param>
        /// <param name="helo">HELO/EHLO name used in macro expansion; defaults to <c>mail.domain</c>.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        /// <returns>Evaluation result with verdict, matched token, source and lookup statistics.</returns>
        public async Task<SpfHostEvaluation> EvaluateHostAsync(string domain, IPAddress ip, string sender, string helo, InternalLogger? logger = null)
        {
            var eval = new SpfHostEvaluation
            {
                Subject = domain,
                IpAddress = ip.ToString(),
                Sender = string.IsNullOrWhiteSpace(sender) ? $"postmaster@{domain}" : sender,
                Helo = string.IsNullOrWhiteSpace(helo) ? $"mail.{domain}" : helo,
                Verdict = "neutral",
            };

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int lookups = 0;
            async Task<string?> GetRecordAsync(string d)
            {
                if (TestSpfRecords.TryGetValue(d, out var fake)) return fake;
                lookups++;
                if (lookups > MaxDnsLookups) { eval.LookupsExceeded = true; return null; }
                var answers = await DnsConfiguration.QueryDNS(d, DnsRecordType.TXT, "SPF1");
                return answers != null && answers.Length > 0 ? answers[0].Data : null;
            }

            async Task<(bool matched, string verdict, string token, string type, string? source, List<string> chain)> EvalDomainAsync(string d, List<string> chain)
            {
                if (!visited.Add(d)) return (false, "neutral", string.Empty, string.Empty, null, chain);
                string? record = SpfRecordExists && string.Equals(d, Subject, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(SpfRecord)
                    ? SpfRecord
                    : await GetRecordAsync(d);
                if (record == null || string.IsNullOrWhiteSpace(record)) return (false, "neutral", string.Empty, string.Empty, null, chain);
                var parts = TokenizeSpfRecord(record).ToArray();
                foreach (var p in parts)
                {
                    var tok = p.Trim('"');
                    var q = tok.Length > 0 && "+-~?".IndexOf(tok[0]) >= 0 ? tok[0] : '+';
                    string trimmed = tok.TrimStart('+', '-', '~', '?');
                    string verdictForQualifier(char qq) => qq switch { '+' => "pass", '-' => "fail", '~' => "softfail", '?' => "neutral", _ => "neutral" };

                    if (trimmed.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase))
                    {
                        var cidr = trimmed.Substring(4);
                        if (IpMatchesCidr(ip, cidr)) return (true, verdictForQualifier(q), tok, trimmed.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) ? "ip4" : "ip6", d, chain);
                    }
                    else if (trimmed.Equals("a", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("a:", StringComparison.OrdinalIgnoreCase))
                    {
                        var host = trimmed.Length > 2 ? trimmed.Substring(2) : d;
                        lookups++;
                        if (lookups > MaxDnsLookups) { eval.LookupsExceeded = true; return (false, "permerror", tok, "a", d, chain); }
                        var a = await DnsConfiguration.QueryDNS(host, DnsRecordType.A);
                        var aaaa = await DnsConfiguration.QueryDNS(host, DnsRecordType.AAAA);
                        if (a.Concat(aaaa).Any(ans => ans.Data == ip.ToString())) return (true, verdictForQualifier(q), tok, "a", d, chain);
                    }
                    else if (trimmed.Equals("mx", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("mx:", StringComparison.OrdinalIgnoreCase))
                    {
                        var host = trimmed.Length > 3 ? trimmed.Substring(3) : d;
                        lookups++;
                        if (lookups > MaxDnsLookups) { eval.LookupsExceeded = true; return (false, "permerror", tok, "mx", d, chain); }
                        var mx = await DnsConfiguration.QueryDNS(host, DnsRecordType.MX);
                        foreach (var mxr in mx)
                        {
                            var partsMx = mxr.Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            var h = partsMx.Length == 2 ? partsMx[1].TrimEnd('.') : mxr.Data.TrimEnd('.');
                            var a = await DnsConfiguration.QueryDNS(h, DnsRecordType.A);
                            var aaaa = await DnsConfiguration.QueryDNS(h, DnsRecordType.AAAA);
                            if (a.Concat(aaaa).Any(ans => ans.Data == ip.ToString())) return (true, verdictForQualifier(q), tok, "mx", d, chain);
                        }
                    }
                    else if (trimmed.StartsWith("exists:", StringComparison.OrdinalIgnoreCase))
                    {
                        var target = trimmed.Substring(7);
                        var expanded = await ExpandMacrosAsync(target, ip, eval.Sender, eval.Helo, d, logger);
                        lookups++;
                        if (lookups > MaxDnsLookups) { eval.LookupsExceeded = true; return (false, "permerror", tok, "exists", d, chain); }
                        var a = await DnsConfiguration.QueryDNS(expanded, DnsRecordType.A);
                        var aaaa = await DnsConfiguration.QueryDNS(expanded, DnsRecordType.AAAA);
                        if ((a?.Length ?? 0) + (aaaa?.Length ?? 0) > 0) return (true, verdictForQualifier(q), tok, "exists", d, chain);
                    }
                    else if (trimmed.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
                    {
                        var inc = trimmed.Substring(8);
                        var nextChain = new List<string>(chain) { inc };
                        lookups++;
                        if (lookups > MaxDnsLookups) { eval.LookupsExceeded = true; return (false, "permerror", tok, "include", d, chain); }
                        var rec = await GetRecordAsync(inc);
                        if (!string.IsNullOrWhiteSpace(rec))
                        {
                            var sub = await EvalDomainAsync(inc, nextChain);
                            if (sub.matched && sub.verdict == "pass") return (true, "pass", tok, "include", d, nextChain);
                        }
                    }
                    else if (IsAllMechanism(trimmed))
                    {
                        return (true, verdictForQualifier(q), tok, "all", d, chain);
                    }
                }

                return (false, "neutral", string.Empty, string.Empty, null, chain);
            }

            var top = await EvalDomainAsync(domain, new List<string> { domain });
            eval.DnsLookups = lookups;
            if (top.matched)
            {
                eval.Verdict = top.verdict;
                eval.MatchedToken = top.token;
                eval.MatchedType = top.type;
                eval.MatchedDomain = top.source;
                eval.Chain = top.chain;
            }
            else if (eval.LookupsExceeded)
            {
                eval.Verdict = "permerror";
            }
            return eval;
        }

        private static bool IpMatchesCidr(IPAddress ip, string cidr)
        {
            var parts = cidr.Split('/');
            if (!IPAddress.TryParse(parts[0], out var baseIp)) return false;
            int prefix = parts.Length == 2 && int.TryParse(parts[1], out var p) ? p : (baseIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
            var ipBytes = ip.GetAddressBytes();
            var baseBytes = baseIp.GetAddressBytes();
            if (ipBytes.Length != baseBytes.Length)
            {
                return false;
            }
            int fullBytes = prefix / 8;
            int remBits = prefix % 8;
            for (int i = 0; i < fullBytes; i++)
            {
                if (ipBytes[i] != baseBytes[i]) return false;
            }
            if (remBits > 0)
            {
                int mask = 0xFF << (8 - remBits) & 0xFF;
                if ((ipBytes[fullBytes] & mask) != (baseBytes[fullBytes] & mask)) return false;
            }
            return true;
        }
    }
}

