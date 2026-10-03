using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class SpfAnalysis {
    private async Task<List<string>> ResolveSpfAddressTermAsync(string term, string defaultDomain, InternalLogger? logger) {
        var result = new List<string>();
        if (TryGetSpfModifier(term, out _, out _)) return result;
        if (term.Length > 0 && "+-~?".IndexOf(term[0]) >= 0) {
            if (term[0] != '+') return result;
            term = term.Substring(1);
        }
        if (term.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase) || term.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase)) {
            result.Add(term.Substring(4));
            return result;
        }
        string name = term.Equals("a", StringComparison.OrdinalIgnoreCase) || term.StartsWith("a:", StringComparison.OrdinalIgnoreCase)
            || term.StartsWith("a/", StringComparison.OrdinalIgnoreCase) ? "a" : "mx";
        if (name == "mx" && !term.Equals("mx", StringComparison.OrdinalIgnoreCase) && !term.StartsWith("mx:", StringComparison.OrdinalIgnoreCase)
            && !term.StartsWith("mx/", StringComparison.OrdinalIgnoreCase)) return result;
        if (!TryParseDualCidrMechanism(term, name, defaultDomain, out string domain, out int ipv4Prefix, out int ipv6Prefix)) return result;
        if (domain.IndexOf('%') >= 0) {
            RetainFlatteningDependency(term, "sender-dependent macros prevent a concrete address projection", logger);
            return result;
        }
        DnsAnswer[]? mxAnswers = name == "mx" ? await QuerySpfAddressDns(domain, DnsRecordType.MX, term, logger) : null;
        if (name == "mx" && mxAnswers == null) return result;
        var hosts = name == "a" ? new[] { domain } : mxAnswers!
            .Where(answer => answer.Type == DnsRecordType.MX).Take(10).Select(answer => {
                var parts = answer.Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                return parts.Length == 0 ? string.Empty : parts[parts.Length - 1].TrimEnd('.');
            }).Where(host => !string.IsNullOrWhiteSpace(host)).ToArray();
        foreach (string host in hosts) {
            var ipv4 = await QuerySpfAddressDns(host, DnsRecordType.A, term, logger);
            var ipv6 = await QuerySpfAddressDns(host, DnsRecordType.AAAA, term, logger);
            foreach (var answer in (ipv4 ?? Array.Empty<DnsAnswer>()).Concat(ipv6 ?? Array.Empty<DnsAnswer>())) {
                if (answer.Type != DnsRecordType.A && answer.Type != DnsRecordType.AAAA || !IPAddress.TryParse(answer.Data, out var address)) continue;
                bool isIpv4 = address.AddressFamily == AddressFamily.InterNetwork;
                int prefix = isIpv4 ? ipv4Prefix : ipv6Prefix;
                result.Add(address + (prefix == (isIpv4 ? 32 : 128) ? string.Empty : "/" + prefix));
            }
        }
        return result;
    }

    private async Task<DnsAnswer[]?> QuerySpfAddressDns(string name, DnsRecordType type, string term, InternalLogger? logger) {
        try {
            return QueryDnsOverride != null
                ? await QueryDnsOverride(name, type)
                : await DnsConfiguration.QueryPolicyDNS(name, type);
        } catch (Exception exception) when (exception is DnsQueryFailureException || exception is TaskCanceledException ||
            exception is TimeoutException || exception is System.Net.Http.HttpRequestException) {
            RetainFlatteningDependency(term, $"address lookup failed for {name} ({type}): {exception.Message}", logger);
            return null;
        }
    }

    // This sending signal is a bounded best-effort policy inspection, separate
    // from an equivalent flattened record and from a host-specific SPF verdict.
    private async Task<bool> MayAuthorizeSendingAsync(string record, InternalLogger? logger) {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int lookups = 0;
        async Task<bool> Inspect(string policy) {
            if (!TryValidateSpfSyntax(policy, out var source, out _, out _)) return false;
            string? redirect = null;
            foreach (string term in ReachableSpfTerms(source).Skip(1)) {
                if (TryGetSpfModifier(term, out string modifier, out string value)) {
                    if (modifier.Equals("redirect", StringComparison.OrdinalIgnoreCase)) redirect = value;
                    continue;
                }
                char qualifier = "+-~?".IndexOf(term[0]) >= 0 ? term[0] : '+';
                string token = "+-~?".IndexOf(term[0]) >= 0 ? term.Substring(1) : term;
                if (IsAllMechanism(term)) return qualifier == '+';
                if (qualifier != '+') continue;
                if (!token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) return true;
                if (await InspectTarget(token.Substring(8), "include")) return true;
            }
            return redirect != null && await InspectTarget(redirect, "redirect");
        }
        async Task<bool> InspectTarget(string target, string mechanism) {
            if (++lookups > MaxDnsLookups || !visited.Add(target)) return false;
            try {
                // It may authorize a sender, but no sender context is available for expansion.
                if (target.IndexOf('%') >= 0) return true;
                string? child = await ResolveSpfRecordForCounting(target, logger, mechanism);
                return child != null && await Inspect(child);
            } finally {
                visited.Remove(target);
            }
        }
        return await Inspect(record);
    }
}
