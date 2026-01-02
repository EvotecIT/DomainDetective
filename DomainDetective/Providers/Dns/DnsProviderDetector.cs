using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Providers.Dns;

public static class DnsProviderDetector
{
    public sealed class Match
    {
        public DnsProvider Provider { get; init; }
        public int Score { get; init; }
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

    public static Match Detect(IEnumerable<string>? nameServers, string? soaPrimaryNameServer = null)
    {
        var nsHosts = (nameServers ?? Array.Empty<string>())
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(NormalizeHost)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var soa = NormalizeHost(soaPrimaryNameServer);

        if (nsHosts.Count == 0 && string.IsNullOrWhiteSpace(soa))
        {
            return new Match { Provider = DnsProvider.Unknown, Score = 0 };
        }

        Match? best = null;
        foreach (var rule in Rules)
        {
            int score = 0;
            var evidence = new List<string>();

            foreach (var host in nsHosts)
            {
                foreach (var pat in rule.NsPatterns)
                {
                    if (!WildcardMatch(host, pat))
                    {
                        continue;
                    }

                    score++;
                    if (evidence.Count < 8)
                    {
                        evidence.Add($"NS {host} matches {pat}");
                    }
                    break;
                }
            }

            if (!string.IsNullOrWhiteSpace(soa))
            {
                foreach (var pat in rule.SoaPatterns)
                {
                    if (!WildcardMatch(soa!, pat))
                    {
                        continue;
                    }

                    score++;
                    if (evidence.Count < 8)
                    {
                        evidence.Add($"SOA {soa} matches {pat}");
                    }
                    break;
                }
            }

            if (score <= 0)
            {
                continue;
            }

            var current = new Match
            {
                Provider = rule.Provider,
                Score = score,
                Evidence = evidence
            };

            if (best == null || current.Score > best.Score)
            {
                best = current;
            }
        }

        return best ?? new Match { Provider = DnsProvider.Unknown, Score = 0 };
    }

    private sealed class Rule
    {
        public DnsProvider Provider { get; init; }
        public string[] NsPatterns { get; init; } = Array.Empty<string>();
        public string[] SoaPatterns { get; init; } = Array.Empty<string>();
    }

    private static readonly Rule[] Rules = new[]
    {
        new Rule
        {
            Provider = DnsProvider.Cloudflare,
            NsPatterns = new[] { "*.ns.cloudflare.com" }
        },
        new Rule
        {
            Provider = DnsProvider.AmazonRoute53,
            NsPatterns = new[]
            {
                "ns-*.awsdns-*.com",
                "ns-*.awsdns-*.net",
                "ns-*.awsdns-*.org",
                "ns-*.awsdns-*.co.uk"
            }
        },
        new Rule
        {
            Provider = DnsProvider.AzureDns,
            NsPatterns = new[]
            {
                "ns1-*.azure-dns.com",
                "ns2-*.azure-dns.net",
                "ns3-*.azure-dns.org",
                "ns4-*.azure-dns.info"
            },
            SoaPatterns = new[]
            {
                "*.azure-dns.com",
                "*.azure-dns.net",
                "*.azure-dns.org",
                "*.azure-dns.info"
            }
        },
        new Rule
        {
            Provider = DnsProvider.GoogleCloudDns,
            NsPatterns = new[] { "ns-cloud-*.googledomains.com" }
        },
        new Rule
        {
            Provider = DnsProvider.GoDaddy,
            NsPatterns = new[] { "ns*.domaincontrol.com" }
        },
        new Rule
        {
            Provider = DnsProvider.Namecheap,
            NsPatterns = new[] { "dns*.registrar-servers.com" }
        },
        new Rule
        {
            Provider = DnsProvider.DigitalOcean,
            NsPatterns = new[] { "ns*.digitalocean.com" }
        }
    };

    private static string NormalizeHost(string? value)
    {
        if (value == null)
        {
            return string.Empty;
        }

        var trimmed = value.Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        return trimmed.ToLowerInvariant();
    }

    // Simple wildcard matcher: supports '*' anywhere (multi-part contains).
    private static bool WildcardMatch(string text, string pattern)
    {
        if (string.IsNullOrEmpty(pattern))
        {
            return false;
        }

        if (pattern == "*")
        {
            return true;
        }

        if (!pattern.Contains('*'))
        {
            return text.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        }

        int idx = 0;
        foreach (var part in pattern.Split('*'))
        {
            if (part.Length == 0)
            {
                continue;
            }

            idx = text.IndexOf(part, idx, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                return false;
            }

            idx += part.Length;
        }

        return true;
    }
}
