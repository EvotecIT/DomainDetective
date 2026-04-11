using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Providers.Email;

/// <summary>Provides mail provider kind detector functionality.</summary>
public static class MailProviderKindDetector
{
    /// <summary>Provides match functionality.</summary>
    public sealed class Match
    {
        /// <summary>Gets or sets the provider value.</summary>
        public MailProviderKind Provider { get; init; }
        /// <summary>Gets or sets the score value.</summary>
        public int Score { get; init; }
        /// <summary>Gets or sets the evidence value.</summary>
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

    /// <summary>Executes the detect from mx hosts operation.</summary>
    public static Match DetectFromMxHosts(IEnumerable<string>? mxHosts)
    {
        var hosts = (mxHosts ?? Array.Empty<string>())
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(NormalizeHost)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (hosts.Count == 0)
        {
            return new Match { Provider = MailProviderKind.Unknown, Score = 0 };
        }

        Match? best = null;
        foreach (var p in ProviderRegistry.All)
        {
            if (!TryMapProviderId(p.Id, out var kind))
            {
                continue;
            }

            int score = 0;
            var evidence = new List<string>();

            foreach (var host in hosts)
            {
                foreach (var rawPattern in p.MxHostPatterns ?? Array.Empty<string>())
                {
                    var pattern = NormalizeHost(rawPattern);
                    if (string.IsNullOrWhiteSpace(pattern))
                    {
                        continue;
                    }

                    if (!WildcardMatch(host, pattern))
                    {
                        continue;
                    }

                    score++;
                    if (evidence.Count < 8)
                    {
                        evidence.Add($"MX {host} matches {pattern}");
                    }
                    break;
                }
            }

            if (score <= 0)
            {
                continue;
            }

            var current = new Match { Provider = kind, Score = score, Evidence = evidence };
            if (best == null || current.Score > best.Score || (current.Score == best.Score && current.Provider < best.Provider))
            {
                best = current;
            }
        }

        return best ?? new Match { Provider = MailProviderKind.Unknown, Score = 0 };
    }

    private static bool TryMapProviderId(string? id, out MailProviderKind kind)
    {
        kind = MailProviderKind.Unknown;
        var key = (id ?? string.Empty).Trim();
        if (key.Length == 0)
        {
            return false;
        }

        switch (key.ToLowerInvariant())
        {
            case "m365":
                kind = MailProviderKind.Microsoft365;
                return true;
            case "googleworkspace":
                kind = MailProviderKind.GoogleWorkspace;
                return true;
            case "mimecast":
                kind = MailProviderKind.Mimecast;
                return true;
            case "barracuda-egd":
                kind = MailProviderKind.BarracudaEmailGatewayDefense;
                return true;
            case "proofpoint-essentials":
                kind = MailProviderKind.ProofpointEssentials;
                return true;
            case "zoho-mail":
                kind = MailProviderKind.ZohoMail;
                return true;
            case "sendgrid":
                kind = MailProviderKind.SendGrid;
                return true;
            case "amazon-ses":
                kind = MailProviderKind.AmazonSes;
                return true;
            case "mailgun":
                kind = MailProviderKind.Mailgun;
                return true;
            case "postmark":
                kind = MailProviderKind.Postmark;
                return true;
            case "fastmail":
                kind = MailProviderKind.Fastmail;
                return true;
            case "protonmail":
                kind = MailProviderKind.ProtonMail;
                return true;
            case "cloudflare-email-routing":
                kind = MailProviderKind.CloudflareEmailRouting;
                return true;
            case "cisco-secure-email":
                kind = MailProviderKind.CiscoSecureEmail;
                return true;
            default:
                return false;
        }
    }

    private static string NormalizeHost(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim().TrimEnd('.');
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
