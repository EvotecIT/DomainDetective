using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Helpers;

namespace DomainDetective.Providers.Email;

/// <summary>Provides email provider detector functionality.</summary>
public static class EmailProviderDetector
{
    /// <summary>Executes the detect operation.</summary>
    public static ProviderMatch Detect(IEnumerable<string> mxHosts, IEnumerable<string>? spfTokens = null, IEnumerable<string>? dkimTargets = null)
    {
        var hosts = (mxHosts ?? Array.Empty<string>()).Select(h => h.Trim('.')).Where(h => !string.IsNullOrWhiteSpace(h)).ToList();
        var spf = (spfTokens ?? Array.Empty<string>()).ToList();
        var dkim = (dkimTargets ?? Array.Empty<string>()).Select(h => h.Trim('.')).ToList();

        var gateways = new List<(IMailProvider Provider, double Score)>();
        var inbound = new List<(IMailProvider Provider, double Score)>();
        var outbound = new List<(IMailProvider Provider, double Score)>();

        foreach (var p in ProviderRegistry.All)
        {
            double score = 0.0;

            // MX matching (basic wildcard contains).
            bool anyMx = hosts.Any(h => p.MxHostPatterns.Any(pattern => WildcardMatch(h, pattern)));
            if (anyMx) { score += 0.7; }

            // SPF hint tokens.
            if (p.SpfRequiredTokens.Any() && spf.Any())
            {
                bool allPresent = p.SpfRequiredTokens.All(req => spf.Any(t => t != null && t.IndexOf(req, StringComparison.OrdinalIgnoreCase) >= 0));
                if (allPresent) { score += 0.25; }
            }

            // DKIM CNAME suffix matches (outbound senders/gateways often expose this).
            if (p.DkimCnameSuffixes.Any() && dkim.Any())
            {
                bool anyCname = dkim.Any(c => p.DkimCnameSuffixes.Any(sfx => DomainHelper.IsDomainOrSubdomainOf(c, sfx)));
                if (anyCname) { score += 0.25; }
            }

            if (score <= 0) { continue; }

            if (p.Capabilities.HasFlag(ProviderCapability.Gateway))
            {
                gateways.Add((p, score));
            }
            if (p.Capabilities.HasFlag(ProviderCapability.InboundMx))
            {
                inbound.Add((p, score));
            }
            if (p.Capabilities.HasFlag(ProviderCapability.OutboundOnly) && !p.Capabilities.HasFlag(ProviderCapability.InboundMx) && !p.Capabilities.HasFlag(ProviderCapability.Gateway))
            {
                outbound.Add((p, score));
            }
        }

        var primary = inbound.OrderByDescending(x => x.Score).FirstOrDefault();
        var match = new ProviderMatch
        {
            Primary = primary.Provider,
            PrimaryScore = primary.Score
        };

        foreach (var g in gateways.OrderByDescending(g => g.Score))
        {
            if (match.Primary == null || !ReferenceEquals(g.Provider, match.Primary))
            {
                match.Gateways.Add(g.Provider);
            }
        }

        foreach (var o in outbound.OrderByDescending(o => o.Score))
        {
            match.OutboundSenders.Add(o.Provider);
        }

        return match;
    }

    // Simple wildcard matcher: supports '*' anywhere (multi-part contains).
    private static bool WildcardMatch(string text, string pattern)
    {
        if (string.IsNullOrEmpty(pattern)) { return false; }
        if (pattern == "*") { return true; }
        if (!pattern.Contains('*')) { return text.Equals(pattern, StringComparison.OrdinalIgnoreCase); }

        int idx = 0;
        foreach (var part in pattern.Split('*'))
        {
            if (part.Length == 0) { continue; }
            idx = text.IndexOf(part, idx, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) { return false; }
            idx += part.Length;
        }
        return true;
    }
}
