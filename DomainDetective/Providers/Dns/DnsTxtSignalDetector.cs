using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Providers.Dns;

public static class DnsTxtSignalDetector
{
    public sealed class Match
    {
        public DnsTxtSignals Signals { get; init; }
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

    public static Match Detect(IEnumerable<string>? txtValues)
    {
        var values = (txtValues ?? Array.Empty<string>())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (values.Count == 0)
        {
            return new Match { Signals = DnsTxtSignals.None };
        }

        var evidence = new List<string>();
        DnsTxtSignals signals = DnsTxtSignals.None;

        foreach (var raw in values)
        {
            var v = NormalizeTxt(raw);
            if (v.Length == 0)
            {
                continue;
            }

            void Add(DnsTxtSignals s, string why)
            {
                if (signals.HasFlag(s))
                {
                    return;
                }

                signals |= s;
                if (evidence.Count < 10)
                {
                    evidence.Add(why);
                }
            }

            if (v.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase))
            {
                Add(DnsTxtSignals.Spf, "TXT: SPF record present (v=spf1)");
            }
            if (v.IndexOf("google-site-verification=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(DnsTxtSignals.GoogleSiteVerification, "TXT: Google site verification token present");
            }
            if (v.StartsWith("ms=", StringComparison.OrdinalIgnoreCase))
            {
                Add(DnsTxtSignals.MicrosoftDomainVerification, "TXT: Microsoft domain verification token present (MS=)");
            }
            if (v.IndexOf("facebook-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(DnsTxtSignals.FacebookDomainVerification, "TXT: Facebook domain verification token present");
            }
            if (v.IndexOf("apple-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(DnsTxtSignals.AppleDomainVerification, "TXT: Apple domain verification token present");
            }
            if (v.IndexOf("atlassian-domain-verification=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(DnsTxtSignals.AtlassianDomainVerification, "TXT: Atlassian domain verification token present");
            }
            if (v.IndexOf("stripe-verification=", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(DnsTxtSignals.StripeVerification, "TXT: Stripe domain verification token present");
            }
        }

        return new Match { Signals = signals, Evidence = evidence };
    }

    private static string NormalizeTxt(string value)
    {
        var v = (value ?? string.Empty).Trim();
        if (v.Length == 0)
        {
            return string.Empty;
        }

        // Handle single quoted-string TXT values.
        if (v.Length >= 2 && v[0] == '"' && v[v.Length - 1] == '"')
        {
            v = v.Substring(1, v.Length - 2);
        }

        return v.Trim();
    }
}

[Flags]
public enum DnsTxtSignals
{
    None = 0,
    Spf = 1,
    GoogleSiteVerification = 2,
    MicrosoftDomainVerification = 4,
    FacebookDomainVerification = 8,
    AppleDomainVerification = 16,
    AtlassianDomainVerification = 32,
    StripeVerification = 64
}

