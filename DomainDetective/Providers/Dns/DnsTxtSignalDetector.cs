using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Providers.Dns;

/// <summary>Provides dns txt signal detector functionality.</summary>
public static class DnsTxtSignalDetector
{
    /// <summary>Provides match functionality.</summary>
    public sealed class Match
    {
        /// <summary>Gets or sets the signals value.</summary>
        public DnsTxtSignals Signals { get; init; }
        /// <summary>Gets or sets the evidence value.</summary>
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

    /// <summary>Executes the detect operation.</summary>
    public static Match Detect(IEnumerable<string>? txtValues)
    {
        var values = (txtValues ?? Array.Empty<string>())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(DnsTxtDetectionCatalog.NormalizeTxt)
            .Where(static value => value.Length > 0)
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

            if (raw.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase))
            {
                Add(DnsTxtSignals.Spf, "TXT: SPF record present (v=spf1)");
            }

            var matches = DnsTxtDetectionCatalog.FindMatches(raw);
            for (var i = 0; i < matches.Count; i++) {
                var definition = matches[i].Definition;
                if (definition.Signals == DnsTxtSignals.None || string.IsNullOrWhiteSpace(definition.SignalEvidence)) {
                    continue;
                }

                Add(definition.Signals, definition.SignalEvidence!);
            }
        }

        return new Match { Signals = signals, Evidence = evidence };
    }
}

/// <summary>Defines values for dns txt signals.</summary>
[Flags]
public enum DnsTxtSignals
{
    /// <summary>Represents the none value.</summary>
    None = 0,
    /// <summary>Represents the spf value.</summary>
    Spf = 1,
    /// <summary>Represents the google site verification value.</summary>
    GoogleSiteVerification = 2,
    /// <summary>Represents the microsoft domain verification value.</summary>
    MicrosoftDomainVerification = 4,
    /// <summary>Represents the facebook domain verification value.</summary>
    FacebookDomainVerification = 8,
    /// <summary>Represents the apple domain verification value.</summary>
    AppleDomainVerification = 16,
    /// <summary>Represents the atlassian domain verification value.</summary>
    AtlassianDomainVerification = 32,
    /// <summary>Represents the stripe verification value.</summary>
    StripeVerification = 64,
    /// <summary>Represents the bing webmaster verification value.</summary>
    BingWebmasterVerification = 128
}
