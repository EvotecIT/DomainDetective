using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

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
    StripeVerification = 64,
    BingWebmasterVerification = 128
}
