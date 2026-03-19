using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Catalog of simple technology verifications derived from DNS TXT and similar signals.
/// Centralizes string matching so analyzers remain small and testable.
/// </summary>
internal static class WebTechVerificationCatalog
{
    /// <summary>
    /// Applies DNS TXT-based verifications (e.g., google-site-verification) to the detection sets.
    /// </summary>
    public static void ApplyDnsTxt(string txt, ISet<string> outTech, IList<TechDetectionDetail> details)
    {
        if (string.IsNullOrWhiteSpace(txt)) return;
        void add(string tech, string evidence)
        {
            outTech.Add(tech);
            details.Add(new TechDetectionDetail
            {
                Name = tech,
                SourceKind = TechEvidenceKind.Dns,
                Category = TechSignatureCatalog.GetCategory(tech),
                Evidence = evidence.Length > 200 ? evidence.Substring(0, 200) + "..." : evidence,
                Confidence = 100
            });
        }

        var matches = DnsTxtDetectionCatalog.FindMatches(txt);
        for (var i = 0; i < matches.Count; i++) {
            var tech = matches[i].Definition.TechName;
            if (string.IsNullOrWhiteSpace(tech)) {
                continue;
            }

            add(tech!, matches[i].NormalizedValue);
        }
    }
}

