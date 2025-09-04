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
        void add(string tech)
        {
            outTech.Add(tech);
            details.Add(new TechDetectionDetail
            {
                Name = tech,
                SourceKind = TechEvidenceKind.Dns,
                Category = TechSignatureCatalog.GetCategory(tech),
                Evidence = txt.Length > 200 ? txt.Substring(0, 200) + "..." : txt,
                Confidence = 100
            });
        }
        var t = txt;
        if (t.IndexOf("status-page-domain-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Atlassian Statuspage");
        if (t.IndexOf("google-site-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Google Site Verification");
        if (t.IndexOf("facebook-domain-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Facebook Domain Verification");
        if (t.IndexOf("apple-domain-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Apple Domain Verification");
        if (t.IndexOf("msvalidate.01=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Bing Site Verification");
        if (t.IndexOf("yandex-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Yandex Site Verification");
        if (t.IndexOf("pinterest-site-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Pinterest Site Verification");
        if (t.IndexOf("ahrefs-site-verification=", System.StringComparison.OrdinalIgnoreCase) >= 0) add("Ahrefs Site Verification");
    }
}

