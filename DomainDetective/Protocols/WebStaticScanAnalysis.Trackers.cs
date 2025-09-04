using System;

namespace DomainDetective;

/// <summary>
/// Tracker detection helpers split out from the core analysis for clarity.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private static readonly string[] _trackerDomains = new[]
    {
        "google-analytics.com","googletagmanager.com","doubleclick.net","facebook.net","facebook.com",
        "hotjar.com","segment.io","mixpanel.com","matomo.org","clarity.ms","optimizely.com","snowplowanalytics.com",
        "newrelic.com","googlesyndication.com"
    };

    private bool IsTracker(string hostOrDomain)
    {
        try
        {
            var dom = GetRegistrableDomain?.Invoke(hostOrDomain) ?? hostOrDomain;
            foreach (var t in _trackerDomains)
            {
                if (dom.EndsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        catch { }
        return false;
    }

    private static string? MapTrackerName(string registrableDomain)
    {
        if (registrableDomain.EndsWith("googletagmanager.com", StringComparison.OrdinalIgnoreCase)) return "Google Tag Manager";
        if (registrableDomain.EndsWith("google-analytics.com", StringComparison.OrdinalIgnoreCase)) return "Google Analytics";
        if (registrableDomain.EndsWith("doubleclick.net", StringComparison.OrdinalIgnoreCase)) return "Google Ads/DoubleClick";
        if (registrableDomain.EndsWith("googlesyndication.com", StringComparison.OrdinalIgnoreCase)) return "Google Ads";
        if (registrableDomain.EndsWith("facebook.com", StringComparison.OrdinalIgnoreCase) || registrableDomain.EndsWith("facebook.net", StringComparison.OrdinalIgnoreCase)) return "Facebook Widgets";
        if (registrableDomain.EndsWith("clarity.ms", StringComparison.OrdinalIgnoreCase)) return "Microsoft Clarity";
        if (registrableDomain.EndsWith("hotjar.com", StringComparison.OrdinalIgnoreCase)) return "Hotjar";
        if (registrableDomain.EndsWith("segment.io", StringComparison.OrdinalIgnoreCase)) return "Segment";
        if (registrableDomain.EndsWith("mixpanel.com", StringComparison.OrdinalIgnoreCase)) return "Mixpanel";
        if (registrableDomain.EndsWith("matomo.org", StringComparison.OrdinalIgnoreCase)) return "Matomo";
        if (registrableDomain.EndsWith("optimizely.com", StringComparison.OrdinalIgnoreCase)) return "Optimizely";
        if (registrableDomain.EndsWith("snowplowanalytics.com", StringComparison.OrdinalIgnoreCase)) return "Snowplow";
        if (registrableDomain.EndsWith("newrelic.com", StringComparison.OrdinalIgnoreCase)) return "New Relic Browser";
        return null;
    }

    private void BuildTrackerDetails()
    {
        TrackerDetails.Clear();
        foreach (var kv in Hosts)
        {
            var host = kv.Key;
            var h = kv.Value;
            var dom = h.RegistrableDomain ?? host;
            if (!IsTracker(dom)) continue;
            try
            {
                var reqs = Requests.FindAll(r => string.Equals(r.Host, host, StringComparison.OrdinalIgnoreCase));
                var contentTypes = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
                var samples = new System.Collections.Generic.List<string>();
                string evidenceKind = "DomainSuffix";
                string evidence = dom;
                foreach (var r in reqs)
                {
                    if (!string.IsNullOrWhiteSpace(r.ContentType)) contentTypes.Add(r.ContentType!);
                    if (samples.Count < 5) samples.Add(r.FinalUrl ?? r.Url);
                    // If we see clear path tokens, switch evidence kind
                    try {
                        var p = new System.Uri(r.FinalUrl ?? r.Url).AbsolutePath.ToLowerInvariant();
                        if (p.Contains("/gtm.js") || p.Contains("/gtag/") || p.Contains("/analytics") || p.Contains("/collect")) { evidenceKind = "Path"; evidence = p; }
                    } catch { }
                }
                TrackerDetails.Add(new TrackerDetection
                {
                    Host = host,
                    RegistrableDomain = dom,
                    FirstParty = h.FirstParty,
                    RequestCount = reqs.Count,
                    Bytes = h.Bytes,
                    SampleUrls = samples.ToArray(),
                    ContentTypes = System.Linq.Enumerable.ToArray(contentTypes),
                    EvidenceKind = evidenceKind,
                    Evidence = evidence,
                    TrackerName = MapTrackerName(dom)
                });
                TrackersUsed.Add(dom);
            }
            catch { }
        }
    }
}
