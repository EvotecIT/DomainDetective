using System;
using DomainDetective.Helpers;

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
                    if (DomainHelper.IsDomainOrSubdomainOf(dom, t)) return true;
                }
            }
            catch { }
        return false;
    }

    private static string? MapTrackerName(string registrableDomain)       
    {
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "googletagmanager.com")) return "Google Tag Manager";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "google-analytics.com")) return "Google Analytics";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "doubleclick.net")) return "Google Ads/DoubleClick";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "googlesyndication.com")) return "Google Ads";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "facebook.com") || DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "facebook.net")) return "Facebook Widgets";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "clarity.ms")) return "Microsoft Clarity";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "hotjar.com")) return "Hotjar";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "segment.io")) return "Segment";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "mixpanel.com")) return "Mixpanel";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "matomo.org")) return "Matomo";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "optimizely.com")) return "Optimizely";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "snowplowanalytics.com")) return "Snowplow";
        if (DomainHelper.IsDomainOrSubdomainOf(registrableDomain, "newrelic.com")) return "New Relic Browser";
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
