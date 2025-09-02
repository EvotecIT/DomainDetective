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
}

