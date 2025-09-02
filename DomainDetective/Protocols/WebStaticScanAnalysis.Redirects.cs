namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public enum RedirectKind
    {
        None = 0,
        SchemeUpgrade,
        SchemeDowngrade,
        ApexToWww,
        WwwToApex,
        HostChangeOther,
        TrailingSlashAdded,
        TrailingSlashRemoved,
        IndexToSlash,
        QueryChangeOnly,
        PathChangeOther
    }

    private static RedirectKind ClassifyRedirect(System.Uri from, System.Uri to)
    {
        try
        {
            if (!System.StringComparer.OrdinalIgnoreCase.Equals(from.Scheme, to.Scheme))
            {
                if (from.Scheme == "http" && to.Scheme == "https") return RedirectKind.SchemeUpgrade;
                if (from.Scheme == "https" && to.Scheme == "http") return RedirectKind.SchemeDowngrade;
            }
            if (!System.StringComparer.OrdinalIgnoreCase.Equals(from.Host, to.Host))
            {
                var f = from.Host; var t = to.Host;
                if (t == "www." + f) return RedirectKind.ApexToWww;
                if (f == "www." + t) return RedirectKind.WwwToApex;
                return RedirectKind.HostChangeOther;
            }
            var fpath = from.AbsolutePath; var tpath = to.AbsolutePath;
            if (!System.StringComparer.Ordinal.Equals(fpath, tpath))
            {
                if (!fpath.EndsWith("/") && tpath == fpath + "/") return RedirectKind.TrailingSlashAdded;
                if (!tpath.EndsWith("/") && fpath == tpath + "/") return RedirectKind.TrailingSlashRemoved;
                if ((fpath.EndsWith("/index.html") || fpath.EndsWith("/index.htm")) && (tpath == fpath.Substring(0, fpath.LastIndexOf('/') + 1) || tpath.EndsWith("/")))
                    return RedirectKind.IndexToSlash;
                return RedirectKind.PathChangeOther;
            }
            var fquery = from.Query; var tquery = to.Query;
            if (!System.StringComparer.Ordinal.Equals(fquery, tquery)) return RedirectKind.QueryChangeOnly;
        }
        catch { }
        return RedirectKind.None;
    }

    private void RecordRedirect(string sourceHost, StaticRequest req)
    {
        if (req == null || !req.WasRedirected) return;
        try
        {
            lock (_sync)
            {
                if (!Hosts.TryGetValue(sourceHost, out var hh) || hh == null)
                {
                    hh = new StaticHost { Host = sourceHost, RegistrableDomain = GetRegistrableDomain?.Invoke(sourceHost) };
                    Hosts[sourceHost] = hh;
                }
                hh.RedirectTotal++;
                switch (req.RedirectKind)
                {
                    case RedirectKind.SchemeUpgrade: hh.RedirectSchemeUpgrade++; break;
                    case RedirectKind.SchemeDowngrade: hh.RedirectSchemeDowngrade++; break;
                    case RedirectKind.ApexToWww: hh.RedirectApexToWww++; break;
                    case RedirectKind.WwwToApex: hh.RedirectWwwToApex++; break;
                    case RedirectKind.HostChangeOther: hh.RedirectHostChangeOther++; break;
                    case RedirectKind.TrailingSlashAdded: hh.RedirectTrailingSlashAdded++; break;
                    case RedirectKind.TrailingSlashRemoved: hh.RedirectTrailingSlashRemoved++; break;
                    case RedirectKind.IndexToSlash: hh.RedirectIndexToSlash++; break;
                    case RedirectKind.QueryChangeOnly: hh.RedirectQueryChangeOnly++; break;
                    case RedirectKind.PathChangeOther: hh.RedirectPathChangeOther++; break;
                }
                if (req.SourceKind == ResourceSourceKind.Link)
                {
                    hh.LinkRedirectSamples++;
                    hh.LinkRedirectHopSum += req.RedirectHopCount > 0 ? req.RedirectHopCount : (req.WasRedirected ? 1 : 0);
                }
                // Redirect pair matrix
                var toHost = req.RedirectToHost ?? string.Empty;
                var key = sourceHost + "->" + toHost;
                if (!RedirectPairs.TryGetValue(key, out var stat))
                {
                    stat = new RedirectPairStat { FromHost = sourceHost, ToHost = toHost };
                    RedirectPairs[key] = stat;
                }
                stat.Count++;
                if (req.RedirectKind == RedirectKind.SchemeUpgrade) stat.SchemeUpgradeCount++;
                else if (req.RedirectKind == RedirectKind.SchemeDowngrade) stat.SchemeDowngradeCount++;
            }
        }
        catch { }
    }

    private void AddAdjacency(int? parentId, int childId)
    {
        try
        {
            if (!parentId.HasValue) return;
            lock (_sync)
            {
                if (!RequestAdjacency.TryGetValue(parentId.Value, out var list))
                {
                    list = new System.Collections.Generic.List<int>();
                    RequestAdjacency[parentId.Value] = list;
                }
                list.Add(childId);
            }
        }
        catch { }
    }
}
