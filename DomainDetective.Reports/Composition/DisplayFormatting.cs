using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Shared small formatting helpers to surface Word-level extras in all renderers.
/// </summary>
public static class DisplayFormatting
{
    public static string ComposeDkimSummary(IReadOnlyList<DomainDetective.Views.DkimRecordInfo>? dkim, bool includeSelectorCount)
    {
        if (dkim == null || dkim.Count == 0) return "-";
        int err = dkim.Sum(x => x?.ErrorCount ?? 0);
        int warn = dkim.Sum(x => x?.WarningCount ?? 0);
        string core = err > 0 ? "Error" : (warn > 0 ? "Warning" : "OK");
        if (includeSelectorCount)
        {
            int n = dkim.Count;
            core += $" ({n} selector{(n == 1 ? string.Empty : "s")})";
        }
        return core;
    }

    public static string ComposeMailTlsSummary(DomainDetective.Views.MailTlsInfo? smtp, DomainDetective.Views.MailTlsInfo? imap, DomainDetective.Views.MailTlsInfo? pop, bool includeProtocol)
    {
        if (smtp != null)
        {
            var s = smtp.Status ?? "-";
            return includeProtocol && s != "-" ? $"{s} (SMTP)" : s;
        }
        if (imap != null)
        {
            var s = imap.Status ?? "-";
            return includeProtocol && s != "-" ? $"{s} (IMAP)" : s;
        }
        if (pop != null)
        {
            var s = pop.Status ?? "-";
            return includeProtocol && s != "-" ? $"{s} (POP)" : s;
        }
        return "-";
    }

    public static string ComposeDnssecSummary(DomainDetective.Views.DnssecStatusInfo? ds)
    {
        if (ds == null) return "-";
        var parts = new List<string>();
        parts.Add(ds.ChainValid ? "chain=valid" : "chain=invalid");
        parts.Add(ds.DsMatch ? "ds=match" : "ds=check");
        if (ds.RootAnchorExpiration.HasValue)
        {
            var days = (int)Math.Ceiling((ds.RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays);
            parts.Add(days > 0 ? $"root={days}d" : "root=expired");
        }
        return string.Join("; ", parts);
    }

    public static string ComposeRpkiSummary(DomainDetective.Views.RpkiInfo? r)
    {
        if (r == null) return "-";
        if (r.TotalChecked <= 0) return "-";
        var core = (r.ValidCount == r.TotalChecked) ? "All valid" : (r.ValidCount > 0 ? "Partial" : "None valid");
        return $"{core} ({r.ValidCount}/{r.TotalChecked})";
    }
}
