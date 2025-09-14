using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: helpers, models, and enums.
/// </summary>
public static partial class HtmlCompositionReport {
    private static string BuildSubjectTitle(List<string> domains)
        => CompositionBuilder.BuildSubjectTitle(domains);

    private static (int warn, int err) CountFindings(DomainBucket b) {
        int warn = (b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount);
        int err  = (b.Mx?.ErrorCount ?? 0)   + (b.Spf?.ErrorCount ?? 0)   + (b.Dmarc?.ErrorCount ?? 0)   + (b.Mtasts?.ErrorCount ?? 0)   + (b.TlsRpt?.ErrorCount ?? 0)   + b.Dkim.Sum(x => x.ErrorCount);
        return (warn, err);
    }

    private sealed class DomainBucket {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; }
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var comp = CompositionBuilder.GroupBySubject(items);
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in comp)
        {
            map[kv.Key] = Map(kv.Value);
        }
        return map;
    }

    private static List<KeyValuePair<string, DomainBucket>> OrderDomainsByInput(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped) {
        var comp = CompositionBuilder.GroupBySubject(items);
        var orderedComp = CompositionBuilder.OrderDomains(items, comp, DomainOrder.Input);
        var list = new List<KeyValuePair<string, DomainBucket>>();
        foreach (var kv in orderedComp)
        {
            if (grouped.TryGetValue(kv.Key, out var b)) list.Add(new KeyValuePair<string, DomainBucket>(kv.Key, b));
        }
        foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            if (!list.Any(x => string.Equals(x.Key, kv.Key, StringComparison.OrdinalIgnoreCase))) list.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
        return list;
    }

    private static string? TryGetSubject(object item) {
        try { var p = item.GetType().GetProperty("Subject"); return p?.GetValue(item) as string; } catch { return null; }
    }

    private static Dictionary<string, List<string>> DetermineSectionOrderByDomain(IReadOnlyList<object> items) {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items ?? Array.Empty<object>()) {
            var subject = TryGetSubject(it);
            if (string.IsNullOrWhiteSpace(subject)) continue;
            var key = TryGetSectionKey(it);
            if (string.IsNullOrWhiteSpace(key)) continue;
            if (!map.TryGetValue(subject!, out var list)) { list = new List<string>(); map[subject!] = list; }
            if (!list.Contains(key!, StringComparer.OrdinalIgnoreCase)) list.Add(key!);
        }
        return map;
    }

    private static string? TryGetSectionKey(object it) {
        try {
            var p = it.GetType().GetProperty("Check");
            if (p == null) return null;
            if (p.GetValue(it) is not DomainDetective.HealthCheckType h) return null;
            return SectionKeyFor(h);
        } catch { return null; }
    }

    private static string SectionKeyFor(DomainDetective.HealthCheckType h) => h switch {
        DomainDetective.HealthCheckType.MX => "MX",
        DomainDetective.HealthCheckType.SPF => "SPF",
        DomainDetective.HealthCheckType.DKIM => "DKIM",
        DomainDetective.HealthCheckType.DMARC => "DMARC",
        DomainDetective.HealthCheckType.DNSBL => "DNSBL",
        DomainDetective.HealthCheckType.MAILCLASSIFICATION => "Classification",
        DomainDetective.HealthCheckType.MTASTS => "MTA-STS",
        DomainDetective.HealthCheckType.TLSRPT => "TLS-RPT",
        _ => null
    };

    private static string[] CanonicalSections => new[] { "MX","SPF","DKIM","DMARC","DNSBL","Classification","MTA-STS","TLS-RPT" };

    private static string[] NormalizeSectionList(IEnumerable<string> list) {
        return list?.Select(s => NormalizeSection(s)).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? Array.Empty<string>();
    }
    private static string NormalizeSection(string s) {
        if (string.IsNullOrWhiteSpace(s)) return s;
        var t = s.Trim();
        var u = t.ToUpperInvariant().Replace(" ", "");
        return u switch {
            "TLSRPT" => "TLS-RPT",
            "MTASTS" => "MTA-STS",
            _ => (u == "MX" || u == "SPF" || u == "DKIM" || u == "DMARC" || u == "DNSBL" || u == "CLASSIFICATION" || u == "MTA-STS" || u == "TLS-RPT") ? (u == "CLASSIFICATION" ? "Classification" : (u == "MTA-STS" ? "MTA-STS" : u)) : t
        };
    }

    // Helper: choose a badge color for a status string
    private static TablerBadgeColor ColorForStatus(string? status) {
        var s = (status ?? "-").Trim().ToLowerInvariant();
        if (s.Contains("error") || s.Contains("fail")) return TablerBadgeColor.Danger;
        if (s.Contains("warn")) return TablerBadgeColor.Warning;
        if (s.Contains("ok") || s.Contains("pass") || s.Contains("valid")) return TablerBadgeColor.Success;
        if (s == "-" || s.Contains("none") || s.Contains("missing")) return TablerBadgeColor.Info;
        return TablerBadgeColor.Blue;
    }

    // Adapter: map shared CompositionBuilder.DomainBucket to the local DomainBucket used by HTML renderer
    private static DomainBucket Map(CompositionBuilder.DomainBucket s)
    {
        var b = new DomainBucket
        {
            Subject = s.Subject,
            Mx = s.Mx,
            Spf = s.Spf,
            Dmarc = s.Dmarc,
            Dnsbl = s.Dnsbl,
            Classification = s.Classification,
            Mtasts = s.Mtasts,
            TlsRpt = s.TlsRpt,
            Ns = s.Ns,
            Soa = s.Soa,
            Caa = s.Caa,
            Dnssec = s.Dnssec,
            Dane = s.Dane,
            SmtpTls = s.SmtpTls,
            ImapTls = s.ImapTls,
            PopTls = s.PopTls,
            Rpki = s.Rpki,
            ZoneTransfer = s.ZoneTransfer,
            Wildcard = s.Wildcard
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        return b;
    }
}
