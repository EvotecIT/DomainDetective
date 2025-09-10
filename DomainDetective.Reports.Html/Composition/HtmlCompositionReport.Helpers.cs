using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: helpers, models, and enums.
/// </summary>
public static partial class HtmlCompositionReport {
    private static string BuildSubjectTitle(List<string> domains) {
        if (domains.Count == 0) return "Custom Composition";
        if (domains.Count == 1) return domains[0];
        if (domains.Count == 2) return $"{domains[0]}+{domains[1]}";
        return $"{domains[0]}+{domains[1]}(+{domains.Count - 2})";
    }

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
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items) {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string subject) {
            if (!map.ContainsKey(subject)) map[subject] = new DomainBucket { Subject = subject };
        }

        foreach (var it in items) {
            switch (it) {
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject):
                    Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject):
                    Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject):
                    Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject):
                    Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.DnsblInfo dnsbl when !string.IsNullOrWhiteSpace(dnsbl.Subject):
                    Ensure(dnsbl.Subject); map[dnsbl.Subject].Dnsbl = dnsbl; break;
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject):
                    Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject):
                    Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject):
                    Ensure(tr.Subject); map[tr.Subject].TlsRpt = tr; break;
                default:
                    break;
            }
        }
        return map;
    }

    private static List<KeyValuePair<string, DomainBucket>> OrderDomainsByInput(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped) {
        var ordered = new List<KeyValuePair<string, DomainBucket>>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items ?? Array.Empty<object>()) {
            var subject = TryGetSubject(it);
            if (string.IsNullOrWhiteSpace(subject)) continue;
            if (seen.Contains(subject!)) continue;
            if (grouped.TryGetValue(subject!, out var bucket)) {
                ordered.Add(new KeyValuePair<string, DomainBucket>(subject!, bucket));
                seen.Add(subject!);
            }
        }
        foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)) if (!seen.Contains(kv.Key)) ordered.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
        return ordered;
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
}
