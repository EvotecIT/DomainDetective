using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using DocumentFormat.OpenXml.Wordprocessing;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Aggregates mixed view objects (SPF/DKIM/DMARC) for one or more domains into a single Word document.
/// </summary>
/// <summary>
/// Builds a single Word document from mixed per-section view objects across one or many domains.
/// </summary>
public static partial class WordCompositionReport {
    private static Dictionary<string, Dictionary<HealthCheckType, (string Status, int Warn, int Err)>> AggregateExtras(IReadOnlyList<object> items, HashSet<HealthCheckType> covered) {
        var map = new Dictionary<string, Dictionary<HealthCheckType, (string, int, int)>>(StringComparer.OrdinalIgnoreCase);
        void Acc(string subject, HealthCheckType check, string status, int warn, int err) {
            if (!map.TryGetValue(subject ?? string.Empty, out var byCheck)) {
                byCheck = new Dictionary<HealthCheckType, (string, int, int)>();
                map[subject ?? string.Empty] = byCheck;
            }
            if (byCheck.TryGetValue(check, out var cur)) {
                var nextStatus = MaxStatus(cur.Item1, status);
                byCheck[check] = (nextStatus, cur.Item2 + warn, cur.Item3 + err);
            } else {
                byCheck[check] = (status, warn, err);
            }
        }

        foreach (var raw in items ?? Array.Empty<object>()) {
            foreach (var it in EnumeratePossiblyNested(raw)) {
                var t = it.GetType();
                var checkProp = t.GetProperty("Check");
                var subjProp = t.GetProperty("Subject");
                var statusProp = t.GetProperty("Status");
                var warnProp = t.GetProperty("WarningCount");
                var errProp = t.GetProperty("ErrorCount");
                if (checkProp == null || subjProp == null || statusProp == null || warnProp == null || errProp == null) continue;
                if (checkProp.GetValue(it) is not HealthCheckType check) continue;
                if (covered.Contains(check)) continue;
                var subject = subjProp.GetValue(it) as string ?? string.Empty;
                var status = statusProp.GetValue(it) as string ?? "";
                var warn = warnProp.GetValue(it) as int? ?? 0;
                var err = errProp.GetValue(it) as int? ?? 0;
                Acc(subject, check, status, warn, err);
            }
        }
        return map;
    }

    private static IEnumerable<object> EnumeratePossiblyNested(object o) {
        if (o is System.Collections.IEnumerable seq && o is not string) {
            foreach (var e in seq) if (e != null) yield return e;
        } else {
            yield return o;
        }
    }

    private static List<string> DetermineDomainOrder(IReadOnlyList<object> items) {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in items ?? Array.Empty<object>()) {
            foreach (var it in EnumeratePossiblyNested(raw)) {
                var subj = TryGetSubject(it);
                if (!string.IsNullOrWhiteSpace(subj) && seen.Add(subj!)) list.Add(subj!);
            }
        }
        return list;
    }

    private static Dictionary<string, List<string>> DetermineSectionOrderByDomain(IReadOnlyList<object> items) {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in items ?? Array.Empty<object>()) {
            foreach (var it in EnumeratePossiblyNested(raw)) {
                string? subject = TryGetSubject(it);
                if (string.IsNullOrWhiteSpace(subject)) continue;
                string? key = TryGetSectionKey(it);
                if (string.IsNullOrWhiteSpace(key)) continue;
                if (!map.TryGetValue(subject!, out var list)) { list = new List<string>(); map[subject!] = list; }
                if (!list.Contains(key!, StringComparer.OrdinalIgnoreCase)) list.Add(key!);
            }
        }
        return map;
    }

    private static string? TryGetSubject(object it) {
        try { var p = it.GetType().GetProperty("Subject"); return p?.GetValue(it) as string; } catch { return null; }
    }

    private static string? TryGetSectionKey(object it) {
        try {
            var keyProp = it.GetType().GetProperty("SectionKey");
            if (keyProp != null && keyProp.GetValue(it) is string sectionKey && !string.IsNullOrWhiteSpace(sectionKey)) {
                return NormalizeSection(sectionKey);
            }
            var p = it.GetType().GetProperty("Check");
            if (p == null) return null;
            if (p.GetValue(it) is not HealthCheckType h) return null;     
            return SectionKeyFor(h);
        } catch { return null; }
    }

    private static string? SectionKeyFor(HealthCheckType h) => SectionOrdering.SectionKeyFor(h);

    private static string[] CanonicalSections => SectionOrdering.CanonicalSections.ToArray();

    private static string NormalizeSection(string s) {
        return SectionOrdering.NormalizeSection(s);
    }

    private static string[] NormalizeSectionList(IEnumerable<string> list) {
        return SectionOrdering.NormalizeSectionList(list);
    }

    private static string MaxStatus(string a, string b) {
        int Rank(string s) => string.Equals(s, "Error", StringComparison.OrdinalIgnoreCase) ? 3
            : string.Equals(s, "Warning", StringComparison.OrdinalIgnoreCase) ? 2
            : string.Equals(s, "OK", StringComparison.OrdinalIgnoreCase) ? 1
            : 0;
        return Rank(a) >= Rank(b) ? a : b;
    }

    private static string BuildSubjectTitle(List<string> domains) {
        if (domains == null || domains.Count == 0) return "Custom Composition";
        if (domains.Count == 1) return domains[0];
        if (domains.Count == 2) return $"{domains[0]}+{domains[1]}";
        return $"{domains[0]}+{domains[1]}(+{domains.Count - 2})";
    }

    /// <summary>Internal grouping container for per-domain section data.</summary>
    private sealed class DomainBucket {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }       
        public DomainDetective.Views.DmarcAggregateTimeSeriesInfo? DmarcAggregate { get; set; }
        public DomainDetective.Views.RegistrationDriftInfo? Registration { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.TtlInfo? Ttl { get; set; }
        public DomainDetective.Views.ArcInfo? Arc { get; set; }
        public DomainDetective.Views.BimiRecordInfo? Bimi { get; set; }
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.DesiredStateInfo? DesiredState { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }     
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }     
        public DomainDetective.Views.TlsRptReportsTimeSeriesInfo? TlsRptReports { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; } 
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }   
        public DomainDetective.Views.CtTimelineInfo? CtTimeline { get; set; }
        public DomainDetective.Views.SubdomainsInfo? Subdomains { get; set; }
        public DomainDetective.Views.DnsInventoryInfo? DnsInventory { get; set; }
        public DomainDetective.Views.DnsTraceInfo? DnsTrace { get; set; }
        public DomainDetective.Views.HttpInfo? Http { get; set; }
        public DomainDetective.Views.IpEnrichmentInfo? IpEnrichment { get; set; }
        public DomainDetective.Views.Microsoft365TenantInfo? Microsoft365 { get; set; }
        public DomainDetective.Views.TyposquattingInfo? Typosquatting { get; set; }
        public DomainDetective.Views.DnsAmplificationSummary? DnsAmplification { get; set; }
        public DomainDetective.Views.DnsOverTlsSummary? DnsOverTls { get; set; }
        public List<DomainDetective.Views.DnsPropagationInfo> DnsPropagation { get; } = new();
        // Mail TLS (per protocol) for rollup column
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
    }

    private static string ComposeDkimStatus(List<DomainDetective.Views.DkimRecordInfo> dkim, bool showCount) {
        return DisplayFormatting.ComposeDkimSummary(dkim, showCount);
    }

    private static string ComposeMailTlsStatus(DomainBucket b, bool showProto) {
        // Prefer SMTP, else IMAP, else POP. If none present, "-".
        if (b.SmtpTls != null) {
            var s = b.SmtpTls.Status ?? "-";
            return showProto && s != "-" ? $"{s} (SMTP)" : s;
        }
        if (b.ImapTls != null) {
            var s = b.ImapTls.Status ?? "-";
            return showProto && s != "-" ? $"{s} (IMAP)" : s;
        }
        if (b.PopTls != null) {
            var s = b.PopTls.Status ?? "-";
            return showProto && s != "-" ? $"{s} (POP)" : s;
        }
        return "-";
    }

    private static string ComposeDnssecStatus(DomainBucket b) {
        var ds = b.Dnssec;
        if (ds == null) return "-";
        var parts = new List<string>();
        parts.Add(ds.ChainValid ? "chain=valid" : "chain=invalid");
        parts.Add(ds.DsMatch ? "ds=match" : "ds=check");
        if (ds.RootAnchorExpiration.HasValue) {
            var days = (int)Math.Ceiling((ds.RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays);
            parts.Add(days > 0 ? $"root={days}d" : "root=expired");
        }
        return string.Join("; ", parts);
    }

    private static string ComposeRpkiStatus(DomainBucket b) {
        var r = b.Rpki;
        if (r == null) return "-";
        if (r.TotalChecked <= 0) return "-";
        var core = (r.ValidCount == r.TotalChecked) ? "All valid" : (r.ValidCount > 0 ? "Partial" : "None valid");
        return $"{core} ({r.ValidCount}/{r.TotalChecked})";
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items) {
        var comp = CompositionBuilder.GroupBySubject(items);
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in comp) {
            map[kv.Key] = Map(kv.Value);
        }
        return map;
    }

    private static DomainBucket Map(CompositionBuilder.DomainBucket s) {
        var b = new DomainBucket {
            Subject = s.Subject,
            Mx = s.Mx,
            Spf = s.Spf,
            Dmarc = s.Dmarc,
            DmarcAggregate = s.DmarcAggregate,
            Registration = s.Registration,
            Ttl = s.Ttl,
            Arc = s.Arc,
            Bimi = s.Bimi,
            Dnsbl = s.Dnsbl,
            Caa = s.Caa,
            Rpki = s.Rpki,
            Ns = s.Ns,
            Soa = s.Soa,
            ZoneTransfer = s.ZoneTransfer,
            Wildcard = s.Wildcard,
            Classification = s.Classification,
            DesiredState = s.DesiredState,
            Mtasts = s.Mtasts,
            TlsRpt = s.TlsRpt,
            TlsRptReports = s.TlsRptReports,
            Dnssec = s.Dnssec,
            Dane = s.Dane,
            CtTimeline = s.CtTimeline,
            Subdomains = s.Subdomains,
            DnsInventory = s.DnsInventory,
            DnsTrace = s.DnsTrace,
            Http = s.Http,
            IpEnrichment = s.IpEnrichment,
            Microsoft365 = s.Microsoft365,
            Typosquatting = s.Typosquatting,
            DnsAmplification = s.DnsAmplification,
            DnsOverTls = s.DnsOverTls,
            SmtpTls = s.SmtpTls,
            ImapTls = s.ImapTls,
            PopTls = s.PopTls
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        if (s.DnsPropagation != null && s.DnsPropagation.Count > 0) b.DnsPropagation.AddRange(s.DnsPropagation);
        return b;
    }
}
