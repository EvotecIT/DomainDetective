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
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string subject) {
            if (!map.ContainsKey(subject)) map[subject] = new DomainBucket { Subject = subject };
        }

        // Flatten one level so arrays/lists piped in are handled correctly
        foreach (var raw in items ?? Array.Empty<object>()) {
            foreach (var it in EnumeratePossiblyNested(raw)) {
                switch (it) {
                    case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject):
                        Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                    case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject):
                        Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                    case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject):
                        Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                    case DomainDetective.Views.DmarcAggregateTimeSeriesInfo da when !string.IsNullOrWhiteSpace(da.Subject):
                        Ensure(da.Subject); map[da.Subject].DmarcAggregate = da; break;
                    case DomainDetective.Views.RegistrationDriftInfo reg when !string.IsNullOrWhiteSpace(reg.Subject):
                        Ensure(reg.Subject); map[reg.Subject].Registration = reg; break;
                    case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject):
                        Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                    case DomainDetective.Views.ArcInfo arc when !string.IsNullOrWhiteSpace(arc.Subject):
                        Ensure(arc.Subject); map[arc.Subject].Arc = arc; break;
                    case DomainDetective.Views.BimiRecordInfo bimi when !string.IsNullOrWhiteSpace(bimi.Subject):
                        Ensure(bimi.Subject); map[bimi.Subject].Bimi = bimi; break;
                    case DomainDetective.Views.DnsblInfo dnsbl when !string.IsNullOrWhiteSpace(dnsbl.Subject):
                    {
                        var subject = dnsbl.Subject!;
                        Ensure(subject);
                        map[subject].Dnsbl = dnsbl;
                        break;
                    }
                    case DomainDetective.Views.RpkiInfo rpki when !string.IsNullOrWhiteSpace(rpki.Subject):
                    {
                        var subject = rpki.Subject!;
                        Ensure(subject);
                        map[subject].Rpki = rpki;
                        break;
                    }
                    case DomainDetective.Views.CaaInfo caa when !string.IsNullOrWhiteSpace(caa.Subject):
                        Ensure(caa.Subject); map[caa.Subject].Caa = caa; break;
                    case DomainDetective.Views.NsInfo ns when !string.IsNullOrWhiteSpace(ns.Subject):
                        Ensure(ns.Subject); map[ns.Subject].Ns = ns; break;
                    case DomainDetective.Views.SoaInfo soa when !string.IsNullOrWhiteSpace(soa.Subject):
                        Ensure(soa.Subject); map[soa.Subject].Soa = soa; break;
                    case DomainDetective.Views.ZoneTransferInfo zt when !string.IsNullOrWhiteSpace(zt.Subject):
                        Ensure(zt.Subject); map[zt.Subject].ZoneTransfer = zt; break;
                    case DomainDetective.Views.WildcardDnsInfo wc when !string.IsNullOrWhiteSpace(wc.Subject):
                        Ensure(wc.Subject); map[wc.Subject].Wildcard = wc; break;
                    case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject):
                        Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                    case DomainDetective.Views.DesiredStateInfo ds when !string.IsNullOrWhiteSpace(ds.Subject):
                    {
                        var subject = ds.Subject!;
                        Ensure(subject);
                        map[subject].DesiredState = ds;
                        break;
                    }
                    case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject):
                        Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                    case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject):
                    {
                        var subject = tr.Subject!;
                        Ensure(subject);
                        map[subject].TlsRpt = tr;
                        break;
                    }
                    case DomainDetective.Views.TlsRptReportsTimeSeriesInfo trr when !string.IsNullOrWhiteSpace(trr.Subject):
                        Ensure(trr.Subject); map[trr.Subject].TlsRptReports = trr; break;
                    case DomainDetective.Views.DnssecStatusInfo ds when !string.IsNullOrWhiteSpace(ds.Subject):
                        Ensure(ds.Subject); map[ds.Subject].Dnssec = ds; break;
                    case DomainDetective.Views.DaneRecordInfo dn when !string.IsNullOrWhiteSpace(dn.Subject):
                        Ensure(dn.Subject); map[dn.Subject].Dane = dn; break;
                    case DomainDetective.Views.TtlInfo ttl when !string.IsNullOrWhiteSpace(ttl.Subject):
                    {
                        var subject = ttl.Subject!;
                        Ensure(subject);
                        map[subject].Ttl = ttl;
                        break;
                    }
	                    case DomainDetective.Views.MailTlsInfo mt when !string.IsNullOrWhiteSpace(mt.Subject):
	                        Ensure(mt.Subject);
	                        switch (mt.Check) {
	                            case HealthCheckType.SMTPTLS: map[mt.Subject].SmtpTls = mt; break;
	                            case HealthCheckType.IMAPTLS: map[mt.Subject].ImapTls = mt; break;
	                            case HealthCheckType.POP3TLS: map[mt.Subject].PopTls = mt; break;
	                            default: break;
	                        }
	                        break;
	                    case DomainDetective.Views.CtTimelineInfo ct:
	                    {
	                        var subject = ct.Subject;
	                        if (subject != null)
	                        {
	                            subject = subject.Trim();
	                            if (subject.Length > 0)
	                            {
	                                Ensure(subject);
	                                map[subject].CtTimeline = ct;
	                            }
	                        }
	                        break;
	                    }
	                    case DomainDetective.Views.SubdomainsInfo sub:
	                    {
	                        var subject = sub.Subject;
	                        if (subject != null)
	                        {
	                            subject = subject.Trim();
	                            if (subject.Length > 0)
	                            {
	                                Ensure(subject);
	                                map[subject].Subdomains = sub;
	                            }
	                        }
	                        break;
	                    }
	                    case DomainDetective.Views.DnsInventoryInfo inv:
	                    {
	                        var subject = inv.Subject;
	                        if (subject != null)
	                        {
	                            subject = subject.Trim();
	                            if (subject.Length > 0)
	                            {
	                                Ensure(subject);
	                                map[subject].DnsInventory = inv;
	                            }
	                        }
	                        break;
	                    }
                    case DomainDetective.Views.DnsTraceInfo trc:
                    {
                        var subject = trc.Subject;
                        if (subject != null)
                        {
                            subject = subject.Trim();
                            if (subject.Length > 0)
                            {
                                Ensure(subject);
                                map[subject].DnsTrace = trc;
                            }
                        }
                        break;
                    }
                    case DomainDetective.Views.HttpInfo http when !string.IsNullOrWhiteSpace(http.Subject) || !string.IsNullOrWhiteSpace(http.Url):
                    {
                        var rawUrl = !string.IsNullOrWhiteSpace(http.Subject) ? http.Subject : http.Url;
                        var subject = rawUrl ?? string.Empty;
                        try
                        {
                            if (Uri.TryCreate(subject, UriKind.Absolute, out var uri))
                            {
                                subject = uri.Host;
                            }
                        }
                        catch
                        {
                        }

                        bool IsHttps(DomainDetective.Views.HttpInfo h)
                            => (!string.IsNullOrWhiteSpace(h.Url) ? h.Url : h.Subject)?.StartsWith("https://", StringComparison.OrdinalIgnoreCase) == true;

                        bool prefer = map.ContainsKey(subject) && map[subject].Http != null
                            ? ((IsHttps(http) && !IsHttps(map[subject].Http!)) || (http.IsReachable && !map[subject].Http!.IsReachable))
                            : true;

                        if (!string.IsNullOrWhiteSpace(subject))
                        {
                            Ensure(subject);
                            if (prefer)
                            {
                                map[subject].Http = http;
                            }
                        }
                        break;
                    }
                    case DomainDetective.Views.IpEnrichmentInfo ip:
                    {
                        var subject = ip.Subject;
                        if (subject != null)
                        {
                            subject = subject.Trim();
                            if (subject.Length > 0)
                            {
                                Ensure(subject);
                                map[subject].IpEnrichment = ip;
                            }
                        }
                        break;
                    }
                    case DomainDetective.Views.DnsPropagationInfo dp:
                    {
                        var subject = dp.Subject;
                        if (subject != null)
                        {
                            subject = subject.Trim();
                            if (subject.Length > 0)
                            {
                                Ensure(subject);
                                map[subject].DnsPropagation.Add(dp);
                            }
                        }
                        break;
                    }
                    case DomainDetective.Views.DnsAmplificationSummary amp:
                    {
                        var subject = amp.Subject;
                        if (subject != null)
                        {
                            subject = subject.Trim();
                            if (subject.Length > 0)
                            {
                                Ensure(subject);
                                map[subject].DnsAmplification = amp;
                            }
                        }
                        break;
                    }
                    case DomainDetective.Views.DnsOverTlsSummary dot:
                    {
                        var subject = dot.Subject;
                        if (subject != null)
                        {
                            subject = subject.Trim();
                            if (subject.Length > 0)
                            {
                                Ensure(subject);
                                map[subject].DnsOverTls = dot;
                            }
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }
        return map;
    }
}
