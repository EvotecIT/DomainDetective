using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Shared composition helpers to normalize mixed view inputs into per-domain buckets
/// and provide consistent ordering/title utilities. Intended to be used by all renderers
/// (Word, Html, Markdown, Excel) to avoid data drift.
/// </summary>
public static class CompositionBuilder
{
    public sealed class DomainBucket
    {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public DomainDetective.Views.DmarcAggregateTimeSeriesInfo? DmarcAggregate { get; set; }
        public DomainDetective.Views.RegistrationDriftInfo? Registration { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.ArcInfo? Arc { get; set; }
        public DomainDetective.Views.BimiRecordInfo? Bimi { get; set; }
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }      
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }      
        public DomainDetective.Views.TlsRptReportsTimeSeriesInfo? TlsRptReports { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; }
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }
        public DomainDetective.Views.TtlInfo? Ttl { get; set; }
        public DomainDetective.Views.DesiredStateInfo? DesiredState { get; set; }
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
	        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
	        public DomainDetective.Views.SubdomainsInfo? Subdomains { get; set; }
	        public DomainDetective.Views.DnsInventoryInfo? DnsInventory { get; set; }
	        public DomainDetective.Views.DnsTraceInfo? DnsTrace { get; set; }
	        public DomainDetective.Views.CtTimelineInfo? CtTimeline { get; set; }
	        public DomainDetective.Views.HttpInfo? Http { get; set; }
        public DomainDetective.Views.AgentReadinessInfo? AgentReadiness { get; set; }
        public DomainDetective.Views.SitemapInfo? Sitemap { get; set; }
	        public DomainDetective.Views.IpEnrichmentInfo? IpEnrichment { get; set; }
        public DomainDetective.Views.Microsoft365TenantInfo? Microsoft365 { get; set; }
        public DomainDetective.Views.TyposquattingInfo? Typosquatting { get; set; }
	        public DomainDetective.Views.DnsAmplificationSummary? DnsAmplification { get; set; }
	        public DomainDetective.Views.DnsOverTlsSummary? DnsOverTls { get; set; }
	        public List<DomainDetective.Views.DnsPropagationInfo> DnsPropagation { get; } = new();
	    }

    public static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        void Ensure(string subject) { if (!map.ContainsKey(subject)) map[subject] = new DomainBucket { Subject = subject }; }

        foreach (var it in items ?? Array.Empty<object>())
        {
            switch (it)
            {
                case DomainDetective.Views.MxInfo mx when !string.IsNullOrWhiteSpace(mx.Subject): Ensure(mx.Subject); map[mx.Subject].Mx = mx; break;
                case DomainDetective.Views.SpfRecordInfo spf when !string.IsNullOrWhiteSpace(spf.Subject): Ensure(spf.Subject); map[spf.Subject].Spf = spf; break;
                case DomainDetective.Views.DmarcRecordInfo dmarc when !string.IsNullOrWhiteSpace(dmarc.Subject): Ensure(dmarc.Subject); map[dmarc.Subject].Dmarc = dmarc; break;
                case DomainDetective.Views.DmarcAggregateTimeSeriesInfo da when !string.IsNullOrWhiteSpace(da.Subject): Ensure(da.Subject); map[da.Subject].DmarcAggregate = da; break;
                case DomainDetective.Views.RegistrationDriftInfo reg when !string.IsNullOrWhiteSpace(reg.Subject): Ensure(reg.Subject); map[reg.Subject].Registration = reg; break;
                case DomainDetective.Views.DkimRecordInfo dkim when !string.IsNullOrWhiteSpace(dkim.Subject): Ensure(dkim.Subject); map[dkim.Subject].Dkim.Add(dkim); break;
                case DomainDetective.Views.ArcInfo arc when !string.IsNullOrWhiteSpace(arc.Subject): Ensure(arc.Subject); map[arc.Subject].Arc = arc; break;
                case DomainDetective.Views.BimiRecordInfo bimi when !string.IsNullOrWhiteSpace(bimi.Subject): Ensure(bimi.Subject); map[bimi.Subject].Bimi = bimi; break;
                case DomainDetective.Views.DnsblInfo dnsbl when !string.IsNullOrWhiteSpace(dnsbl.Subject):
                {
                    var subject = dnsbl.Subject!;
                    Ensure(subject);
                    map[subject].Dnsbl = dnsbl;
                    break;
                }
                case DomainDetective.Views.MailClassificationInfo mc when !string.IsNullOrWhiteSpace(mc.Subject): Ensure(mc.Subject); map[mc.Subject].Classification = mc; break;
                case DomainDetective.Views.MtastsInfo ms when !string.IsNullOrWhiteSpace(ms.Subject): Ensure(ms.Subject); map[ms.Subject].Mtasts = ms; break;
                case DomainDetective.Views.TlsRptInfo tr when !string.IsNullOrWhiteSpace(tr.Subject):
                {
                    var subject = tr.Subject!;
                    Ensure(subject);
                    map[subject].TlsRpt = tr;
                    break;
                }
                case DomainDetective.Views.TlsRptReportsTimeSeriesInfo trr when !string.IsNullOrWhiteSpace(trr.Subject):
                {
                    var subject = trr.Subject;
                    Ensure(subject);
                    map[subject].TlsRptReports = trr;
                    break;
                }
                case DomainDetective.Views.NsInfo ns when !string.IsNullOrWhiteSpace(ns.Subject): Ensure(ns.Subject); map[ns.Subject].Ns = ns; break;      
                case DomainDetective.Views.SoaInfo soa when !string.IsNullOrWhiteSpace(soa.Subject): Ensure(soa.Subject); map[soa.Subject].Soa = soa; break;    
                case DomainDetective.Views.CaaInfo caa when !string.IsNullOrWhiteSpace(caa.Subject): Ensure(caa.Subject); map[caa.Subject].Caa = caa; break;    
                case DomainDetective.Views.DnssecStatusInfo ds when !string.IsNullOrWhiteSpace(ds.Subject): Ensure(ds.Subject); map[ds.Subject].Dnssec = ds; break;
                case DomainDetective.Views.DaneRecordInfo dr when !string.IsNullOrWhiteSpace(dr.Subject): Ensure(dr.Subject); map[dr.Subject].Dane = dr; break;
                case DomainDetective.Views.TtlInfo ttl when !string.IsNullOrWhiteSpace(ttl.Subject):
                {
                    var subject = ttl.Subject!;
                    Ensure(subject);
                    map[subject].Ttl = ttl;
                    break;
                }
                case DomainDetective.Views.DesiredStateInfo ds when !string.IsNullOrWhiteSpace(ds.Subject):
                {
                    var subject = ds.Subject!;
                    Ensure(subject);
                    map[subject].DesiredState = ds;
                    break;
                }
                case DomainDetective.Views.MailTlsInfo mt when !string.IsNullOrWhiteSpace(mt.Subject):
                    Ensure(mt.Subject);
                    switch (mt.Check)
                    {
                        case DomainDetective.HealthCheckType.SMTPTLS:
                        case DomainDetective.HealthCheckType.STARTTLS:
                            map[mt.Subject].SmtpTls = mt; break;
                        case DomainDetective.HealthCheckType.IMAPTLS:
                            map[mt.Subject].ImapTls = mt; break;
                        case DomainDetective.HealthCheckType.POP3TLS:
                            map[mt.Subject].PopTls = mt; break;
                        default:
                            map[mt.Subject].SmtpTls ??= mt; break;
                    }
                    break;
                case DomainDetective.Views.RpkiInfo rpki when !string.IsNullOrWhiteSpace(rpki.Subject):
                {
                    var subject = rpki.Subject!;
                    Ensure(subject);
                    map[subject].Rpki = rpki;
                    break;
                }
                case DomainDetective.Views.ZoneTransferInfo zt when !string.IsNullOrWhiteSpace(zt.Subject): Ensure(zt.Subject); map[zt.Subject].ZoneTransfer = zt; break;
	                case DomainDetective.Views.WildcardDnsInfo wc when !string.IsNullOrWhiteSpace(wc.Subject): Ensure(wc.Subject); map[wc.Subject].Wildcard = wc; break;
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
	                case DomainDetective.Views.DnsTraceInfo tr:
	                {
	                    var subject = tr.Subject;
	                    if (subject != null)
	                    {
	                        subject = subject.Trim();
	                        if (subject.Length > 0)
	                        {
	                            Ensure(subject);
	                            map[subject].DnsTrace = tr;
	                        }
	                    }
	                    break;
	                }
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
	                case DomainDetective.Views.HttpInfo http when !string.IsNullOrWhiteSpace(http.Url) || !string.IsNullOrWhiteSpace(http.Subject):
	                {
	                    var raw = !string.IsNullOrWhiteSpace(http.Subject) ? http.Subject : http.Url;
	                    var subject = NormalizeHttpSubject(raw);
	                    if (!string.IsNullOrWhiteSpace(subject))
	                    {
	                        Ensure(subject!);
	                        if (map[subject!].Http == null || PreferHttp(http, map[subject!].Http!))
	                        {
	                            map[subject!].Http = http;
	                        }
	                    }
	                    break;
	                }
                case DomainDetective.Views.AgentReadinessInfo agent when !string.IsNullOrWhiteSpace(agent.Subject):
                {
                    var subject = NormalizeHttpSubject(agent.Subject);
                    if (!string.IsNullOrWhiteSpace(subject))
                    {
                        Ensure(subject!);
                        map[subject!].AgentReadiness = agent;
                    }
                    break;
                }
                case DomainDetective.Views.SitemapInfo sitemap when !string.IsNullOrWhiteSpace(sitemap.Subject):
                {
                    var subject = NormalizeHttpSubject(sitemap.Subject);
                    if (!string.IsNullOrWhiteSpace(subject))
                    {
                        Ensure(subject!);
                        map[subject!].Sitemap = sitemap;
                    }
                    break;
                }
	                case DomainDetective.Views.IpEnrichmentInfo ip when !string.IsNullOrWhiteSpace(ip.Subject):
	                {
	                    Ensure(ip.Subject!);
	                    map[ip.Subject!].IpEnrichment = ip;
	                    break;
	                }
	                case DomainDetective.Views.Microsoft365TenantInfo m365 when !string.IsNullOrWhiteSpace(m365.Subject):
	                {
	                    Ensure(m365.Subject!);
	                    map[m365.Subject!].Microsoft365 = m365;
	                    break;
	                }
	                case DomainDetective.Views.TyposquattingInfo typo when !string.IsNullOrWhiteSpace(typo.Subject):
	                {
	                    Ensure(typo.Subject!);
	                    map[typo.Subject!].Typosquatting = typo;
	                    break;
	                }
	                case DomainDetective.Views.DnsPropagationInfo dp when !string.IsNullOrWhiteSpace(dp.Subject):
	                {
	                    Ensure(dp.Subject!);
	                    map[dp.Subject!].DnsPropagation.Add(dp);
	                    break;
	                }
	                default: break;
	            }
	        }
        return map;
    }

    private static string? NormalizeHttpSubject(string? raw)
    {
        if (raw == null)
        {
            return null;
        }

        var s = raw.Trim();
        if (s.Length == 0)
        {
            return null;
        }
        try
        {
            if (Uri.TryCreate(s, UriKind.Absolute, out var uri))
            {
                return uri.Host;
            }
        }
        catch { }
        return s;
    }

    private static bool PreferHttp(DomainDetective.Views.HttpInfo candidate, DomainDetective.Views.HttpInfo existing)
    {
        bool IsHttps(DomainDetective.Views.HttpInfo h) =>
            (!string.IsNullOrWhiteSpace(h.Url) ? h.Url : h.Subject)?.StartsWith("https://", StringComparison.OrdinalIgnoreCase) == true;

        if (existing == null) return true;
        if (candidate == null) return false;
        if (IsHttps(candidate) && !IsHttps(existing)) return true;
        if (candidate.IsReachable && !existing.IsReachable) return true;
        return false;
    }

    public static List<KeyValuePair<string, DomainBucket>> OrderDomains(IReadOnlyList<object> items, Dictionary<string, DomainBucket> map, DomainOrder order)
    {
        var list = map.ToList();
        return order switch
        {
            DomainOrder.Input => OrderByFirstSeen(items, list),
            _ => list.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).ToList(),
        };
    }

    private static List<KeyValuePair<string, DomainBucket>> OrderByFirstSeen(IReadOnlyList<object> items, List<KeyValuePair<string, DomainBucket>> list)
    {
        var positions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int idx = 0;
        foreach (var it in items ?? Array.Empty<object>())
        {
            var subject = TryGetSubject(it);
            if (string.IsNullOrWhiteSpace(subject)) continue;
            if (!positions.ContainsKey(subject!)) positions[subject!] = idx++;
        }
        return list.OrderBy(kv => positions.TryGetValue(kv.Key, out var p) ? p : int.MaxValue).ToList();
    }

    private static string? TryGetSubject(object it)
    {
        try
        {
            var p = it.GetType().GetProperty("Subject");
            return p?.GetValue(it)?.ToString();
        }
        catch { return null; }
    }

    public static string BuildSubjectTitle(IReadOnlyList<string> domains)
    {
        if (domains == null || domains.Count == 0) return "Custom Composition";
        if (domains.Count == 1) return domains[0];
        if (domains.Count == 2) return $"{domains[0]}+{domains[1]}";
        return $"{domains[0]}+{domains[1]}(+{domains.Count - 2})";
    }
}
