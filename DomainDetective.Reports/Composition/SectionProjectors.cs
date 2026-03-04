using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public static SpfSection? BuildSpf(DomainDetective.Views.SpfRecordInfo spf)
    {
        if (spf == null) return null;
        var sec = new SpfSection { DnsLookupsCount = spf.DnsLookupsCount };
        sec.Summary.Add(("Status", spf.Status ?? "-"));
        sec.Summary.Add(("DNS Lookups", spf.DnsLookupsCount.ToString()));
        sec.Summary.Add(("Record Present", spf.SpfRecordExists ? "Yes" : "No"));
        sec.Summary.Add(("DNS TTL (s)", spf.DnsRecordTtl?.ToString() ?? "-"));
        sec.Summary.Add(("CNAME Resolved", spf.IsCnameResolved ? "Yes" : "No"));
        sec.Summary.Add(("CNAME TTL (s)", spf.CnameTtl?.ToString() ?? "-"));
        if (spf.StartsCorrectly) sec.Summary.Add(("Starts Correctly", "Yes")); else sec.Summary.Add(("Starts Correctly", "No"));
        if (!string.IsNullOrWhiteSpace(spf.Raw?.AllMechanism)) sec.Summary.Add(("All Mechanism", spf.Raw!.AllMechanism!));
        // Findings (exclude Info)
        foreach (var a in (spf.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info))
            sec.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        // Positives
        foreach (var p in spf.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var t = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(t)) sec.Positives.Add(t!);
        }
        // References
        foreach (var r in spf.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) sec.References.Add(r);
        // Evidence
        sec.SpfRecord = spf.SpfRecord;
        // Mechanisms
        try {
            foreach (var m in spf.Mechanisms ?? Array.Empty<DomainDetective.SpfPartAnalysis>())
            {
                string q = string.IsNullOrEmpty(m?.Prefix) ? "+" : m!.Prefix!;
                sec.Mechanisms.Add((q, m?.Type ?? string.Empty, m?.Value ?? string.Empty, m?.Provider ?? string.Empty));
            }
        } catch { }
        // Flattened IP analysis summary
        try {
            var flat = spf.Raw?.FlattenedIpAnalysis;
            if (flat != null)
            {
                sec.FlattenedUniqueIpCount = flat.UniqueIps?.Count ?? 0;
                sec.FlattenedDuplicateIpCount = flat.DuplicateIps?.Count ?? 0;
                sec.FlattenedTokenCount = flat.TokenIpMap?.Count ?? 0;
            }
        } catch { }
        // Provider Help topics (title+url)
        try {
            foreach (var ph in spf.ProviderHelp ?? Array.Empty<DomainDetective.Views.ProviderHelpLinks>())
            {
                var topics = ph.Topics ?? new List<DomainDetective.Views.ProviderHelpTopic>();
                foreach (var t in topics)
                {
                    if (string.IsNullOrWhiteSpace(t?.Url)) continue;
                    var f = LinkFormatter.Format(t!.Url!);
                    string title = string.IsNullOrWhiteSpace(t!.Title) ? f.Title : t!.Title!;
                    sec.ProviderHelp.Add((title, f.Url));
                }
            }
        } catch { }
        // Highlights
        try { foreach (var h in spf.Highlights ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(h)) sec.Highlights.Add(h!); } catch { }
        return sec;
    }

    public static DmarcSection? BuildDmarc(DomainDetective.Views.DmarcRecordInfo d)
    {
        if (d == null) return null;
        var sec = new DmarcSection
        {
            Policy = string.IsNullOrWhiteSpace(d.Policy) ? "-" : d.Policy!,
            Status = d.Status ?? "-",
            RuaCount = d.MailtoRua?.Count ?? 0,
            RufCount = d.MailtoRuf?.Count ?? 0
        };
        sec.Summary.Add(("Status", sec.Status));
        sec.Summary.Add(("Policy", sec.Policy));
        sec.Summary.Add(("DNS TTL (s)", d.DnsRecordTtl?.ToString() ?? "-"));
        sec.Summary.Add(("CNAME Resolved", d.IsCnameResolved ? "Yes" : "No"));
        sec.Summary.Add(("CNAME TTL (s)", d.CnameTtl?.ToString() ?? "-"));
        sec.Summary.Add(("rua", sec.RuaCount.ToString()));
        sec.Summary.Add(("ruf", sec.RufCount.ToString()));
        if (!string.IsNullOrWhiteSpace(d.DkimAlignment)) sec.Summary.Add(("adkim", d.DkimAlignment));
        if (!string.IsNullOrWhiteSpace(d.SpfAlignment)) sec.Summary.Add(("aspf", d.SpfAlignment));
        foreach (var a in (d.Assessments ?? Array.Empty<DomainDetective.Assessment>()).Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info))
            sec.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in d.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        { var t = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(t)) sec.Positives.Add(t!); }
        foreach (var r in d.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) sec.References.Add(r);
        // Extras
        sec.DmarcRecord = d.DmarcRecord;
        sec.DkimAlignment = d.DkimAlignment; sec.SpfAlignment = d.SpfAlignment;
        try { if (d.MailtoRua != null) foreach (var u in d.MailtoRua) if (!string.IsNullOrWhiteSpace(u)) sec.MailtoRua.Add(u); } catch { }
        try { if (d.HttpRua != null) foreach (var u in d.HttpRua) if (!string.IsNullOrWhiteSpace(u)) sec.HttpRua.Add(u); } catch { }
        try { if (d.MailtoRuf != null) foreach (var u in d.MailtoRuf) if (!string.IsNullOrWhiteSpace(u)) sec.MailtoRuf.Add(u); } catch { }
        try { if (d.HttpRuf != null) foreach (var u in d.HttpRuf) if (!string.IsNullOrWhiteSpace(u)) sec.HttpRuf.Add(u); } catch { }
        try { foreach (var h in d.Highlights ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(h)) sec.Highlights.Add(h); } catch { }
        return sec;
    }

    public static DkimSection? BuildDkim(IReadOnlyList<DomainDetective.Views.DkimRecordInfo> dkimList)
    {
        if (dkimList == null || dkimList.Count == 0) return null;
        var sec = new DkimSection();
        foreach (var k in dkimList)
        {
            sec.Rows.Add(new DkimSection.Row {
                Selector = k.Selector ?? string.Empty,
                Status = k.Status ?? "-",
                KeyBits = k.PublicKeyExists ? k.KeyLength.ToString() : "-",
                Hash = string.IsNullOrWhiteSpace(k.HashAlgorithm) ? "-" : k.HashAlgorithm!,
                Weak = k.WeakKey,
                Flags = k.Flags ?? string.Empty,
                TtlSeconds = k.DnsRecordTtl,
                CnameResolved = k.IsCnameResolved,
                CnameTtlSeconds = k.CnameTtl,
                Record = k.DkimRecord ?? string.Empty
            });
        }
        var findings = dkimList.SelectMany(x => x.Assessments ?? Array.Empty<DomainDetective.Assessment>())
            .Where(a => a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
            .Select(a => new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        sec.Findings.AddRange(findings);
        var pos = dkimList.SelectMany(x => x.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
            .Select(p => p?.Title ?? p?.Code)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        sec.Positives.AddRange(pos);
        var refs = dkimList.SelectMany(x => x.References ?? Array.Empty<string>())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        sec.References.AddRange(refs);
        try { foreach (var d in dkimList.SelectMany(x => x.Highlights ?? Array.Empty<string>())) if (!string.IsNullOrWhiteSpace(d)) sec.Highlights.Add(d); } catch { }
        return sec;
    }

    // Overload with TTL support (maps TTLs from TtlInfo to per-selector rows)
    public static DkimSection? BuildDkim(IReadOnlyList<DomainDetective.Views.DkimRecordInfo> dkimList, DomainDetective.Views.TtlInfo? ttl)
    {
        var sec = BuildDkim(dkimList);
        if (sec == null) return null;
        try
        {
            if (ttl?.DkimTxtTtls != null && ttl.DkimTxtTtls.Count > 0)
            {
                foreach (var row in sec.Rows)
                {
                    // Prefer exact FQDN if available via Name; else compose from selector and subject
                    string? fqdn = null;
                    var src = dkimList.FirstOrDefault(x => string.Equals(x.Selector, row.Selector, StringComparison.OrdinalIgnoreCase));
                    if (src != null)
                    {
                        fqdn = src.Name;
                        if (string.IsNullOrWhiteSpace(fqdn) && !string.IsNullOrWhiteSpace(src.Subject) && !string.IsNullOrWhiteSpace(src.Selector))
                            fqdn = $"{src.Selector}._domainkey.{src.Subject}";
                    }
                    if (!string.IsNullOrWhiteSpace(fqdn) && ttl.DkimTxtTtls.TryGetValue(fqdn!, out var ttls) && ttls != null && ttls.Count > 0)
                    {
                        // Use minimum TTL observed across authoritative servers as conservative value
                        row.TtlSeconds = ttls.Min();
                    }
                }
            }
        }
        catch { /* best effort TTL mapping */ }
        return sec;
    }

    public static MxSection? BuildMx(DomainDetective.Views.MxInfo mx, DomainDetective.Views.MailTlsInfo? smtp = null, DomainDetective.Views.MailTlsInfo? imap = null, DomainDetective.Views.MailTlsInfo? pop = null)
    {
        if (mx == null) return null;
        var s = new MxSection { Status = mx.Status ?? "-", HasBackup = mx.HasBackupServers, Ipv6 = mx.Ipv6Supported, NullMx = mx.HasNullMx };
        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Has Backup Servers", mx.HasBackupServers ? "Yes" : "No"));
        s.Summary.Add(("IPv6 Supported", mx.Ipv6Supported ? "Yes" : "No"));
        s.Summary.Add(("Null MX", mx.HasNullMx ? "Yes" : "No"));
        s.Summary.Add(("TTL Uniform", mx.MxTtlUniform ? "Yes" : "No"));
        s.Summary.Add(("MX TTL Min (s)", mx.MinMxTtl?.ToString() ?? "-"));
        s.Summary.Add(("MX TTL Avg (s)", mx.AvgMxTtl.HasValue ? ((int)Math.Round(mx.AvgMxTtl.Value)).ToString() : "-"));
        s.Summary.Add(("MX TTL Max (s)", mx.MaxMxTtl?.ToString() ?? "-"));
        try { foreach (var rec in mx.MxRecords ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rec)) s.Records.Add(rec); } catch { }
        try { s.MailTlsSmtp = smtp?.Status; s.MailTlsImap = imap?.Status; s.MailTlsPop = pop?.Status; } catch { }
        foreach (var a in mx.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in mx.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var t = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(t)) s.Positives.Add(t!); }
        foreach (var r in mx.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static MtastsSection? BuildMtasts(DomainDetective.Views.MtastsInfo m)
    {
        if (m == null) return null;
        var s = new MtastsSection { Status = m.Status ?? "-", Mode = m.Mode ?? "-", MaxAge = m.MaxAge, DnsRecordPresent = m.DnsRecordPresent, PolicyValid = m.PolicyValid, MxAligned = m.MxAligned };
        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Mode", s.Mode));
        s.Summary.Add(("Max-Age", m.MaxAge.ToString()));
        s.Summary.Add(("DNS Present", m.DnsRecordPresent ? "Yes" : "No"));
        s.Summary.Add(("DNS TTL (s)", m.DnsRecordTtl?.ToString() ?? "-"));
        s.Summary.Add(("CNAME Resolved", m.IsCnameResolved ? "Yes" : "No"));
        s.Summary.Add(("CNAME TTL (s)", m.CnameTtl?.ToString() ?? "-"));
        s.Summary.Add(("Policy Valid", m.PolicyValid ? "Yes" : "No"));
        s.Summary.Add(("MX Aligned", m.MxAligned ? "Yes" : "No"));
        foreach (var a in m.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in m.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var t = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(t)) s.Positives.Add(t!); }
        foreach (var r in m.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static TlsRptSection? BuildTlsRpt(DomainDetective.Views.TlsRptInfo t)
    {
        if (t == null) return null;
        var s = new TlsRptSection { Status = t.Status ?? "-", RuaCount = t.MailtoRua?.Count ?? 0 };
        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("rua", s.RuaCount.ToString()));
        s.Summary.Add(("DNS TTL (s)", t.DnsRecordTtl?.ToString() ?? "-"));
        s.Summary.Add(("CNAME Resolved", t.IsCnameResolved ? "Yes" : "No"));
        s.Summary.Add(("CNAME TTL (s)", t.CnameTtl?.ToString() ?? "-"));
        foreach (var a in t.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in t.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in t.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static DnsblSection? BuildDnsbl(DomainDetective.Views.DnsblInfo d)
    {
        if (d == null) return null;
        var s = new DnsblSection { Status = d.Status ?? "-", ProvidersChecked = d.ProvidersChecked, HostsChecked = d.HostsChecked, HostsListed = d.HostsListed };
        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Providers Checked", d.ProvidersChecked.ToString()));
        s.Summary.Add(("Hosts Checked", d.HostsChecked.ToString()));
        s.Summary.Add(("Hosts Listed", d.HostsListed.ToString()));
        foreach (var a in d.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in d.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in d.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static NsSection? BuildNs(DomainDetective.Views.NsInfo n)
    {
        if (n == null) return null;
        var s = new NsSection { Status = n.Status ?? "-" };
        s.Summary.Add(("At Least Two", n.AtLeastTwoRecords ? "Yes" : "No"));
        s.Summary.Add(("All Have A/AAAA", n.AllHaveAOrAaaa ? "Yes" : "No"));
        s.Summary.Add(("Glue Complete", n.GlueRecordsComplete ? "Yes" : "No"));
        s.Summary.Add(("Glue Consistent", n.GlueRecordsConsistent ? "Yes" : "No"));
        s.Summary.Add(("Delegation Matches", n.DelegationMatches ? "Yes" : "No"));
        s.Summary.Add(("Distinct ASNs", n.AsnDistinctCount.ToString()));
        foreach (var a in n.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in n.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in n.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static SoaSection? BuildSoa(DomainDetective.Views.SoaInfo ssoa)
    {
        if (ssoa == null) return null;
        var s = new SoaSection { Status = ssoa.Status ?? "-" };
        s.Summary.Add(("Primary NS", ssoa.PrimaryNameServer ?? "-"));
        s.Summary.Add(("Responsible", ssoa.ResponsibleMailbox ?? "-"));
        s.Summary.Add(("Serial", ssoa.SerialNumber.ToString()));
        s.Summary.Add(("Refresh", ssoa.Refresh.ToString()));
        foreach (var a in ssoa.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in ssoa.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in ssoa.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static CaaSection? BuildCaa(DomainDetective.Views.CaaInfo c)
    {
        if (c == null) return null;
        var s = new CaaSection { Status = c.Status ?? "-" };
        s.Summary.Add(("Valid Records", c.ValidRecords.ToString()));
        s.Summary.Add(("Invalid Records", c.InvalidRecords.ToString()));
        foreach (var a in c.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in c.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in c.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static DnssecSection? BuildDnssec(DomainDetective.Views.DnssecStatusInfo d)
    {
        if (d == null) return null;
        var s = new DnssecSection { Status = d.Status ?? "-", HasDs = d.DsMatch, Validates = d.ChainValid }; 
        s.Summary.Add(("DS Match", d.DsMatch ? "Yes" : "No"));
        s.Summary.Add(("Chain Valid", d.ChainValid ? "Yes" : "No"));
        foreach (var a in d.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in d.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in d.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static DaneSection? BuildDane(DomainDetective.Views.DaneRecordInfo d)
    {
        if (d == null) return null;
        var s = new DaneSection { Status = d.Status ?? "-", TlsaUsage = null }; 
        s.Summary.Add(("Records", d.NumberOfRecords.ToString()));
        s.Summary.Add(("Invalid Records", d.HasInvalidRecords ? "Yes" : "No"));
        foreach (var a in d.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in d.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var r in d.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        return s;
    }

    public static MailTlsSection? BuildMailTls(DomainDetective.Views.MailTlsInfo? smtp, DomainDetective.Views.MailTlsInfo? imap, DomainDetective.Views.MailTlsInfo? pop)
    {
        if (smtp == null && imap == null && pop == null) return null;
        var s = new MailTlsSection();
        void add(string name, DomainDetective.Views.MailTlsInfo? v) {
            if (v == null) return; s.Rows.Add(new MailTlsSection.Row { Service = name, Status = v.Status ?? "-", Protocol = null });
            foreach (var a in v.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
            foreach (var p in v.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
            foreach (var r in v.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(r)) s.References.Add(r);
        }
        add("SMTP", smtp); add("IMAP", imap); add("POP3", pop);
        return s;
    }

    public static MailTransportPostureSection? BuildMailTransportPosture(
        DomainDetective.Views.MxInfo? mx,
        DomainDetective.Views.MailTlsInfo? smtp,
        DomainDetective.Views.MailTlsInfo? imap,
        DomainDetective.Views.MailTlsInfo? pop,
        DomainDetective.Views.MtastsInfo? mtasts,
        DomainDetective.Views.TlsRptInfo? tlsRpt,
        DomainDetective.Views.TlsRptReportsTimeSeriesInfo? tlsRptReports,
        DomainDetective.Views.DaneRecordInfo? dane)
    {
        if (mx == null && smtp == null && imap == null && pop == null && mtasts == null && tlsRpt == null && tlsRptReports == null && dane == null)
        {
            return null;
        }

        int mailTlsWarn = (smtp?.WarningCount ?? 0) + (imap?.WarningCount ?? 0) + (pop?.WarningCount ?? 0);
        int mailTlsErr = (smtp?.ErrorCount ?? 0) + (imap?.ErrorCount ?? 0) + (pop?.ErrorCount ?? 0);
        string mailTlsStatus = (smtp != null || imap != null || pop != null)
            ? (mailTlsErr > 0 ? "Error" : (mailTlsWarn > 0 ? "Warning" : "OK"))
            : "-";

        var sec = new MailTransportPostureSection
        {
            WarningCount = (mx?.WarningCount ?? 0) + mailTlsWarn + (mtasts?.WarningCount ?? 0) + (tlsRpt?.WarningCount ?? 0) + (tlsRptReports?.WarningCount ?? 0) + (dane?.WarningCount ?? 0),
            ErrorCount = (mx?.ErrorCount ?? 0) + mailTlsErr + (mtasts?.ErrorCount ?? 0) + (tlsRpt?.ErrorCount ?? 0) + (tlsRptReports?.ErrorCount ?? 0) + (dane?.ErrorCount ?? 0),
        };
        sec.Status = sec.ErrorCount > 0 ? "Error" : (sec.WarningCount > 0 ? "Warning" : "OK");

        var summaryKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddSummary(string key, string? value)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return;
            }
            if (!summaryKeys.Add(key))
            {
                return;
            }
            sec.Summary.Add((key, string.IsNullOrWhiteSpace(value) ? "-" : value!.Trim()));
        }

        AddSummary("Status", sec.Status);
        AddSummary("Warnings", sec.WarningCount.ToString());
        AddSummary("Errors", sec.ErrorCount.ToString());

        if (mx != null) AddSummary("MX", mx.Status);
        if (smtp != null) AddSummary("SMTP TLS", smtp.Status);
        if (imap != null) AddSummary("IMAP TLS", imap.Status);
        if (pop != null) AddSummary("POP3 TLS", pop.Status);
        if (smtp != null || imap != null || pop != null) AddSummary("Mail TLS", mailTlsStatus);

        if (mtasts != null) AddSummary("MTA-STS", mtasts.Status);
        if (tlsRpt != null) AddSummary("TLS-RPT", tlsRpt.Status);

        if (tlsRptReports != null)
        {
            AddSummary("TLS-RPT Reports", tlsRptReports.Status);
            AddSummary("TLS-RPT Reports (snapshots)", tlsRptReports.SnapshotCount.ToString());

            int total = tlsRptReports.TotalSuccessfulSessions + tlsRptReports.TotalFailedSessions;
            AddSummary("TLS-RPT Failure Rate", total > 0 ? tlsRptReports.FailureRatePercent.ToString("0.0") + "%" : "-");
            AddSummary("TLS-RPT Failed Sessions", tlsRptReports.TotalFailedSessions.ToString());

            var start = tlsRptReports.PeriodStartUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            var end = tlsRptReports.PeriodEndUtc?.UtcDateTime.ToString("yyyy-MM-dd") ?? "-";
            AddSummary("TLS-RPT Period (UTC)", $"{start}..{end}");
        }

        if (dane != null) AddSummary("DANE", dane.Status);

        var findingSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddFinding(SimpleFinding f)
        {
            if (f == null)
            {
                return;
            }
            var key = $"{f.Severity}|{f.Code}|{f.Target}|{f.Message}".Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                return;
            }
            if (findingSet.Add(key))
            {
                sec.Findings.Add(f);
            }
        }
        void AddFindings(IEnumerable<SimpleFinding>? list)
        {
            if (list == null)
            {
                return;
            }
            foreach (var f in list)
            {
                if (f != null) AddFinding(f);
            }
        }

        var positiveSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddPositive(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return;
            }
            var v = text!.Trim();
            if (positiveSet.Add(v))
            {
                sec.Positives.Add(v);
            }
        }
        void AddPositives(IEnumerable<string>? list)
        {
            if (list == null)
            {
                return;
            }
            foreach (var p in list)
            {
                AddPositive(p);
            }
        }

        var referenceSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddReference(string? url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return;
            }
            var v = url!.Trim();
            if (referenceSet.Add(v))
            {
                sec.References.Add(v);
            }
        }
        void AddReferences(IEnumerable<string>? list)
        {
            if (list == null)
            {
                return;
            }
            foreach (var r in list)
            {
                AddReference(r);
            }
        }

        var mxSec = mx != null ? BuildMx(mx, smtp, imap, pop) : null;
        AddFindings(mxSec?.Findings);
        AddPositives(mxSec?.Positives);
        AddReferences(mxSec?.References);

        var mailTlsSec = BuildMailTls(smtp, imap, pop);
        AddFindings(mailTlsSec?.Findings);
        AddPositives(mailTlsSec?.Positives);
        AddReferences(mailTlsSec?.References);

        var mtastsSec = mtasts != null ? BuildMtasts(mtasts) : null;
        AddFindings(mtastsSec?.Findings);
        AddPositives(mtastsSec?.Positives);
        AddReferences(mtastsSec?.References);

        var tlsSec = tlsRpt != null ? BuildTlsRpt(tlsRpt) : null;
        AddFindings(tlsSec?.Findings);
        AddPositives(tlsSec?.Positives);
        AddReferences(tlsSec?.References);

        if (tlsRptReports != null)
        {
            foreach (var a in tlsRptReports.Assessments ?? Array.Empty<DomainDetective.Assessment>())
            {
                if (a == null || a.Severity == DomainDetective.AssessmentSeverity.Info)
                {
                    continue;
                }
                AddFinding(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
            }
            foreach (var p in tlsRptReports.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
            {
                AddPositive(p?.Title ?? p?.Code);
            }
            AddReferences(tlsRptReports.References);
        }

        var daneSec = dane != null ? BuildDane(dane) : null;
        AddFindings(daneSec?.Findings);
        AddPositives(daneSec?.Positives);
        AddReferences(daneSec?.References);

        if (mtasts != null) AddReference("https://www.rfc-editor.org/rfc/rfc8461");
        if (tlsRpt != null || tlsRptReports != null) AddReference("https://www.rfc-editor.org/rfc/rfc8460");
        if (dane != null) AddReference("https://www.rfc-editor.org/rfc/rfc7672");
        if (smtp != null || imap != null || pop != null) AddReference("https://www.rfc-editor.org/rfc/rfc8314");

        return sec;
    }

    public static RpkiSection? BuildRpki(DomainDetective.Views.RpkiInfo r)      
    {
        if (r == null) return null;
        var s = new RpkiSection { Status = r.Status ?? "-" };
        s.Summary.Add(("Valid", r.ValidCount.ToString()));
        s.Summary.Add(("Checked", r.TotalChecked.ToString()));
        foreach (var a in r.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in r.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var rr in r.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);
        return s;
    }

    public static ZoneTransferSection? BuildZoneTransfer(DomainDetective.Views.ZoneTransferInfo z)
    {
        if (z == null) return null;
        var s = new ZoneTransferSection { Status = z.Status ?? "-" };
        s.Summary.Add(("Open Servers", z.OpenCount.ToString()));
        s.Summary.Add(("Checked", z.TotalChecked.ToString()));
        foreach (var a in z.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in z.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var rr in z.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);
        return s;
    }

    public static WildcardSection? BuildWildcard(DomainDetective.Views.WildcardDnsInfo w)
    {
        if (w == null) return null;
        var s = new WildcardSection { Status = w.Status ?? "-" };
        s.Summary.Add(("Wildcard (catch-all)", w.CatchAll ? "Yes" : "No"));
        foreach (var a in w.Assessments ?? Array.Empty<DomainDetective.Assessment>()) if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info) s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        foreach (var p in w.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>()) { var tt = p?.Title ?? p?.Code; if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!); }
        foreach (var rr in w.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);
        return s;
    }

    public static CtTimelineSection? BuildCtTimeline(DomainDetective.Views.CtTimelineInfo ct)
    {
        if (ct == null) return null;

        string FormatDate(DateTimeOffset? dt) => dt.HasValue ? dt.Value.ToString("yyyy-MM-dd") : "-";

        string FormatIssuerList(IReadOnlyDictionary<string, int>? counts, int take)
        {
            if (counts == null || counts.Count == 0) return "-";
            var items = counts
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(0, take))
                .Select(kv => kv.Key)
                .ToList();
            if (items.Count == 0) return "-";
            var extra = counts.Count - items.Count;
            return extra > 0 ? string.Join(", ", items) + $" (+{extra})" : string.Join(", ", items);
        }

        var s = new CtTimelineSection
        {
            Status = ct.Status ?? "-",
            QuerySucceeded = ct.QuerySucceeded,
            ResultsCapped = ct.ResultsCapped,
            FailureReason = ct.FailureReason,
            Observations = ct.CertificateObservationCount,
            UniqueCertificates = ct.UniqueCertificateCount,
            ActiveCertificates = ct.ActiveCertificateCount,
            ExpiredCertificates = ct.ExpiredCertificateCount,
            NotYetValidCertificates = ct.NotYetValidCertificateCount,
            WildcardCertificates = ct.WildcardCertificateCount,
            IssuedLast7Days = ct.IssuedLast7Days,
            IssuedLast30Days = ct.IssuedLast30Days,
            FirstSeenUtc = FormatDate(ct.FirstSeenUtc),
            LastSeenUtc = FormatDate(ct.LastSeenUtc),
            DistinctIssuers = ct.IssuerCounts?.Count ?? 0,
            TopIssuers = FormatIssuerList(ct.IssuerCounts, 3)
        };

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Query OK", s.QuerySucceeded ? "Yes" : "No"));
        if (!string.IsNullOrWhiteSpace(s.FailureReason)) s.Summary.Add(("Failure", s.FailureReason!));
        s.Summary.Add(("Observations", s.Observations.ToString()));
        s.Summary.Add(("Unique Certificates", s.UniqueCertificates.ToString()));
        s.Summary.Add(("Active", s.ActiveCertificates.ToString()));
        s.Summary.Add(("Expired", s.ExpiredCertificates.ToString()));
        if (s.NotYetValidCertificates > 0) s.Summary.Add(("Not Yet Valid", s.NotYetValidCertificates.ToString()));
        s.Summary.Add(("Wildcards", s.WildcardCertificates.ToString()));
        s.Summary.Add(("Issued (7d)", s.IssuedLast7Days.ToString()));
        s.Summary.Add(("Issued (30d)", s.IssuedLast30Days.ToString()));
        s.Summary.Add(("First Seen (UTC)", s.FirstSeenUtc));
        s.Summary.Add(("Last Seen (UTC)", s.LastSeenUtc));
        s.Summary.Add(("Issuer Diversity", s.DistinctIssuers.ToString()));
        s.Summary.Add(("Top Issuers", s.TopIssuers));
        if (s.ResultsCapped) s.Summary.Add(("Capped", "Yes"));

        try
        {
            foreach (var b in ct.Timeline ?? Array.Empty<DomainDetective.CtTimelineBucket>())
            {
                s.Timeline.Add(new CtTimelineSection.BucketRow
                {
                    Month = b.ToString(),
                    Certificates = b.UniqueCertificates,
                    Issuers = b.DistinctIssuers
                });
            }
        }
        catch
        {
        }

        try
        {
            foreach (var r in ct.RecentCertificates ?? Array.Empty<DomainDetective.CtCertificateSample>())
            {
                s.RecentCertificates.Add(new CtTimelineSection.RecentRow
                {
                    EntryUtc = r.EntryTimestampUtc?.ToString("yyyy-MM-dd") ?? "-",
                    NotAfterUtc = r.NotAfterUtc?.ToString("yyyy-MM-dd") ?? "-",
                    Issuer = r.IssuerName,
                    CommonName = r.CommonName,
                    Validity = r.ValidityStatus,
                    Wildcard = r.Wildcard
                });
                if (s.RecentCertificates.Count >= 200) break;
            }
        }
        catch
        {
        }

        foreach (var a in ct.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in ct.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var tt = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!);
        }
        foreach (var rr in ct.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }

    public static HttpSection? BuildHttp(DomainDetective.Views.HttpInfo http)
    {
        if (http == null) return null;

        string? effectiveUrl = null;
        try
        {
            var visited = http.Raw?.VisitedUrls;
            if (visited != null && visited.Count > 0)
            {
                effectiveUrl = visited[visited.Count - 1];
            }
        }
        catch
        {
        }
        effectiveUrl ??= http.Url ?? http.Subject;

        var s = new HttpSection
        {
            Status = http.Status ?? "-",
            IsReachable = http.IsReachable,
            StatusCode = http.StatusCode,
            FailureReason = http.Raw?.FailureReason,
            EffectiveUrl = effectiveUrl,
            Method = http.RequestMethodUsed,
            TlsValidationDisabled = http.TlsValidationDisabled,
            ProxyUsed = http.ProxyUsed,
            HstsPresent = http.HstsPresent,
            Http2Supported = http.Http2Supported,
            Http3Supported = http.Http3Supported,
            CspFrameAncestorsPresent = http.CspFrameAncestorsPresent,
            MissingSecurityHeaderCount = http.MissingSecurityHeaders?.Count ?? 0
        };

        s.Summary.Add(("Status", s.Status));
        s.Summary.Add(("Reachable", s.IsReachable ? "Yes" : "No"));
        s.Summary.Add(("Status Code", s.StatusCode?.ToString() ?? "-"));
        s.Summary.Add(("Method", s.Method.ToString()));
        if (!string.IsNullOrWhiteSpace(s.EffectiveUrl)) s.Summary.Add(("Effective URL", s.EffectiveUrl!));
        if (!string.IsNullOrWhiteSpace(s.ProxyUsed)) s.Summary.Add(("Proxy", s.ProxyUsed!));
        s.Summary.Add(("TLS Validation", s.TlsValidationDisabled ? "Disabled" : "Enabled"));
        s.Summary.Add(("HSTS", s.HstsPresent ? "Present" : "Missing"));
        s.Summary.Add(("HTTP/2", s.Http2Supported ? "Yes" : "No"));
        s.Summary.Add(("HTTP/3", s.Http3Supported ? "Yes" : "No"));
        if (s.CspFrameAncestorsPresent) s.Summary.Add(("CSP frame-ancestors", "Yes"));
        s.Summary.Add(("Missing Security Headers", s.MissingSecurityHeaderCount.ToString()));
        s.Summary.Add(("Info Disclosure Headers", (http.InformationDisclosureHeaders?.Count ?? 0).ToString()));
        s.Summary.Add(("Caching Headers", (http.CachingHeaders?.Count ?? 0).ToString()));

        if (!string.IsNullOrWhiteSpace(s.FailureReason))
        {
            s.Summary.Add(("Failure", s.FailureReason!));
        }

        try
        {
            foreach (var kv in http.Raw?.SecurityHeaders ?? new Dictionary<string, DomainDetective.SecurityHeader>(StringComparer.OrdinalIgnoreCase))
            {
                s.PresentSecurityHeaders.Add(new HttpSection.HeaderRow { Name = kv.Key, Value = kv.Value?.Value ?? string.Empty });
            }
            s.PresentSecurityHeaders.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
        }

        try
        {
            foreach (var miss in http.MissingSecurityHeaders ?? Array.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(miss)) s.MissingSecurityHeaders.Add(miss);
            }
            s.MissingSecurityHeaders.Sort(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
        }

        try
        {
            foreach (var kv in http.InformationDisclosureHeaders ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
            {
                s.InformationDisclosureHeaders.Add(new HttpSection.HeaderRow { Name = kv.Key, Value = kv.Value ?? string.Empty });
            }
            s.InformationDisclosureHeaders.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
        }

        try
        {
            foreach (var kv in http.CachingHeaders ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
            {
                s.CachingHeaders.Add(new HttpSection.HeaderRow { Name = kv.Key, Value = kv.Value ?? string.Empty });
            }
            s.CachingHeaders.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
        }

        try
        {
            foreach (var d in http.DeprecatedHeadersPresent ?? Array.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(d)) s.DeprecatedPresent.Add(d);
            }
            s.DeprecatedPresent.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (var d in http.MissingDeprecatedHeaders ?? Array.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(d)) s.DeprecatedMissing.Add(d);
            }
            s.DeprecatedMissing.Sort(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
        }

        foreach (var a in http.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a != null && a.Severity != DomainDetective.AssessmentSeverity.Info)
                s.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }
        foreach (var p in http.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var tt = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(tt)) s.Positives.Add(tt!);
        }
        foreach (var rr in http.References ?? Array.Empty<string>()) if (!string.IsNullOrWhiteSpace(rr)) s.References.Add(rr);

        return s;
    }

}
