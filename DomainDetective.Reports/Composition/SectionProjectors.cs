using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

public static class SectionProjectors
{
    public sealed class SimpleFinding
    {
        public string Severity { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public SimpleFinding() {}
        public SimpleFinding(string severity, string code, string target, string message) { Severity = severity; Code = code; Target = target; Message = message; }
    }

    public sealed class SpfSection
    {
        public string Status { get; set; } = "-";
        public int DnsLookupsCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        // Extras for parity with Word and richer Excel/HTML
        public string? SpfRecord { get; set; }
        public List<(string Qualifier, string Type, string Value, string Provider)> Mechanisms { get; } = new();
        public int FlattenedUniqueIpCount { get; set; }
        public int FlattenedDuplicateIpCount { get; set; }
        public int FlattenedTokenCount { get; set; }
        public List<(string Title, string Url)> ProviderHelp { get; } = new();
        public List<string> Highlights { get; } = new();
    }

    public sealed class DmarcSection
    {
        public string Status { get; set; } = "-";
        public string Policy { get; set; } = "-";
        public int RuaCount { get; set; }
        public int RufCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        // Extras
        public string? DmarcRecord { get; set; }
        public string? DkimAlignment { get; set; }
        public string? SpfAlignment { get; set; }
        public List<string> MailtoRua { get; } = new();
        public List<string> HttpRua { get; } = new();
        public List<string> MailtoRuf { get; } = new();
        public List<string> HttpRuf { get; } = new();
        public List<string> Highlights { get; } = new();
    }

    public sealed class DkimSection
    {
        public sealed class Row
        {
            public string Selector { get; set; } = string.Empty;
            public string Status { get; set; } = "-";
            public string KeyBits { get; set; } = string.Empty;
            public string Hash { get; set; } = string.Empty;
            public bool Weak { get; set; }
            public string Flags { get; set; } = string.Empty;
            public int? TtlSeconds { get; set; }
            public string Record { get; set; } = string.Empty;
        }
        public List<Row> Rows { get; } = new List<Row>();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        public List<string> Highlights { get; } = new();
    }

    // MX (Mail Exchanger) — compact DTO
    public sealed class MxSection
    {
        public string Status { get; set; } = "-";
        public bool HasBackup { get; set; }
        public bool Ipv6 { get; set; }
        public bool NullMx { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
        public List<string> Records { get; } = new();
        public string? MailTlsSmtp { get; set; }
        public string? MailTlsImap { get; set; }
        public string? MailTlsPop { get; set; }
    }

    // Transport: MTA‑STS
    public sealed class MtastsSection
    {
        public string Status { get; set; } = "-";
        public string Mode { get; set; } = "-";
        public int? MaxAge { get; set; }
        public bool DnsRecordPresent { get; set; }
        public bool PolicyValid { get; set; }
        public bool MxAligned { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Transport: TLS‑RPT
    public sealed class TlsRptSection
    {
        public string Status { get; set; } = "-";
        public int RuaCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Reputation: DNSBL
    public sealed class DnsblSection
    {
        public string Status { get; set; } = "-";
        public int ProvidersChecked { get; set; }
        public int HostsChecked { get; set; }
        public int HostsListed { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // DNS: NS / SOA / CAA / DNSSEC
    public sealed class NsSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class SoaSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class CaaSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class DnssecSection { public string Status { get; set; } = "-"; public bool HasDs { get; set; } public bool Validates { get; set; } public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class DaneSection { public string Status { get; set; } = "-"; public string? TlsaUsage { get; set; } public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }

    // Mail TLS (SMTP/IMAP/POP3)
    public sealed class MailTlsSection
    {
        public sealed class Row { public string Service { get; set; } = string.Empty; public string Status { get; set; } = "-"; public string? Protocol { get; set; } }
        public List<Row> Rows { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    // Other
    public sealed class RpkiSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class ZoneTransferSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }
    public sealed class WildcardSection { public string Status { get; set; } = "-"; public List<(string Key, string Value)> Summary { get; } = new(); public List<SimpleFinding> Findings { get; } = new(); public List<string> Positives { get; } = new(); public List<string> References { get; } = new(); }

    public static SpfSection? BuildSpf(DomainDetective.Views.SpfRecordInfo spf)
    {
        if (spf == null) return null;
        var sec = new SpfSection { DnsLookupsCount = spf.DnsLookupsCount };
        sec.Summary.Add(("Status", spf.Status ?? "-"));
        sec.Summary.Add(("DNS Lookups", spf.DnsLookupsCount.ToString()));
        sec.Summary.Add(("Record Present", spf.SpfRecordExists ? "Yes" : "No"));
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
}
