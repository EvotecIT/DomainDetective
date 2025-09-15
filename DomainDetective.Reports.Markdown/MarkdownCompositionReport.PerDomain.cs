using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

public static partial class MarkdownCompositionReport
{
    // Extracted per-domain writer to keep the core file lean and under 500 lines.
    private static void WritePerDomain(MarkdownDoc md, List<KeyValuePair<string, DomainBucket>> domains)
    {
        foreach (var kv in domains)
        {
            var d = kv.Key; var b = kv.Value;
            md.H1(d).H2("Overview").Table(t => t.Headers("Key","Value")
                .Row("Domain", d)
                .Row("Classification", b.Classification?.Classification ?? "-")
                .Row("Confidence", b.Classification?.Confidence ?? "-")
                .Row("Status", ComputeStatus(b))
                .Row("Warnings", ((b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount)).ToString())
                .Row("Errors", ((b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount)).ToString())
                .AlignLeft(0,1));

            if (b.Classification != null && b.Classification.ScoreBreakdown != null && b.Classification.ScoreBreakdown.Count > 0)
            {
                md.H2("Score Breakdown").Table(t => t.Headers("Metric","Value")
                    .Rows(b.Classification.ScoreBreakdown.Select(kv2 => (IReadOnlyList<string>)new[]{ kv2.Key, kv2.Value.ToString("0.##") }))
                    .AlignLeft(0).AlignRight(1));
            }

            if (b.Classification?.Recommendations?.Count > 0)
                md.H2("Recommendations").Ul(b.Classification.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
            if (b.Classification?.Positives?.Count > 0)
                md.H2("Positives").Ul(b.Classification.Positives.Select(r => r.Title ?? r.Code).ToArray());
            if (b.Classification?.References?.Count > 0)
            {
                md.H2("References");
                md.Ul(ul => { foreach (var u in b.Classification.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } });
            }

            // SPF
            if (b.Spf != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildSpf(b.Spf);
                md.H2("SPF");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var spfFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (spfFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(spfFind).AlignLeft(0,1,2,3));
                    if (!string.IsNullOrWhiteSpace(sec.SpfRecord)) { md.H3("Evidence").P("SPF Record:"); md.Code("", sec.SpfRecord!); }
                    if (sec.Mechanisms.Count > 0) { md.H3("Mechanisms"); var mechRows = sec.Mechanisms.Select(m => (IReadOnlyList<string>)new[]{ m.Qualifier, m.Type, m.Value, m.Provider }).ToList(); md.Table(t => t.Headers("Qualifier","Type","Value","Provider").Rows(mechRows).AlignLeft(0,1,2,3)); }
                    if (sec.FlattenedUniqueIpCount + sec.FlattenedDuplicateIpCount + sec.FlattenedTokenCount > 0) { md.H3("Flattened IP Analysis"); md.Table(t => t.Headers("Metric","Value").Row("Unique IPs", sec.FlattenedUniqueIpCount.ToString()).Row("Duplicate IPs", sec.FlattenedDuplicateIpCount.ToString()).Row("Tokens Resolved", sec.FlattenedTokenCount.ToString()).AlignLeft(0,1)); }
                    if (sec.ProviderHelp.Count > 0) { md.H3("Provider Help"); md.Ul(ul => { foreach (var (title, url) in sec.ProviderHelp.Take(5)) ul.ItemLink(title, url); }); }
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // DMARC
            if (b.Dmarc != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildDmarc(b.Dmarc);
                md.H2("DMARC");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dmFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dmFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dmFind).AlignLeft(0,1,2,3));
                    if (!string.IsNullOrWhiteSpace(sec.DmarcRecord)) { md.H3("Evidence").P("DMARC Record:"); md.Code("", sec.DmarcRecord!); }
                    if (sec.MailtoRua.Count + sec.HttpRua.Count + sec.MailtoRuf.Count + sec.HttpRuf.Count > 0) { md.H3("Reporting URIs"); if (sec.MailtoRua.Count + sec.HttpRua.Count > 0) { md.H4("Aggregate (RUA)"); var rowsRua = sec.MailtoRua.Select(x => (IReadOnlyList<string>)new[]{ "mailto", x }).Concat(sec.HttpRua.Select(x => (IReadOnlyList<string>)new[]{ "http", x })).ToList(); md.Table(t => t.Headers("Scheme","URI").Rows(rowsRua).AlignLeft(0,1)); } if (sec.MailtoRuf.Count + sec.HttpRuf.Count > 0) { md.H4("Forensic (RUF)"); var rowsRuf = sec.MailtoRuf.Select(x => (IReadOnlyList<string>)new[]{ "mailto", x }).Concat(sec.HttpRuf.Select(x => (IReadOnlyList<string>)new[]{ "http", x })).ToList(); md.Table(t => t.Headers("Scheme","URI").Rows(rowsRuf).AlignLeft(0,1)); } }
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // DKIM
            if (b.Dkim.Count > 0)
            {
                md.H2("DKIM");
                var sec = DomainDetective.Reports.SectionProjectors.BuildDkim(b.Dkim, b.Ttl);
                if (sec != null)
                {
                    if (sec.Rows.Count > 0) { var dkimRows = sec.Rows.Select(x => (IReadOnlyList<string>)new[]{ x.Selector, x.Status, x.KeyBits, x.Hash, x.Weak ? "Yes" : "No", x.Flags, (x.TtlSeconds?.ToString() ?? "-") }).ToList(); md.Table(t => t.Headers("Selector","Status","Key Bits","Alg","Weak","Flags","TTL (s)").Rows(dkimRows).AlignLeft(0,1,2,3,4,5,6)); }
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dkFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dkFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dkFind).AlignLeft(0,1,2,3));
                    if (sec.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record))) { md.H3("Evidence"); foreach (var r in sec.Rows.Where(r => !string.IsNullOrWhiteSpace(r.Record))) { md.H4($"Selector {r.Selector}"); md.Code("", r.Record); } }
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // MX
            if (b.Mx != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildMx(b.Mx, b.SmtpTls, b.ImapTls, b.PopTls);
                md.H2("MX");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Records.Count > 0) { md.H3("MX Records"); md.Table(tt => { tt.Headers("Host"); foreach (var r2 in sec.Records) tt.Row(r2); tt.AlignLeft(0); }); }
                    if (!string.IsNullOrWhiteSpace(sec.MailTlsSmtp) || !string.IsNullOrWhiteSpace(sec.MailTlsImap) || !string.IsNullOrWhiteSpace(sec.MailTlsPop)) { md.H3("MailTLS"); md.Table(t => t.Headers("Service","Status").Row("SMTP", sec.MailTlsSmtp ?? "-").Row("IMAP", sec.MailTlsImap ?? "-").Row("POP3", sec.MailTlsPop ?? "-").AlignLeft(0,1)); }
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var mxFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mxFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mxFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // MTA-STS
            if (b.Mtasts != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildMtasts(b.Mtasts);
                md.H2("MTA-STS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var mtFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mtFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mtFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // TLS-RPT
            if (b.TlsRpt != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildTlsRpt(b.TlsRpt);
                md.H2("TLS-RPT");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var trFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (trFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(trFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // MailTLS condensed summary table
            if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
            {
                md.H2("MailTLS");
                IEnumerable<(string Service, DomainDetective.Views.MailTlsInfo Info)> svc() { if (b.SmtpTls != null) yield return ("SMTP", b.SmtpTls); if (b.ImapTls != null) yield return ("IMAP", b.ImapTls); if (b.PopTls != null) yield return ("POP3", b.PopTls); }
                var rows = new List<IReadOnlyList<string>>();
                foreach (var (service, info) in svc())
                {
                    var servers = info.Servers ?? Array.Empty<DomainDetective.Views.MailTlsServerInfo>();
                    int n = servers.Count;
                    int starttls = servers.Count(s => s.StartTlsAdvertised);
                    int tls13 = servers.Count(s => s.Tls13Used || s.SupportsTls13);
                    int expSoon = servers.Count(s => s.DaysToExpire <= 30);
                    int a = servers.Count(s => s.Grade.ToString() == "A");
                    int bbb = servers.Count(s => s.Grade.ToString() == "B");
                    int ccc = servers.Count(s => s.Grade.ToString() == "C");
                    int ddd = servers.Count(s => s.Grade.ToString() == "D");
                    int fff = servers.Count(s => s.Grade.ToString() == "F");
                    rows.Add(new [] { service, info.Status ?? "-", n.ToString(), starttls.ToString(), tls13.ToString(), a.ToString(), bbb.ToString(), ccc.ToString(), ddd.ToString(), fff.ToString(), expSoon.ToString() });
                }
                if (rows.Count > 0)
                {
                    md.Table(t => t.Headers("Service","Status","Servers","StartTLS","TLS 1.3","A","B","C","D","F","Exp<=30d").Rows(rows).AlignLeft(0,1).AlignCenter(2,3,4,5,6,7,8,9,10));
                }
            }

            // DNSBL
            if (b.Dnsbl != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildDnsbl(b.Dnsbl);
                md.H2("DNSBL");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Findings.Count > 0)
                    {
                        var dnsblRows = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsblRows).AlignLeft(0,1,2,3));
                    }
                    var listed = b.Dnsbl.ListedRecords?.Select(r => (IReadOnlyList<string>)new[]{ r.SourceHost ?? r.IpAddress ?? "", r.BlackList ?? "", r.ReplyMeaning ?? "" }).ToList() ?? new List<IReadOnlyList<string>>();
                    if (listed.Count > 0) md.H3("Listed Records").Table(t => t.Headers("Host","Blacklist","Reason").Rows(listed).AlignLeft(0,1,2));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // NS
            if (b.Ns != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildNs(b.Ns);
                md.H2("NS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var nsFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (nsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(nsFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // SOA
            if (b.Soa != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildSoa(b.Soa);
                md.H2("SOA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var soaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (soaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(soaFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = DomainDetective.Reports.LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            // CAA
            if (b.Caa != null)
            {
                var sec = DomainDetective.Reports.SectionProjectors.BuildCaa(b.Caa);
                md.H2("CAA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var caaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (caaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(caaFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) ul.ItemLink(u, u); }); }
                }
            }

            // DNSSEC/DANE
            if (b.Dnssec != null || b.Dane != null)
            {
                md.H2("DNSSEC/DANE");
                if (b.Dnssec != null)
                {
                    var dsec = DomainDetective.Reports.SectionProjectors.BuildDnssec(b.Dnssec);
                    if (dsec != null)
                    {
                        md.H3("DNSSEC");
                        md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dsec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                        if (dsec.Positives.Count > 0) md.H4("Positives").Ul(dsec.Positives.ToArray());
                        var dnsFind = dsec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        if (dnsFind.Count > 0) md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsFind));
                    }
                }
                if (b.Dane != null)
                {
                    var dasec = DomainDetective.Reports.SectionProjectors.BuildDane(b.Dane);
                    if (dasec != null)
                    {
                        md.H3("DANE");
                        md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dasec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                        var daFind = dasec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                        if (daFind.Count > 0) md.H4("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(daFind));
                    }
                }
            }
        }
    }
}

