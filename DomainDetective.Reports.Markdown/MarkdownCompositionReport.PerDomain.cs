using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

public static partial class MarkdownCompositionReport
{
    // Extracted per-domain writer to keep the core file lean and under 500 lines.
    private static void WritePerDomain(MarkdownDoc md, List<KeyValuePair<string, DomainBucket>> domains, OrderingOptions? ordering, Dictionary<string, List<string>> inputSectionOrder)
    {
        var mode = ordering?.SectionOrderMode ?? SectionOrderMode.Canonical;
        var custom = SectionOrdering.NormalizeSectionList(ordering?.SectionOrder ?? Array.Empty<string>());

        foreach (var kv in domains)
        {
            var d = kv.Key;
            var b = kv.Value;
            md.H1(d).H2("Overview").Table(t => t.Headers("Key","Value")
                .Row("Domain", d)
                .Row("Classification", b.Classification?.Classification ?? "-")
                .Row("Confidence", b.Classification?.Confidence ?? "-")
                .Row("Status", ComputeStatus(b))
                .Row("Warnings", ((b.Mx?.WarningCount ?? 0) + (b.Spf?.WarningCount ?? 0) + (b.Dmarc?.WarningCount ?? 0) + (b.Mtasts?.WarningCount ?? 0) + (b.TlsRpt?.WarningCount ?? 0) + b.Dkim.Sum(x => x.WarningCount)).ToString())
                .Row("Errors", ((b.Mx?.ErrorCount ?? 0) + (b.Spf?.ErrorCount ?? 0) + (b.Dmarc?.ErrorCount ?? 0) + (b.Mtasts?.ErrorCount ?? 0) + (b.TlsRpt?.ErrorCount ?? 0) + b.Dkim.Sum(x => x.ErrorCount)).ToString())
                .AlignLeft(0,1));

            void RenderClassification()
            {
                var cls = b.Classification;
                if (cls == null) return;
                md.H2("Classification");
                md.Table(t => t.Headers("Key","Value")
                    .Row("Classification", cls.Classification ?? "-")
                    .Row("Confidence", cls.Confidence ?? "-")
                    .Row("Score", cls.Score.ToString("0.##"))
                    .Row("Status", cls.Status ?? "-")
                    .Row("Primary Provider", cls.ProviderPrimary ?? "-")
                    .Row("Gateways", cls.ProviderGateways != null && cls.ProviderGateways.Count > 0 ? string.Join(", ", cls.ProviderGateways) : "-")
                    .Row("Outbound", cls.ProviderOutbound != null && cls.ProviderOutbound.Count > 0 ? string.Join(", ", cls.ProviderOutbound) : "-")
                    .AlignLeft(0,1));

                if (cls.ScoreBreakdown != null && cls.ScoreBreakdown.Count > 0)
                {
                    md.H3("Score Breakdown").Table(t => t.Headers("Metric","Value")
                        .Rows(cls.ScoreBreakdown.Select(kv2 => (IReadOnlyList<string>)new[]{ kv2.Key, kv2.Value.ToString("0.##") }))
                        .AlignLeft(0).AlignRight(1));
                }

                if (cls.Recommendations?.Count > 0)
                    md.H3("Recommendations").Ul(cls.Recommendations.Select(r => r.Title ?? r.Code).ToArray());
                if (cls.Positives?.Count > 0)
                    md.H3("Positives").Ul(cls.Positives.Select(r => r.Title ?? r.Code).ToArray());
                if (cls.References?.Count > 0)
                {
                    md.H3("References");
                    md.Ul(ul => { foreach (var u in cls.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } });
                }
            }

            void RenderSpf()
            {
                if (b.Spf == null) return;
                var sec = SectionProjectors.BuildSpf(b.Spf);
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
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderDmarc()
            {
                if (b.Dmarc == null) return;
                var sec = SectionProjectors.BuildDmarc(b.Dmarc);
                md.H2("DMARC");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dmFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dmFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dmFind).AlignLeft(0,1,2,3));
                    if (!string.IsNullOrWhiteSpace(sec.DmarcRecord)) { md.H3("Evidence").P("DMARC Record:"); md.Code("", sec.DmarcRecord!); }
                    if (sec.MailtoRua.Count + sec.HttpRua.Count + sec.MailtoRuf.Count + sec.HttpRuf.Count > 0)
                    {
                        md.H3("Reporting URIs");
                        if (sec.MailtoRua.Count + sec.HttpRua.Count > 0)
                        {
                            md.H4("Aggregate (RUA)");
                            var rowsRua = sec.MailtoRua.Select(x => (IReadOnlyList<string>)new[]{ "mailto", x }).Concat(sec.HttpRua.Select(x => (IReadOnlyList<string>)new[]{ "http", x })).ToList();
                            md.Table(t => t.Headers("Scheme","URI").Rows(rowsRua).AlignLeft(0,1));
                        }
                        if (sec.MailtoRuf.Count + sec.HttpRuf.Count > 0)
                        {
                            md.H4("Forensic (RUF)");
                            var rowsRuf = sec.MailtoRuf.Select(x => (IReadOnlyList<string>)new[]{ "mailto", x }).Concat(sec.HttpRuf.Select(x => (IReadOnlyList<string>)new[]{ "http", x })).ToList();
                            md.Table(t => t.Headers("Scheme","URI").Rows(rowsRuf).AlignLeft(0,1));
                        }
                    }
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderDkim()
            {
                if (b.Dkim.Count == 0) return;
                md.H2("DKIM");
                var sec = SectionProjectors.BuildDkim(b.Dkim, b.Ttl);
                if (sec != null)
                {
                    if (sec.Rows.Count > 0) { var dkimRows = sec.Rows.Select(x => (IReadOnlyList<string>)new[]{ x.Selector, x.Status, x.KeyBits, x.Hash, x.Weak ? "Yes" : "No", x.Flags, (x.TtlSeconds?.ToString() ?? "-") }).ToList(); md.Table(t => t.Headers("Selector","Status","Key Bits","Alg","Weak","Flags","TTL (s)").Rows(dkimRows).AlignLeft(0,1,2,3,4,5,6)); }
                    if (sec.Highlights.Count > 0) md.H3("Highlights").Ul(sec.Highlights.ToArray());
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var dkFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dkFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dkFind).AlignLeft(0,1,2,3));
                    if (sec.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record))) { md.H3("Evidence"); foreach (var r in sec.Rows.Where(r => !string.IsNullOrWhiteSpace(r.Record))) { md.H4($"Selector {r.Selector}"); md.Code("", r.Record); } }
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderMx()
            {
                if (b.Mx == null) return;
                var sec = SectionProjectors.BuildMx(b.Mx, b.SmtpTls, b.ImapTls, b.PopTls);
                md.H2("MX");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Records.Count > 0) { md.H3("MX Records"); md.Table(tt => { tt.Headers("Host"); foreach (var r2 in sec.Records) tt.Row(r2); tt.AlignLeft(0); }); }
                    if (!string.IsNullOrWhiteSpace(sec.MailTlsSmtp) || !string.IsNullOrWhiteSpace(sec.MailTlsImap) || !string.IsNullOrWhiteSpace(sec.MailTlsPop)) { md.H3("MailTLS"); md.Table(t => t.Headers("Service","Status").Row("SMTP", sec.MailTlsSmtp ?? "-").Row("IMAP", sec.MailTlsImap ?? "-").Row("POP3", sec.MailTlsPop ?? "-").AlignLeft(0,1)); }
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var mxFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mxFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mxFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderMtasts()
            {
                if (b.Mtasts == null) return;
                var sec = SectionProjectors.BuildMtasts(b.Mtasts);
                md.H2("MTA-STS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var mtFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (mtFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(mtFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderTlsRpt()
            {
                if (b.TlsRpt == null) return;
                var sec = SectionProjectors.BuildTlsRpt(b.TlsRpt);
                md.H2("TLS-RPT");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var trFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (trFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(trFind).AlignLeft(0,1,2,3));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderMailTls()
            {
                if (b.SmtpTls == null && b.ImapTls == null && b.PopTls == null) return;
                md.H2("MailTLS");
                IEnumerable<(string Service, DomainDetective.Views.MailTlsInfo Info)> svc()
                {
                    if (b.SmtpTls != null) yield return ("SMTP", b.SmtpTls);
                    if (b.ImapTls != null) yield return ("IMAP", b.ImapTls);
                    if (b.PopTls != null) yield return ("POP3", b.PopTls);
                }
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
                    rows.Add(new[] { service, info.Status ?? "-", n.ToString(), starttls.ToString(), tls13.ToString(), a.ToString(), bbb.ToString(), ccc.ToString(), ddd.ToString(), fff.ToString(), expSoon.ToString() });
                }
                if (rows.Count > 0)
                {
                    md.Table(t => t.Headers("Service","Status","Servers","StartTLS","TLS 1.3","A","B","C","D","F","Exp<=30d").Rows(rows).AlignLeft(0,1).AlignCenter(2,3,4,5,6,7,8,9,10));
                }
            }

            void RenderDnsbl()
            {
                if (b.Dnsbl == null) return;
                var sec = SectionProjectors.BuildDnsbl(b.Dnsbl);
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
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderNs()
            {
                if (b.Ns == null) return;
                var sec = SectionProjectors.BuildNs(b.Ns);
                md.H2("NS");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var nsFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (nsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(nsFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderSoa()
            {
                if (b.Soa == null) return;
                var sec = SectionProjectors.BuildSoa(b.Soa);
                md.H2("SOA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var soaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (soaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(soaFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderCaa()
            {
                if (b.Caa == null) return;
                var sec = SectionProjectors.BuildCaa(b.Caa);
                md.H2("CAA");
                if (sec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in sec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (sec.Positives.Count > 0) md.H3("Positives").Ul(sec.Positives.ToArray());
                    var caaFind = sec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (caaFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(caaFind));
                    if (sec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in sec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderDnssec()
            {
                if (b.Dnssec == null) return;
                var dsec = SectionProjectors.BuildDnssec(b.Dnssec);
                md.H2("DNSSEC");
                if (dsec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dsec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    if (dsec.Positives.Count > 0) md.H3("Positives").Ul(dsec.Positives.ToArray());
                    var dnsFind = dsec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (dnsFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(dnsFind));
                    if (dsec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in dsec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            void RenderDane()
            {
                if (b.Dane == null) return;
                var dasec = SectionProjectors.BuildDane(b.Dane);
                md.H2("DANE");
                if (dasec != null)
                {
                    md.Table(t => { t.Headers("Key","Value"); foreach (var kv2 in dasec.Summary) t.Row(kv2.Key, kv2.Value); t.AlignLeft(0,1); });
                    var daFind = dasec.Findings.Select(a => (IReadOnlyList<string>)new[]{ a.Severity, a.Code, a.Target, a.Message }).ToList();
                    if (daFind.Count > 0) md.H3("Findings").Table(t => t.Headers("Severity","Code","Target","Message").Rows(daFind));
                    if (dasec.References.Count > 0) { md.H3("References"); md.Ul(ul => { foreach (var u in dasec.References) { var f = LinkFormatter.Format(u); ul.ItemLink(f.Title, f.Url); } }); }
                }
            }

            var present = GetPresentSections(b);
            var input = inputSectionOrder.TryGetValue(d, out var list) ? list : null;
            var order = SectionOrdering.ResolveOrder(mode, present, input, custom);
            foreach (var section in order)
            {
                switch (section)
                {
                    case "Classification":
                        RenderClassification();
                        break;
                    case "SPF":
                        RenderSpf();
                        break;
                    case "DMARC":
                        RenderDmarc();
                        break;
                    case "DKIM":
                        RenderDkim();
                        break;
                    case "MX":
                        RenderMx();
                        break;
                    case "MTA-STS":
                        RenderMtasts();
                        break;
                    case "TLS-RPT":
                        RenderTlsRpt();
                        break;
                    case "MAILTLS":
                        RenderMailTls();
                        break;
                    case "DNSBL":
                        RenderDnsbl();
                        break;
                    case "NS":
                        RenderNs();
                        break;
                    case "SOA":
                        RenderSoa();
                        break;
                    case "CAA":
                        RenderCaa();
                        break;
                    case "DNSSEC":
                        RenderDnssec();
                        break;
                    case "DANE":
                        RenderDane();
                        break;
                }
            }
        }
    }

    private static IReadOnlyList<string> GetPresentSections(DomainBucket b)
    {
        var list = new List<string>();
        if (b.Classification != null) list.Add("Classification");
        if (b.Spf != null) list.Add("SPF");
        if (b.Dmarc != null) list.Add("DMARC");
        if (b.Dkim.Count > 0) list.Add("DKIM");
        if (b.Mx != null) list.Add("MX");
        if (b.Mtasts != null) list.Add("MTA-STS");
        if (b.TlsRpt != null) list.Add("TLS-RPT");
        if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null) list.Add("MAILTLS");
        if (b.Dnsbl != null) list.Add("DNSBL");
        if (b.Ns != null) list.Add("NS");
        if (b.Soa != null) list.Add("SOA");
        if (b.Caa != null) list.Add("CAA");
        if (b.Dnssec != null) list.Add("DNSSEC");
        if (b.Dane != null) list.Add("DANE");
        return list;
    }
}
