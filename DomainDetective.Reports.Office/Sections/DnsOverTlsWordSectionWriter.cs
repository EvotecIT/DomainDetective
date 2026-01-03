using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class DnsOverTlsWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DnsOverTlsSummary dot, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (dot == null) throw new ArgumentNullException(nameof(dot));

        var dto = DomainDetective.Reports.SectionProjectors.BuildDnsOverTls(dot);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, dot, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DNS over TLS section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DnsOverTlsSection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.DnsOverTlsSection sec,
        DomainDetective.Views.DnsOverTlsSummary? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Probe of authoritative name servers for DNS over TLS (DoT, TCP/853) support and TLS certificate posture.");

        var rows = sec.Summary.Count > 0
            ? sec.Summary
            : new System.Collections.Generic.List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        if (sec.Endpoints.Count > 0)
        {
            headings.AddItem("Endpoints", baseLevel);
            int take = Math.Min(sec.Endpoints.Count, 200);
            var et = doc.AddTable(take + 1, 9, WordTableStyle.TableGrid);
            et.Rows[0].Cells[0].AddParagraph("Name Server");
            et.Rows[0].Cells[1].AddParagraph("IP");
            et.Rows[0].Cells[2].AddParagraph("Port");
            et.Rows[0].Cells[3].AddParagraph("Supported");
            et.Rows[0].Cells[4].AddParagraph("Protocol");
            et.Rows[0].Cells[5].AddParagraph("Cipher Suite");
            et.Rows[0].Cells[6].AddParagraph("Hostname Match");
            et.Rows[0].Cells[7].AddParagraph("Cert Valid");
            et.Rows[0].Cells[8].AddParagraph("Error");

            static string YesNo(bool v) => v ? "Yes" : "No";

            for (int i = 0; i < take; i++)
            {
                var r = sec.Endpoints[i];
                et.Rows[i + 1].Cells[0].AddParagraph(string.IsNullOrWhiteSpace(r.NameServerHost) ? "-" : r.NameServerHost);
                et.Rows[i + 1].Cells[1].AddParagraph(string.IsNullOrWhiteSpace(r.ServerIp) ? "-" : r.ServerIp);
                et.Rows[i + 1].Cells[2].AddParagraph(r.Port.ToString());
                et.Rows[i + 1].Cells[3].AddParagraph(YesNo(r.Supported));
                et.Rows[i + 1].Cells[4].AddParagraph(string.IsNullOrWhiteSpace(r.Protocol) ? "-" : r.Protocol);
                et.Rows[i + 1].Cells[5].AddParagraph(string.IsNullOrWhiteSpace(r.CipherSuite) ? "-" : r.CipherSuite);
                et.Rows[i + 1].Cells[6].AddParagraph(string.IsNullOrWhiteSpace(r.HostnameMatch) ? "-" : r.HostnameMatch);
                et.Rows[i + 1].Cells[7].AddParagraph(string.IsNullOrWhiteSpace(r.CertificateValid) ? "-" : r.CertificateValid);
                et.Rows[i + 1].Cells[8].AddParagraph(string.IsNullOrWhiteSpace(r.Error) ? "-" : r.Error);
            }

            if (sec.Endpoints.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Endpoints.Count} endpoint(s).").SetItalic(true);
            }
        }

        if (sec.Findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var f = sec.Findings;
            if (!showInfoFindings)
            {
                f = f.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
            }
            if (f.Count > 0)
            {
                var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
                ft.Rows[0].Cells[0].AddParagraph("Severity");
                ft.Rows[0].Cells[1].AddParagraph("Code");
                ft.Rows[0].Cells[2].AddParagraph("Target");
                ft.Rows[0].Cells[3].AddParagraph("Message");
                for (int i = 0; i < f.Count; i++)
                {
                    var a = f[i];
                    ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity);
                    ft.Rows[i + 1].Cells[1].AddParagraph(a.Code);
                    ft.Rows[i + 1].Cells[2].AddParagraph(a.Target);
                    ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
                }
            }
        }

        if (sec.Positives.Count > 0)
        {
            headings.AddItem("Positives", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in sec.Positives.Where(x => !string.IsNullOrWhiteSpace(x)).Take(25))
            {
                list.AddItem(p);
            }
            if (sec.Positives.Count > 25)
            {
                doc.AddParagraph($"+{sec.Positives.Count - 25} more positive signal(s).").SetItalic(true);
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in sec.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}

