using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class MailTlsWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Views.MailTlsInfo? smtp,
        DomainDetective.Views.MailTlsInfo? imap,
        DomainDetective.Views.MailTlsInfo? pop,
        DomainDetective.Reports.ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (smtp == null && imap == null && pop == null)
        {
            doc.AddParagraph("No MailTLS data.").SetItalic(true);
            return;
        }

        void WriteService(string title, DomainDetective.Views.MailTlsInfo? info)
        {
            if (info == null) return;
            headings.AddItem(title, baseLevel);
            // Condensed summary row
            var grid = doc.AddTable(1, 3, WordTableStyle.TableGrid);
            grid.Rows[0].Cells[0].AddParagraph("Status"); grid.Rows[0].Cells[1].AddParagraph(info.Status ?? "-"); grid.Rows[0].Cells[2].AddParagraph(info.Summary ?? string.Empty);

            if (scope == DomainDetective.Reports.ReportScope.Detailed)
            {
                // Detailed per-server table
                var servers = (info.Servers != null) ? info.Servers.ToArray() : System.Array.Empty<DomainDetective.Views.MailTlsServerInfo>();
                if (servers.Length > 0)
                {
                    var t = doc.AddTable(servers.Length + 1, 10, WordTableStyle.TableGrid);
                    string[] headers = { "Host","StartTLS","Grade","Protocol","TLS 1.3","CertValid","ChainValid","Hostname","Cipher","DaysToExpire" };
                    for (int i = 0; i < headers.Length; i++) t.Rows[0].Cells[i].AddParagraph(headers[i]);
                    for (int i = 0; i < servers.Length; i++)
                    {
                        var s = servers[i];
                        t.Rows[i + 1].Cells[0].AddParagraph(s.Key ?? string.Empty);
                        t.Rows[i + 1].Cells[1].AddParagraph(s.StartTlsAdvertised ? "Yes" : "No");
                        t.Rows[i + 1].Cells[2].AddParagraph(s.Grade.ToString());
                        t.Rows[i + 1].Cells[3].AddParagraph(s.Protocol ?? string.Empty);
                        t.Rows[i + 1].Cells[4].AddParagraph(s.Tls13Used ? "Yes" : (s.SupportsTls13 ? "Supported" : "No"));
                        t.Rows[i + 1].Cells[5].AddParagraph(s.CertificateValid ? "Yes" : "No");
                        t.Rows[i + 1].Cells[6].AddParagraph(s.ChainValid ? "Yes" : "No");
                        t.Rows[i + 1].Cells[7].AddParagraph(s.HostnameMatch ? "Yes" : "No");
                        t.Rows[i + 1].Cells[8].AddParagraph(s.CipherSuite ?? s.CipherAlgorithm ?? string.Empty);
                        t.Rows[i + 1].Cells[9].AddParagraph(s.DaysToExpire.ToString());
                    }
                }
            }

            // Findings (optionally hide Info)
            var assessAll = info.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
            var assess = showInfoFindings ? assessAll : assessAll.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
            if (assess.Count > 0)
            {
                var ft = doc.AddTable(assess.Count + 1, 4, WordTableStyle.TableGrid);
                ft.Rows[0].Cells[0].AddParagraph("Severity");
                ft.Rows[0].Cells[1].AddParagraph("Code");
                ft.Rows[0].Cells[2].AddParagraph("Target");
                ft.Rows[0].Cells[3].AddParagraph("Message");
                for (int i = 0; i < assess.Count; i++)
                {
                    var a = assess[i];
                    ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                    ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                    ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                    ft.Rows[i + 1].Cells[3].AddParagraph(a.Message ?? string.Empty);
                }
            }
        }

        WriteService("SMTP", smtp);
        WriteService("IMAP", imap);
        WriteService("POP3", pop);
    }
}
