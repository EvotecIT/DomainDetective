using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes a Mail TLS (SMTP/IMAP/POP3) section into Word documents.
/// </summary>
public static class MailTlsWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.MailTlsInfo info, string domain, ReportScope scope, bool showInfoFindings, bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (info == null) throw new ArgumentNullException(nameof(info));

        if (includeNarrative)
        {
            headings.AddItem("Introduction", baseLevel);
            doc.AddParagraph("Mail protocols (SMTP, IMAP, POP3) should negotiate modern TLS with valid certificates. This section summarizes observed TLS posture per server.");
        }

        headings.AddItem("Summary", baseLevel);
        var servers = info.Servers?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Views.MailTlsServerInfo>();
        int valid = servers.Count(s => s.CertificateValid);
        int starttls = servers.Count(s => s.StartTlsAdvertised);
        doc.AddParagraph($"Servers tested: {servers.Count}; STARTTLS advertised: {starttls}; valid certificates: {valid}.");

        // Server matrix
        if (servers.Count > 0)
        {
            headings.AddItem("Servers", baseLevel);
            var cols = new [] { "Server", "STARTTLS", "Protocol", "TLS1.3", "Grade", "CertValid", "HostMatch", "Expires", "CipherSuite" };
            var t = doc.AddTable(servers.Count + 1, cols.Length, WordTableStyle.TableGrid);
            for (int c = 0; c < cols.Length; c++) t.Rows[0].Cells[c].AddParagraph(cols[c]);
            for (int i = 0; i < servers.Count; i++)
            {
                var s = servers[i];
                var r = t.Rows[i + 1].Cells;
                r[0].AddParagraph(s.Key ?? string.Empty);
                r[1].AddParagraph(s.StartTlsAdvertised ? "Yes" : "No");
                r[2].AddParagraph(s.Protocol ?? string.Empty);
                r[3].AddParagraph(s.Tls13Used ? "Yes" : (s.SupportsTls13 ? "Supported" : "No"));
                r[4].AddParagraph(s.Grade.ToString());
                r[5].AddParagraph(s.CertificateValid ? "Yes" : "No");
                r[6].AddParagraph(s.HostnameMatch ? "Yes" : "No");
                r[7].AddParagraph(s.ValidTo.HasValue ? s.ValidTo.Value.ToString("yyyy-MM-dd") : string.Empty);
                r[8].AddParagraph(s.CipherSuite ?? s.CipherAlgorithm ?? string.Empty);
            }
        }

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (info.Positives != null && info.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This service demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in info.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = (info.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assessments.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < assessments.Count; i++)
            {
                var a = assessments[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }

        // References
        if (info.References != null && info.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in info.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}
