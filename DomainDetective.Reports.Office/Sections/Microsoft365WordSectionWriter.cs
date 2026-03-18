using System;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class Microsoft365WordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.Microsoft365TenantInfo info, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (info == null) throw new ArgumentNullException(nameof(info));

        var sec = DomainDetective.Reports.SectionProjectors.BuildMicrosoft365(info);
        if (sec != null)
        {
            Write(doc, headings, baseLevel, sec, info, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Microsoft 365 section could not be projected.");
    }

    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.Microsoft365Section sec,
        DomainDetective.Views.Microsoft365TenantInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Microsoft 365 tenant identity, authentication, workload, and DNS application signals.");

        var summaryRows = sec.Summary.Count > 0
            ? sec.Summary
            : new System.Collections.Generic.List<(string Key, string Value)> { ("Status", sec.Status) };
        var summaryTable = doc.AddTable(summaryRows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < summaryRows.Count; i++)
        {
            summaryTable.Rows[i].Cells[0].AddParagraph(summaryRows[i].Key ?? string.Empty);
            summaryTable.Rows[i].Cells[1].AddParagraph(summaryRows[i].Value ?? string.Empty);
        }

        if (sec.Highlights.Count > 0)
        {
            headings.AddItem("Highlights", baseLevel);
            var highlights = doc.AddList(WordListStyle.Bulleted);
            foreach (var item in sec.Highlights.Where(static item => !string.IsNullOrWhiteSpace(item)))
            {
                highlights.AddItem(item);
            }
        }

        if (sec.Services.Count > 0)
        {
            headings.AddItem("Services", baseLevel);
            var table = doc.AddTable(sec.Services.Count + 1, 4, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Service");
            table.Rows[0].Cells[1].AddParagraph("Status");
            table.Rows[0].Cells[2].AddParagraph("Confidence");
            table.Rows[0].Cells[3].AddParagraph("Evidence");
            for (int i = 0; i < sec.Services.Count; i++)
            {
                var row = sec.Services[i];
                table.Rows[i + 1].Cells[0].AddParagraph(row.Service);
                table.Rows[i + 1].Cells[1].AddParagraph(row.Status);
                table.Rows[i + 1].Cells[2].AddParagraph(row.Confidence);
                table.Rows[i + 1].Cells[3].AddParagraph(row.Evidence);
            }
        }

        if (sec.Domains.Count > 0)
        {
            headings.AddItem("Tenant Domains", baseLevel);
            var table = doc.AddTable(sec.Domains.Count + 1, 4, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Domain");
            table.Rows[0].Cells[1].AddParagraph("Role");
            table.Rows[0].Cells[2].AddParagraph("Confidence");
            table.Rows[0].Cells[3].AddParagraph("Evidence");
            for (int i = 0; i < sec.Domains.Count; i++)
            {
                var row = sec.Domains[i];
                table.Rows[i + 1].Cells[0].AddParagraph(row.Domain);
                table.Rows[i + 1].Cells[1].AddParagraph(row.Role);
                table.Rows[i + 1].Cells[2].AddParagraph(row.Confidence);
                table.Rows[i + 1].Cells[3].AddParagraph(row.Evidence);
            }
        }

        if (sec.Subdomains.Count > 0)
        {
            headings.AddItem("Known Subdomains", baseLevel);
            var take = Math.Min(sec.Subdomains.Count, 100);
            var table = doc.AddTable(take + 1, 3, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Name");
            table.Rows[0].Cells[1].AddParagraph("Role");
            table.Rows[0].Cells[2].AddParagraph("Resolution");
            for (int i = 0; i < take; i++)
            {
                var row = sec.Subdomains[i];
                table.Rows[i + 1].Cells[0].AddParagraph(row.Name);
                table.Rows[i + 1].Cells[1].AddParagraph(row.Role);
                table.Rows[i + 1].Cells[2].AddParagraph(row.Resolution);
            }
            if (sec.Subdomains.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Subdomains.Count} known subdomains.").SetItalic(true);
            }
        }

        if (sec.Applications.Count > 0)
        {
            headings.AddItem("Detected DNS Applications", baseLevel);
            var take = Math.Min(sec.Applications.Count, 100);
            var table = doc.AddTable(take + 1, 5, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Name");
            table.Rows[0].Cells[1].AddParagraph("Category");
            table.Rows[0].Cells[2].AddParagraph("Evidence Kind");
            table.Rows[0].Cells[3].AddParagraph("Confidence");
            table.Rows[0].Cells[4].AddParagraph("Evidence");
            for (int i = 0; i < take; i++)
            {
                var row = sec.Applications[i];
                table.Rows[i + 1].Cells[0].AddParagraph(row.Name);
                table.Rows[i + 1].Cells[1].AddParagraph(row.Category);
                table.Rows[i + 1].Cells[2].AddParagraph(row.EvidenceKind);
                table.Rows[i + 1].Cells[3].AddParagraph(row.Confidence);
                table.Rows[i + 1].Cells[4].AddParagraph(row.Evidence);
            }
            if (sec.Applications.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Applications.Count} detected DNS applications.").SetItalic(true);
            }
        }

        if (sec.Evidence.Count > 0)
        {
            headings.AddItem("Evidence Ledger", baseLevel);
            var take = Math.Min(sec.Evidence.Count, 100);
            var table = doc.AddTable(take + 1, 4, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Label");
            table.Rows[0].Cells[1].AddParagraph("Category");
            table.Rows[0].Cells[2].AddParagraph("Confidence");
            table.Rows[0].Cells[3].AddParagraph("Evidence");
            for (int i = 0; i < take; i++)
            {
                var row = sec.Evidence[i];
                table.Rows[i + 1].Cells[0].AddParagraph(row.Label);
                table.Rows[i + 1].Cells[1].AddParagraph(row.Category);
                table.Rows[i + 1].Cells[2].AddParagraph(row.Confidence);
                table.Rows[i + 1].Cells[3].AddParagraph(row.Evidence);
            }
            if (sec.Evidence.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Evidence.Count} evidence items.").SetItalic(true);
            }
        }

        var findings = sec.Findings;
        if (!showInfoFindings)
        {
            findings = findings.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
        }
        if (findings.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var table = doc.AddTable(findings.Count + 1, 4, WordTableStyle.TableGrid);
            table.Rows[0].Cells[0].AddParagraph("Severity");
            table.Rows[0].Cells[1].AddParagraph("Code");
            table.Rows[0].Cells[2].AddParagraph("Target");
            table.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < findings.Count; i++)
            {
                var row = findings[i];
                table.Rows[i + 1].Cells[0].AddParagraph(row.Severity);
                table.Rows[i + 1].Cells[1].AddParagraph(row.Code);
                table.Rows[i + 1].Cells[2].AddParagraph(row.Target);
                table.Rows[i + 1].Cells[3].AddParagraph(row.Message);
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var references = doc.AddList(WordListStyle.Bulleted);
            foreach (var reference in sec.References.Where(static item => !string.IsNullOrWhiteSpace(item)))
            {
                references.AddItem(reference);
            }
        }
    }
}
