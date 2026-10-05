using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

/// <summary>Markdown and self-contained HTML rendering of message evidence.</summary>
public static class MessageHeaderMarkdownReport {
    /// <summary>Writes message reports as Markdown, or as HTML using the shared document renderer.</summary>
    public static void Generate(string path, IReadOnlyList<MessageHeaderAnalysis> messages, bool html = false) {
        if (messages == null || messages.Count == 0) { throw new ArgumentException("No messages to report.", nameof(messages)); }
        var document = MarkdownDoc.Create().H1("Email Message Analysis");
        for (var i = 0; i < messages.Count; i++) {
            document.H2("Message " + (i + 1));
            var brief = MessageHeaderReportBrief.Build(messages[i]);
            document.H3("Executive brief").P(MarkdownReportText.Escape(brief.Summary));
            document.H3("What the evidence establishes").Ul(brief.Evidence.Select(MarkdownReportText.Escape).ToArray());
            document.H3("Priority findings").Ul(brief.Findings.Select(a => MarkdownReportText.Escape(MessageHeaderReport.VisibleText($"{a.Severity}: {a.Message} [{a.Code}]"))).ToArray());
            document.H3("Recommended next steps");
            foreach (var action in brief.Actions) {
                document.P(MarkdownReportText.Escape(MessageHeaderReport.VisibleText(action.Title)));
                if (!string.IsNullOrWhiteSpace(action.Why)) { document.P(MarkdownReportText.Escape(MessageHeaderReport.VisibleText(action.Why))); }
                if (!string.IsNullOrWhiteSpace(action.How)) { document.P("Action: " + MarkdownReportText.Escape(MessageHeaderReport.VisibleText(action.How))); }
                if (!string.IsNullOrWhiteSpace(action.Verify)) { document.P("Verify: " + MarkdownReportText.Escape(MessageHeaderReport.VisibleText(action.Verify))); }
            }
            if (brief.Actions.Count == 0) { document.P("Retain the original MIME message and corroborate receiver claims before making a trust decision."); }
            document.H3("Evidence appendix");
            foreach (var section in MessageHeaderReport.Build(messages[i]).Where(section => section.Rows.Count > 0)) {
                document.H3(section.Title).Table(table => table.Headers(section.Columns.ToArray()).Rows(section.Rows.Select(row => (IReadOnlyList<string>)row.Select(MarkdownReportText.Escape).ToArray())));
            }
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        if (html) {
            document.SaveAsHtml(path, new HtmlOptions { Kind = HtmlKind.Document, Style = HtmlStyle.GithubAuto, CssDelivery = CssDelivery.Inline, ThemeToggle = true });
        } else { File.WriteAllText(path, document.ToMarkdown(), Encoding.UTF8); }
    }

}
