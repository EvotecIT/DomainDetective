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
            foreach (var section in MessageHeaderReport.Build(messages[i]).Where(section => section.Rows.Count > 0)) {
                document.H3(section.Title).Table(table => table.Headers(section.Columns.ToArray()).Rows(section.Rows.Select(row => (IReadOnlyList<string>)row.Select(EscapeCell).ToArray())));
            }
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        if (html) {
            document.SaveAsHtml(path, new HtmlOptions { Kind = HtmlKind.Document, Style = HtmlStyle.GithubAuto, CssDelivery = CssDelivery.Inline, ThemeToggle = true });
        } else { File.WriteAllText(path, document.ToMarkdown(), Encoding.UTF8); }
    }

    private static string EscapeCell(string value) {
        var text = new StringBuilder();
        foreach (var ch in value) {
            if ("\\`*_{}[]()!|<>".IndexOf(ch) >= 0) { text.Append('\\'); }
            text.Append(ch);
        }
        return text.ToString();
    }
}
