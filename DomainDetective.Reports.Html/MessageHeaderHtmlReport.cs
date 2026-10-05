using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>Offline HTML message report composed from typed HtmlForgeX components.</summary>
public static class MessageHeaderHtmlReport {
    /// <summary>Writes all message evidence without fetching or executing header-supplied resources.</summary>
    public static void Generate(string path, IReadOnlyList<MessageHeaderAnalysis> messages, bool openInBrowser = false) {
        if (messages == null || messages.Count == 0) { throw new ArgumentException("No messages to report.", nameof(messages)); }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        using var document = new Document {
            Head = { Title = "Email Message Analysis", Author = "DomainDetective", Charset = "utf-8" },
            LibraryMode = LibraryMode.OfflineWithFiles,
            ThemeMode = ThemeMode.Light
        };
        document.Head.AddCssInline(TrustedCss.FromTrustedSource("body{color:#203248;background:#f3f6fa}h1{color:#152b45}.card{margin-bottom:1.25rem}.card-body{overflow-x:auto}.table td,.table th{white-space:normal;overflow-wrap:anywhere;vertical-align:top}.table td{min-width:7rem;max-width:42rem}.table th{font-weight:600;color:#526579}.table tbody tr:nth-child(even){background:#f4f7fa}@media print{.card{break-inside:auto}.card-body{overflow:visible}.table{font-size:9pt}}"));
        document.Body.Page(page => {
            page.Layout = TablerLayout.Fluid;
            page.H1("Email Message Analysis");
            for (var i = 0; i < messages.Count; i++) {
                page.H2("Message " + (i + 1));
                var brief = MessageHeaderReportBrief.Build(messages[i]);
                page.Row(row => row.Column(TablerColumnNumber.Twelve, column => column.Card(card => {
                    card.Header(header => header.Title("Executive brief"));
                    card.Body(body => {
                        body.Text(brief.Summary);
                        body.H5("What the evidence establishes");
                        body.AddList(list => list.WithItems(items => { foreach (var line in brief.Evidence) { items.Item(line); } }));
                        body.H5("Priority findings");
                        body.AddList(list => list.WithItems(items => { foreach (var finding in brief.Findings) { items.Item(MessageHeaderReport.VisibleText($"{finding.Severity}: {finding.Message} [{finding.Code}]")); } }));
                        body.H5("Recommended next steps");
                        foreach (var action in brief.Actions) {
                            body.H5(MessageHeaderReport.VisibleText(action.Title));
                            if (!string.IsNullOrWhiteSpace(action.Why)) { body.Text(MessageHeaderReport.VisibleText(action.Why)); }
                            if (!string.IsNullOrWhiteSpace(action.How)) { body.Text("Action: " + MessageHeaderReport.VisibleText(action.How)); }
                            if (!string.IsNullOrWhiteSpace(action.Verify)) { body.Text("Verify: " + MessageHeaderReport.VisibleText(action.Verify)); }
                        }
                        if (brief.Actions.Count == 0) { body.Text("Retain the original MIME message and corroborate receiver claims before making a trust decision."); }
                    });
                })));
                page.H3("Evidence appendix");
                foreach (var section in MessageHeaderReport.Build(messages[i]).Where(section => section.Rows.Count > 0)) {
                    page.Row(row => row.Column(TablerColumnNumber.Twelve, column => column.Card(card => {
                        card.Header(header => header.Title(section.Title));
                        card.Body(body => {
                            var table = body.Table(Array.Empty<object>(), TableType.Tabler);
                            table.AddHeaders(section.Columns.ToArray());
                            foreach (var values in section.Rows) { table.AddRow(values.ToList()); }
                        });
                    })));
                }
            }
        });
        document.Save(path, openInBrowser);
    }
}
