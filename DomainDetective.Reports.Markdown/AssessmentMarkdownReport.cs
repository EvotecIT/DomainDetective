using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using OfficeIMO.Markdown;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Markdown;

/// <summary>Renders an assessment for tickets and wikis, with full check details and captured evidence.</summary>
public static partial class AssessmentMarkdownReport {
    /// <summary>Writes a UTF-8 Markdown assessment. Its directory is created if needed.</summary>
    /// <param name="path">Destination Markdown path.</param>
    /// <param name="report">The assessment used by the HTML report.</param>
    /// <param name="options">Optional export settings.</param>
    public static void Generate(string path, DomainAssessmentReport report, AssessmentMarkdownOptions? options = null) {
        if (string.IsNullOrWhiteSpace(path)) { throw new ArgumentException("An output path is required.", nameof(path)); }
        string markdown = Render(report, options);
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, markdown, new UTF8Encoding(false));
    }

    /// <summary>Renders summary, priority actions, areas and every domain's checks as Markdown.</summary>
    /// <param name="report">The assessment, including presentation-ready evidence.</param>
    /// <param name="options">Optional export settings.</param>
    /// <returns>Markdown containing attention tables and an all-checks disclosure per domain.</returns>
    public static string Render(DomainAssessmentReport report, AssessmentMarkdownOptions? options = null) {
        if (report == null) { throw new ArgumentNullException(nameof(report)); }
        options ??= new AssessmentMarkdownOptions();
        if (options.FixFirstCount < 1) { throw new ArgumentOutOfRangeException(nameof(options), "FixFirstCount must be positive."); }
        string domains = report.Domains.Count switch {
            0 => "No domains",
            1 => report.Domains[0].Domain,
            _ => report.Domains.Count.ToString(CultureInfo.InvariantCulture) + " domains"
        };
        using MarkdownDocument document = MarkdownDocument.Create().H1(InlineText("Domain assessment: " + domains));
        document.P(InlineText(Wording.ReportVerdict(report)));
        document.P(InlineText(Wording.ReportVerdictDetail(report)));
        document.P(InlineText("Generated " + Wording.FormatTime(report.GeneratedAtUtc) + " · "
            + (report.Score.HasValue ? report.Grade + " · " + report.Score.Value.ToString(CultureInfo.InvariantCulture) + " / 100" : "Not scored")));
        // The verdict already counts errors and warnings; the note only adds something when there is no overall grade.
        if (!report.Score.HasValue) document.P(InlineText(Wording.ScoreNote(report)));
        WriteActions(document, report, options);
        WriteAreas(document, report);
        foreach (DomainAssessment domain in report.Domains) {
            document.H2(InlineText(domain.Domain));
            document.P(InlineText(Wording.DomainVerdict(domain)));
            document.P(InlineText(domain.Score.HasValue
                ? domain.Grade + " · " + domain.Score.Value.ToString(CultureInfo.InvariantCulture) + " / 100" : "Not scored"));
            document.H3("Needs attention");
            CheckAssessment[] attention = Wording.FixOrder(domain.Checks).ToArray();
            if (attention.Length == 0) { document.P("Nothing needs attention."); }
            else { WriteChecks(document, attention); }
            document.Details("All checks", details => {
                WriteChecks(details, domain.Checks);
                foreach (CheckAssessment check in domain.Checks) { WriteCheckDetails(details, check, options); }
            });
        }
        document.H2("How scoring works");
        AddTable(document, new[] { "Measure", "How it works" }, Wording.ScoringFacts.Select(static fact => new[] { fact.Key, fact.Value }));
        return document.ToMarkdown(new MarkdownSaveOptions { TextEscapingMode = MarkdownTextEscapingMode.LiteralBackslash });
    }

    private static void WriteActions(MarkdownDocument document, DomainAssessmentReport report, AssessmentMarkdownOptions options) {
        document.H2("Do these first");
        var actions = Wording.DoFirstGroups(report).ToList();
        if (actions.Count == 0) {
            document.P("Nothing needs attention.");
            return;
        }
        var list = new OrderedListBlock();
        foreach (var action in actions.Take(options.FixFirstCount)) {
            CheckAssessment check = action.Check;
            var content = new InlineSequence().Bold(InlineText(check.Title))
                .Text(InlineText("(" + action.AffectedDomains + ", " + Wording.DoFirstSource(check) + ", "
                    + Wording.OutcomeLabel(check.Outcome).ToLowerInvariant() + "): " + Wording.DoFirstMessage(check)));
            list.Items.Add(new ListItem(content));
        }
        document.Add(list);
        if (actions.Count > options.FixFirstCount) {
            document.P("First " + options.FixFirstCount.ToString(CultureInfo.InvariantCulture) + " of "
                + actions.Count.ToString(CultureInfo.InvariantCulture) + " actions shown; all checks and findings follow under each domain.");
        }
    }
}
