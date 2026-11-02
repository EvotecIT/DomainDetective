using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;

namespace DomainDetective.Reports.Html;

public static partial class AssessmentHtmlReport {
    private static void RenderPageCheck(Content section, CheckAssessment check, DisplayLabels labels) {
        // Collect a check's prose once, even when several input projections reuse its summary.
        var shown = new HashSet<string>(StringComparer.Ordinal);
        string? Unique(string? value) => string.IsNullOrWhiteSpace(value) || !shown.Add(value.Trim()) ? null : value.Trim();
        void Text(Content target, string? value) { if (Unique(value) is { } text) target.Text(text); }
        Text(section, check.Summary ?? check.Description ?? ResultLabel(check.Outcome));
        Text(section, check.Description);
        Text(section, check.LongTitle);
        section.Facts(new Fact { Label = "Result", Value = ResultLabel(check.Outcome), Tone = ResultTone(check.Outcome) },
            new Fact { Label = "Evidence", Value = check.EvidenceComplete ? "Collected" : "Incomplete" },
            new Fact { Label = "Score", Value = check.Scored ? check.Score?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "Not established" : "Not scored" });
        if (check.Metrics.Count > 0) section.Facts(check.Metrics.Select(metric => new Fact { Label = metric.Label,
            Value = metric.Value + (metric.Note == null ? string.Empty : " · " + metric.Note), Tone = metric.State switch {
                MetricState.Good => Tone.Good, MetricState.Warning => Tone.Warning, MetricState.Error => Tone.Bad, _ => Tone.Neutral
            } }).ToArray());
        foreach (var value in check.Positives.Concat(check.Highlights)) Text(section, value);
        if (check.Facts.Count > 0) section.Facts(check.Facts.Select(fact => new Fact { Label = fact.Label, Value = fact.Value }).ToArray());
        if (check.Findings.Count > 0) section.StatusList(check.Findings.Select(finding => new LiveStatus {
            Name = finding.Target ?? check.Title, Status = finding.Message,
            Detail = string.IsNullOrWhiteSpace(finding.Code) ? null : labels.Resolve(finding.Code),
            Tone = finding.Severity switch { AssessmentSeverity.Error => Tone.Bad, AssessmentSeverity.Warning => Tone.Warning, _ => Tone.Neutral }
        }).ToArray());
        foreach (var recommendation in check.Recommendations) section.Panel(recommendation.Title, panel => {
            Text(panel, recommendation.Why);
            Text(panel, recommendation.How);
            var facts = new[] { new Fact { Label = "Verify", Value = recommendation.Verify! },
                new Fact { Label = "Impact", Value = recommendation.Impact! }, new Fact { Label = "Effort", Value = recommendation.Effort! } }
                .Where(fact => !string.IsNullOrWhiteSpace(fact.Value)).ToArray();
            if (facts.Length > 0) panel.Facts(facts);
            foreach (var link in recommendation.Links) {
                if (IsWebLink(link)) panel.Link("Reference", link); else Text(panel, link);
            }
        });
        if (Unique(check.Remediation) is { } remediation) section.Panel("Remediation", panel => panel.Text(remediation));
        if (check.Narrative is { } narrative) {
            var introduction = Unique(narrative.Introduction);
            var why = Unique(narrative.WhyItMatters);
            var details = narrative.Highlights.Concat(narrative.Details).Concat(narrative.Positives).Concat(narrative.Negatives)
                .Select(Unique).Where(value => value != null).ToArray();
            var actions = narrative.Remediations.Select(Unique).Where(value => value != null).ToArray();
            if (introduction != null || why != null || details.Length > 0 || actions.Length > 0 || narrative.References.Count > 0)
                section.Deferred("Detailed guidance", detail => {
                    if (introduction != null) detail.Text(introduction);
                    if (why != null) detail.Panel("Why it matters", panel => panel.Text(why));
                    foreach (var value in details) detail.Text(value!);
                    foreach (var value in actions) detail.Panel("Suggested action", panel => panel.Text(value!));
                    foreach (var reference in narrative.References) {
                        if (IsWebLink(reference)) detail.Link("Reference", reference); else Text(detail, reference);
                    }
                });
        }
        var evidenceBlocks = check.Evidence.Select(block => new { Block = block, Text = Unique(block.Text),
            Items = block.Items.Select(Unique).Where(value => value != null).ToArray() })
            .Where(item => item.Text != null || item.Items.Length > 0 || item.Block.Columns.Count > 0 || item.Block.Omitted > 0).ToArray();
        if (evidenceBlocks.Length > 0) section.Deferred("Supporting evidence", evidence => {
            foreach (var item in evidenceBlocks) evidence.Panel(item.Block.Title, panel => {
                if (item.Text != null) panel.Text(item.Text);
                foreach (var value in item.Items) panel.Text(value!);
                if (item.Block.Columns.Count > 0) panel.Table(item.Block.Rows, columns => {
                    for (int index = 0; index < item.Block.Columns.Count; index++) {
                        int cell = index; columns.Column(item.Block.Columns[index], row => cell < row.Count ? row[cell] : string.Empty);
                    }
                }, item.Block.Title);
                if (item.Block.Omitted > 0) panel.Text(item.Block.Omitted + " entries omitted by the evidence collector.");
            });
        });
        foreach (var reference in check.References) {
            if (IsWebLink(reference)) section.Link("Technical reference", reference); else Text(section, reference);
        }
    }
}
