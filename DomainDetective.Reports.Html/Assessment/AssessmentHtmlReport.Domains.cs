using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using Severity = HtmlForgeX.AssessmentSeverity;

namespace DomainDetective.Reports.Html;

public static partial class AssessmentHtmlReport {
    private static void RenderDomain(AssessmentReportSection section, DomainAssessment domain, CheckIds ids, AssessmentHtmlOptions options, DateTimeOffset generatedAt) {
        int attention = domain.ErrorChecks + domain.WarningChecks;
        section.Key(ids.Domain(domain))
            .NavigationIcon(TablerIconType.World)
            .NavigationDetail(domain.Score.HasValue ? $"{domain.Grade} · {domain.Score}" : null)
            .Count(attention, domain.ErrorChecks > 0 ? Severity.High : attention > 0 ? Severity.Elevated : Severity.Good, "checks need attention");

        // Stable marker for scripts and tests that locate a domain in the report.
        section.Add(new HtmlTag("span").Attribute("data-dd-domain", domain.Domain).Attribute("hidden", "hidden"));

        section.AssessmentScopeHeader(header => {
            header.Eyebrow("Domain")
                .Title(domain.Domain)
                .Description(DomainVerdict(domain) + " " + DomainSummary(domain));
            if (domain.Score.HasValue) header.Chip("Grade " + domain.Grade, GradeSeverity(domain.Score));
            header.Metric("Score", domain.Score?.ToString(CultureInfo.InvariantCulture) ?? "-", GradeSeverity(domain.Score));
            foreach (AreaScore area in domain.Areas.Where(static a => a.Score.HasValue)) {
                header.Metric(AreaLabel(area.Area), area.Score!.Value.ToString(CultureInfo.InvariantCulture), GradeSeverity(area.Score));
            }
        });

        RenderDomainProfile(section, domain, ids, generatedAt);

        section.AssessmentChecks(list => {
            foreach (var area in domain.Checks.GroupBy(static c => c.Area)) {
                int areaAttention = area.Count(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning);
                list.Group(AreaKey(area.Key), AreaLabel(area.Key), areaAttention > 0 ? $"{Plural(areaAttention, "check")} need attention" : null);
            }
            foreach (CheckAssessment check in domain.Checks) {
                list.Check(ids.Check(domain, check), check.Title, row => RenderCheck(row, domain, check, options));
            }
        });
    }

    private static void RenderCheck(AssessmentCheck row, DomainAssessment domain, CheckAssessment check, AssessmentHtmlOptions options) {
        int failed = check.ErrorCount + check.WarningCount;
        row.Category(AreaLabel(check.Area))
            .Status(OutcomeSeverity(check.Outcome), OutcomeLabel(check.Outcome))
            .InGroup(AreaKey(check.Area))
            .ScopeLabel(domain.Domain)
            .SearchTerms(string.Join(" ", new[] { check.Key, check.LongTitle, domain.Domain }.Where(static s => !string.IsNullOrEmpty(s))));
        if (!string.IsNullOrWhiteSpace(check.LongTitle)) row.Subtitle(check.LongTitle!);
        if (check.Scored) row.Meta($"score {check.Score.ToString(CultureInfo.InvariantCulture)}");
        if (failed > 0 || check.Positives.Count > 0) row.Progress(check.Positives.Count, failed);
        if (check.Outcome == CheckOutcome.Error) row.Open();

        string? lead = check.Summary ?? check.Description;
        if (!string.IsNullOrWhiteSpace(lead)) row.Text(lead!);
        if (check.Metrics.Count > 0) {
            row.AssessmentStats(stats => {
                foreach (CheckMetric metric in check.Metrics) stats.Stat(metric.Value, MetricCaption(metric), MetricSeverity(metric.State));
            });
        }

        List<CheckFinding> findings = check.Findings
            .Where(f => options.ShowInfoFindings || f.Severity != AssessmentSeverity.Info)
            .ToList();
        if (findings.Count > 0 || check.Positives.Count > 0) {
            row.AssessmentAssertions(assertions => {
                assertions.Settings(s => s.Labels("Findings", "No findings", "{0} things done well", observed: "Where"));
                foreach (CheckFinding finding in findings) {
                    assertions.Assertion(finding.Message, FindingSeverity(finding.Severity), false, a => {
                        if (!string.IsNullOrWhiteSpace(finding.Target) && !string.Equals(finding.Target, domain.Domain, StringComparison.OrdinalIgnoreCase)) a.Observed(finding.Target);
                        if (!string.IsNullOrWhiteSpace(finding.Code)) a.SeverityLabel(finding.Code);
                    });
                }
                foreach (string positive in check.Positives) {
                    assertions.Assertion(positive, Severity.Good, true);
                }
            });
        }

        RenderGuidance(row, check);
        RenderEvidence(row, check);
    }

    private static string DomainSummary(DomainAssessment domain) {
        if (domain.Checks.Count == 0) return "No checks ran for this domain.";
        var parts = new List<string> { $"{Plural(domain.Checks.Count, "check")} ran" };
        if (domain.ErrorChecks > 0) parts.Add($"{Plural(domain.ErrorChecks, "check")} with errors");
        if (domain.WarningChecks > 0) parts.Add($"{Plural(domain.WarningChecks, "check")} with warnings");
        if (domain.PassedChecks > 0) parts.Add($"{domain.PassedChecks.ToString(CultureInfo.InvariantCulture)} passed");
        return string.Join(", ", parts) + ".";
    }

    /// <summary>
    /// Element ids for domains and checks, unique across the report: <c>example.com</c> with an MX check and a domain
    /// named <c>example.com.mx</c> would otherwise both produce <c>domain-example-com-mx</c>.
    /// </summary>
    private sealed class CheckIds {
        private readonly Dictionary<DomainAssessment, string> _domains = new();
        private readonly Dictionary<CheckAssessment, string> _checks = new();

        public CheckIds(DomainAssessmentReport report) {
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "summary", "about", "domains" };
            string Claim(string baseId) {
                string id = baseId;
                for (int i = 2; !used.Add(id); i++) id = baseId + "-" + i.ToString(CultureInfo.InvariantCulture);
                return id;
            }
            foreach (DomainAssessment domain in report.Domains) _domains[domain] = Claim("domain-" + Slug(domain.Domain));
            foreach (DomainAssessment domain in report.Domains) {
                foreach (CheckAssessment check in domain.Checks) _checks[check] = Claim(_domains[domain] + "-" + Slug(check.Key));
            }
        }

        public string Domain(DomainAssessment domain) => _domains[domain];

        public string Check(DomainAssessment domain, CheckAssessment check) => _checks[check];

        private static string Slug(string value) {
            var chars = value.ToLowerInvariant().Select(static c => char.IsLetterOrDigit(c) && c < 128 ? c : '-').ToArray();
            string slug = new string(chars).Trim('-');
            while (slug.Contains("--")) slug = slug.Replace("--", "-");
            return slug.Length == 0 ? "x" : slug;
        }
    }
}
