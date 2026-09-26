using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Options for <see cref="DomainAssessmentBuilder"/>.</summary>
public sealed class DomainAssessmentOptions {
    /// <summary>Report title.</summary>
    public string? Title { get; set; }

    /// <summary>Domain order: alphabetical (default) or order of first appearance in the input.</summary>
    public DomainOrder DomainOrder { get; set; } = DomainOrder.Alphabetical;

    /// <summary>Maximum rows or items kept per evidence block. Defaults to 500.</summary>
    public int MaxEvidenceRows { get; set; } = 500;

    /// <summary>Time recorded as the generation time. Defaults to now.</summary>
    public DateTimeOffset? GeneratedAtUtc { get; set; }

    /// <summary>
    /// Skips inputs that do not name a domain instead of listing them in
    /// <see cref="DomainAssessmentReport.UnassignedInputs"/>. Useful when converting every check of a health check,
    /// where checks that did not run have no subject.
    /// </summary>
    public bool IgnoreInputsWithoutDomain { get; set; }
}

/// <summary>
/// Builds a <see cref="DomainAssessmentReport"/> from DomainDetective view objects (the output of
/// <c>DomainDetective.Views.Converters.Convert(...)</c>), the same input every composition renderer takes.
/// </summary>
public static class DomainAssessmentBuilder {
    /// <summary>Builds the assessment for the given views.</summary>
    /// <param name="items">View objects, optionally nested in lists.</param>
    /// <param name="options">Optional settings.</param>
    /// <returns>The assessment report.</returns>
    public static DomainAssessmentReport Build(IReadOnlyList<object> items, DomainAssessmentOptions? options = null) {
        options ??= new DomainAssessmentOptions();
        int maxRows = Math.Max(1, options.MaxEvidenceRows);
        var report = new DomainAssessmentReport {
            Title = string.IsNullOrWhiteSpace(options.Title) ? "Domain assessment" : options.Title!.Trim(),
            GeneratedAtUtc = options.GeneratedAtUtc ?? DateTimeOffset.UtcNow
        };

        var domains = new Dictionary<string, DomainAssessment>(StringComparer.OrdinalIgnoreCase);
        var firstSeen = new List<string>();
        foreach (object item in CompositionUtilities.Flatten(items ?? Array.Empty<object>())) {
            DomainAssessmentViewReader reader = DomainAssessmentViewReader.For(item.GetType());
            string? domain = reader.IsView ? NormalizeDomain(reader.Subject(item)) : null;
            if (domain == null) {
                if (!options.IgnoreInputsWithoutDomain) report.UnassignedInputs.Add(item.GetType().Name);
                continue;
            }
            if (!domains.TryGetValue(domain, out DomainAssessment? assessment)) {
                assessment = new DomainAssessment { Domain = domain };
                domains[domain] = assessment;
                firstSeen.Add(domain);
            }
            AddView(assessment, item, reader);
        }

        IEnumerable<string> order = options.DomainOrder == DomainOrder.Alphabetical
            ? firstSeen.OrderBy(static d => d, StringComparer.OrdinalIgnoreCase)
            : firstSeen;
        foreach (string name in order) {
            DomainAssessment domain = domains[name];
            foreach (CheckAssessment check in domain.Checks) Finish(check, maxRows);
            Score(domain);
            report.Domains.Add(domain);
        }

        int[] scores = report.Domains.Where(static d => d.Score.HasValue).Select(static d => d.Score!.Value).ToArray();
        report.Score = scores.Length == 0 ? null : (int)Math.Round(scores.Average(), MidpointRounding.AwayFromZero);
        report.Grade = DomainAssessmentCatalog.GradeFor(report.Score);
        return report;
    }

    /// <summary>Normalizes a view subject (domain, host or URL) to the domain it belongs to.</summary>
    internal static string? NormalizeDomain(string? subject) {
        if (string.IsNullOrWhiteSpace(subject)) return null;
        string value = subject!.Trim();
        if (Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.Host) && value.IndexOf("://", StringComparison.Ordinal) > 0) {
            value = uri.Host;
        }
        value = value.TrimEnd('.').ToLowerInvariant();
        // Some views describe something other than a domain (ARC reports "Message Headers"); they have no domain.
        if (value.Length == 0 || value.Any(char.IsWhiteSpace)) return null;
        return value;
    }

    private static void AddView(DomainAssessment domain, object view, DomainAssessmentViewReader reader) {
        HealthCheckType? kind = reader.Check(view);
        // Views built by hand (for example in PowerShell) often leave Check at its default, DMARC; the view type then
        // tells which check it is. A non-DMARC view whose type names no check is kept as its own, unnamed check.
        if (kind == default(HealthCheckType) && !view.GetType().Name.StartsWith("Dmarc", StringComparison.OrdinalIgnoreCase)) {
            kind = InferCheck(view.GetType());
        }
        AnalysisArea area = reader.Area(view) ?? AnalysisArea.General;
        if (area == AnalysisArea.General && kind.HasValue) area = DomainDetective.Views.Converters.AreaFor(kind.Value);
        string key = kind?.ToString().ToLowerInvariant() ?? KeyFromType(view.GetType());
        CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == key);
        if (check == null) {
            (string title, string? longTitle) = kind.HasValue ? DomainAssessmentCatalog.TitleFor(kind.Value) : (DomainAssessmentViewReader.Humanize(key), null);
            CheckDescription? description = kind.HasValue ? CheckDescriptions.Get(kind.Value) : null;
            check = new CheckAssessment {
                Key = key,
                Check = kind,
                Title = title,
                LongTitle = longTitle,
                Description = description?.Summary,
                Remediation = description?.Remediation,
                Area = area,
                // Views that name no check (aggregates such as DomainOverallInfo, time series) describe, not grade.
                Scored = kind.HasValue && DomainAssessmentCatalog.IsScored(kind.Value),
                Weight = kind.HasValue ? DomainAssessmentCatalog.WeightFor(kind.Value) : 1
            };
            if (!string.IsNullOrWhiteSpace(description?.RfcLink)) check.References.Add(description!.RfcLink!);
            domain.Checks.Add(check);
        }
        check.Sources.Add(view);
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, HealthCheckType?> InferredChecks = new();

    /// <summary>Check named by a view type: <c>SpfRecordInfo</c> is SPF, <c>MxInfo</c> is MX, <c>WildcardDnsInfo</c> is WILDCARDDNS.</summary>
    private static HealthCheckType? InferCheck(Type type) => InferredChecks.GetOrAdd(type, static t => {
        string key = KeyFromType(t);
        foreach (string candidate in new[] { key, Strip(key, "record"), Strip(key, "status"), Strip(Strip(key, "record"), "status") }) {
            if (Enum.TryParse(candidate, ignoreCase: true, out HealthCheckType check) && Enum.IsDefined(typeof(HealthCheckType), check)) return check;
        }
        return null;

        static string Strip(string value, string suffix)
            => value.Length > suffix.Length && value.EndsWith(suffix, StringComparison.Ordinal) ? value.Substring(0, value.Length - suffix.Length) : value;
    });

    private static string KeyFromType(Type type) {
        string name = type.Name;
        foreach (string suffix in new[] { "Info", "Summary", "View" }) {
            if (name.Length > suffix.Length && name.EndsWith(suffix, StringComparison.Ordinal)) {
                name = name.Substring(0, name.Length - suffix.Length);
                break;
            }
        }
        return name.ToLowerInvariant();
    }

    private static void Finish(CheckAssessment check, int maxRows) {
        var perSourceFacts = new List<List<CheckFact>>();
        foreach (object view in check.Sources) {
            DomainAssessmentViewReader reader = DomainAssessmentViewReader.For(view.GetType());
            foreach (Assessment assessment in reader.Assessments(view)) {
                if (string.IsNullOrWhiteSpace(assessment.Message)) continue;
                check.Findings.Add(new CheckFinding {
                    Severity = assessment.Severity,
                    Code = assessment.Code,
                    Message = assessment.Message.Trim(),
                    Target = assessment.Target
                });
            }
            AddDistinct(check.Positives, reader.Positives(view).Select(static p => string.IsNullOrWhiteSpace(p.Title) ? p.Code : p.Title));
            AddDistinct(check.Highlights, reader.Highlights(view));
            AddDistinct(check.References, reader.References(view));
            foreach (RecommendationAdvice advice in reader.Recommendations(view)) {
                if (check.Recommendations.Any(r => string.Equals(r.Code, advice.Code, StringComparison.OrdinalIgnoreCase) && string.Equals(r.Title, advice.Title, StringComparison.Ordinal))) continue;
                check.Recommendations.Add(ToGuidance(advice));
            }
            check.Summary ??= NullIfEmpty(reader.Summary(view));
            check.Narrative ??= DomainAssessmentNarratives.Resolve(view, reader);

            var facts = new List<CheckFact>();
            reader.ReadDetails(view, null, facts, check.Evidence, maxRows);
            perSourceFacts.Add(facts);
        }

        if (perSourceFacts.Count == 1) {
            check.Facts.AddRange(perSourceFacts[0]);
        } else if (perSourceFacts.Count > 1) {
            // Several results for one check (DKIM selectors, propagation servers): one row per result.
            var columns = perSourceFacts.SelectMany(static f => f).Select(static f => f.Label).Distinct(StringComparer.Ordinal).ToList();
            var table = new CheckEvidence { Title = check.Title + " results", Kind = CheckEvidenceKind.Table };
            table.Columns.AddRange(columns);
            foreach (List<CheckFact> facts in perSourceFacts) {
                table.Rows.Add(columns.Select(column => facts.FirstOrDefault(f => f.Label == column)?.Value ?? string.Empty).ToList());
            }
            check.Evidence.Insert(0, table);
        }

        // The same finding is often raised once per target and once without one; show it once with its targets.
        check.Findings = check.Findings
            .GroupBy(static f => (f.Severity, f.Code, f.Message))
            .Select(static g => new CheckFinding {
                Severity = g.Key.Severity,
                Code = g.Key.Code,
                Message = g.Key.Message,
                Target = JoinTargets(g.Select(static f => f.Target))
            })
            .OrderByDescending(static f => f.Severity)
            .ToList();
        check.ErrorCount = check.Findings.Count(static f => f.Severity == AssessmentSeverity.Error);
        check.WarningCount = check.Findings.Count(static f => f.Severity == AssessmentSeverity.Warning);
        // Some views report counts without the individual assessments; the outcome must still reflect them.
        if (check.ErrorCount == 0 && check.WarningCount == 0) {
            foreach (object view in check.Sources) {
                DomainAssessmentViewReader reader = DomainAssessmentViewReader.For(view.GetType());
                check.ErrorCount += reader.ErrorCount(view);
                check.WarningCount += reader.WarningCount(view);
            }
        }
        check.Outcome = check.ErrorCount > 0 ? CheckOutcome.Error
            : check.WarningCount > 0 ? CheckOutcome.Warning
            : check.Scored ? CheckOutcome.Pass
            : CheckOutcome.Info;
        check.Score = DomainAssessmentCatalog.ScoreFor(check.ErrorCount, check.WarningCount);
    }

    private static void Score(DomainAssessment domain) {
        domain.Checks = domain.Checks
            .OrderBy(static c => AreaIndex(c.Area))
            .ThenBy(static c => CanonicalIndex(c))
            .ThenBy(static c => c.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
        domain.Score = WeightedScore(domain.Checks);
        domain.Grade = DomainAssessmentCatalog.GradeFor(domain.Score);
        domain.ErrorChecks = domain.Checks.Count(static c => c.Outcome == CheckOutcome.Error);
        domain.WarningChecks = domain.Checks.Count(static c => c.Outcome == CheckOutcome.Warning);
        domain.PassedChecks = domain.Checks.Count(static c => c.Outcome == CheckOutcome.Pass);
        domain.Areas = domain.Checks
            .GroupBy(static c => c.Area)
            .OrderBy(static g => AreaIndex(g.Key))
            .Select(static g => new AreaScore {
                Area = g.Key,
                Score = WeightedScore(g),
                Checks = g.Count(),
                Attention = g.Count(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
            })
            .ToList();
    }

    private static int? WeightedScore(IEnumerable<CheckAssessment> checks) {
        var scored = checks.Where(static c => c.Scored).ToList();
        int weight = scored.Sum(static c => c.Weight);
        if (weight == 0) return null;
        return (int)Math.Round(scored.Sum(static c => (double)c.Score * c.Weight) / weight, MidpointRounding.AwayFromZero);
    }

    private static int AreaIndex(AnalysisArea area) {
        int index = -1;
        for (int i = 0; i < DomainAssessmentCatalog.AreaOrder.Count; i++) {
            if (DomainAssessmentCatalog.AreaOrder[i] == area) index = i;
        }
        return index < 0 ? int.MaxValue : index;
    }

    private static int CanonicalIndex(CheckAssessment check) {
        string? section = check.Check.HasValue ? SectionOrdering.SectionKeyFor(check.Check.Value) : null;
        if (section == null) return int.MaxValue;
        for (int i = 0; i < SectionOrdering.CanonicalSections.Count; i++) {
            if (string.Equals(SectionOrdering.CanonicalSections[i], section, StringComparison.OrdinalIgnoreCase)) return i;
        }
        return int.MaxValue;
    }

    private static CheckGuidance ToGuidance(RecommendationAdvice advice) {
        var guidance = new CheckGuidance {
            Code = NullIfEmpty(advice.Code),
            Title = string.IsNullOrWhiteSpace(advice.Title) ? advice.Code : advice.Title,
            Why = NullIfEmpty(advice.Why),
            How = NullIfEmpty(advice.How),
            Impact = NullIfEmpty(advice.Impact),
            Effort = advice.Effort.ToString(),
            Verify = NullIfEmpty(advice.Verify)
        };
        guidance.Links.AddRange(advice.Links.Where(static l => !string.IsNullOrWhiteSpace(l)));
        return guidance;
    }

    private static void AddDistinct(List<string> target, IEnumerable<string?> values) {
        foreach (string? value in values) {
            if (string.IsNullOrWhiteSpace(value)) continue;
            string trimmed = value!.Trim();
            if (!target.Contains(trimmed, StringComparer.OrdinalIgnoreCase)) target.Add(trimmed);
        }
    }

    private static string? JoinTargets(IEnumerable<string?> targets) {
        var distinct = targets.Where(static t => !string.IsNullOrWhiteSpace(t)).Select(static t => t!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return distinct.Count == 0 ? null : string.Join(", ", distinct);
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value!.Trim();
}
