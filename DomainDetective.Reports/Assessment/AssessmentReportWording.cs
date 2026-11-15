using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>The format-independent vocabulary and reading order of an assessment.</summary>
public static class AssessmentReportWording {
    /// <summary>What needs attention in an area, in one line.</summary>
    public static string AreaLine(DomainAssessmentReport report, List<CheckAssessment> checks) {
        var titles = FixOrder(checks).Select(static c => c.Title).Distinct(StringComparer.Ordinal).ToList();
        if (titles.Count == 0) return checks.Any(static c => !c.EvidenceComplete) ? IncompleteEvidence(checks)
            : checks.All(static c => !c.Scored) ? checks.Count == 1 ? "Informational check only." : "Informational checks only."
            : checks.Count == 1 ? $"The {Plural(checks.Count, "check")} passes." : $"All {Plural(checks.Count, "check")} pass.";
        string list = titles.Count <= 3 ? string.Join(", ", titles) : string.Join(", ", titles.Take(3)) + $" and {(titles.Count - 3).ToString(CultureInfo.InvariantCulture)} more";
        return report.Domains.Count == 1 ? "Needs attention: " + list + "." : "Needs attention on some domains: " + list + ".";
    }

    /// <summary>The verdict across the top of the summary: what the run found, in one or two sentences.</summary>
    public static string ReportVerdict(DomainAssessmentReport report, int errors, int warnings) {
        if (report.Domains.Count == 0) return "No domains were assessed.";
        int open = report.Domains.Sum(static d => d.Checks.Count(NeedsAttention));
        string need = open == 1 ? "needs" : "need";
        string attention = open == 0
            ? report.Domains.Any(d => d.Checks.Any(c => !c.EvidenceComplete)) ? IncompleteEvidence(report.Domains.SelectMany(static d => d.Checks)) : "Every scored check passed."
            : errors == 0
                ? $"{Plural(open, "check")} {need} attention; none has errors."
                : open == 1
                    ? "1 check has errors."
                    : $"{Plural(open, "check")} {need} attention, {errors.ToString(CultureInfo.InvariantCulture)} of them with errors.";
        if (report.Domains.Count == 1) {
            string? strengths = DomainStrengths(report.Domains[0]);
            return strengths == null ? attention : strengths + " " + attention;
        }
        int withErrors = report.Domains.Count(static d => d.ErrorChecks > 0);
        int warningsOnly = report.Domains.Count(static d => d.ErrorChecks == 0 && d.WarningChecks > 0);
        int incomplete = report.Domains.Count(static d => d.ErrorChecks == 0 && d.WarningChecks == 0 && d.Checks.Any(c => !c.EvidenceComplete));
        int clean = report.Domains.Count - withErrors - warningsOnly - incomplete;
        int total = report.Domains.Count;
        var groups = new List<(int Count, string One, string Many)>();
        if (withErrors > 0) groups.Add((withErrors, "has errors", "have errors"));
        if (warningsOnly > 0) groups.Add((warningsOnly, "has warnings only", "have warnings only"));
        if (incomplete > 0) groups.Add((incomplete, "has incomplete evidence", "have incomplete evidence"));
        if (clean > 0) groups.Add((clean, "passes every check", "pass every check"));
        // "2 of 5 domains have errors, 1 has warnings only and 2 pass every check"; one group covering all reads "Both
        // domains have errors" or "All 5 domains have errors".
        var (firstCount, firstOne, firstMany) = groups[0];
        string first = firstCount == total
            ? (total == 2 ? "Both domains " : $"All {total.ToString(CultureInfo.InvariantCulture)} domains ") + firstMany
            : $"{firstCount.ToString(CultureInfo.InvariantCulture)} of {Plural(total, "domain")} {(firstCount == 1 ? firstOne : firstMany)}";
        var parts = new List<string> { first };
        parts.AddRange(groups.Skip(1).Select(static g => $"{g.Count.ToString(CultureInfo.InvariantCulture)} {(g.Count == 1 ? g.One : g.Many)}"));
        return JoinList(parts) + ".";
    }

    /// <summary>Shared assessment wording and selection for ReportVerdictDetail.</summary>
    public static string ReportVerdictDetail(DomainAssessmentReport report, List<CheckAssessment> checks) {
        int areas = checks.Select(static c => c.Area).Distinct().Count();
        int passed = checks.Count(static c => c.Outcome == CheckOutcome.Pass);
        int info = checks.Count(static c => c.Outcome == CheckOutcome.Info);
        int incomplete = checks.Count(static c => !c.EvidenceComplete);
        string what = $"{Plural(checks.Count, "check")} in {Plural(areas, "area")}: {passed.ToString(CultureInfo.InvariantCulture)} passed";
        if (info > 0) what += $", {info.ToString(CultureInfo.InvariantCulture)} informational";
        if (incomplete > 0) what += $", {incomplete.ToString(CultureInfo.InvariantCulture)} with incomplete evidence";
        return what + (report.Domains.Count > 1 && report.Score.HasValue ? ". The overall grade averages the domain scores." : ".");
    }

    /// <summary>Joins a readable list with commas and a final conjunction.</summary>
    public static string JoinList(List<string> parts) => parts.Count switch {
        0 => string.Empty,
        1 => parts[0],
        _ => string.Join(", ", parts.Take(parts.Count - 1)) + " and " + parts[parts.Count - 1]
    };

    /// <summary>The controls readers look for first and their preferred headline metrics.</summary>
    public static IReadOnlyList<(string Key, string Headline)> Controls { get; } = Array.AsReadOnly(new (string Key, string Headline)[] {
        ("dmarc", "Policy"), ("spf", "Ends with"), ("dkim", "Selectors found"), ("mx", "Mail servers"),
        ("mtasts", "Mode"), ("tlsrpt", "Report addresses"), ("bimi", "Logo"), ("dnssec", string.Empty), ("caa", string.Empty)
    });

    /// <summary>The familiar mail/DNS controls plus every scored Web/Security check present in this report.</summary>
    public static IEnumerable<CheckAssessment> ControlChecks(DomainAssessmentReport report) {
        var checks = report.Domains.SelectMany(domain => domain.Checks).ToList();
        return Controls.Select(control => checks.FirstOrDefault(check => check.Key == control.Key))
            .Where(check => check != null).Select(check => check!)
            .Concat(checks.Where(check => check.Scored && check.Area is AnalysisArea.Web or AnalysisArea.Security)
                .OrderBy(check => check.Area == AnalysisArea.Web ? 0 : 1))
            .GroupBy(check => check.Key, StringComparer.OrdinalIgnoreCase).Select(group => group.First());
    }


    /// <summary>Explains the overall score when all scored evidence is complete.</summary>
    public static string ScoreNote(int? score, int errors, int warnings) {
        if (!score.HasValue) return "No scored checks ran.";
        if (errors == 0 && warnings == 0) return "Every scored check passed.";
        return $"{Plural(errors, "check")} with errors and {Plural(warnings, "check")} with warnings.";
    }
    /// <summary>
    /// One sentence on what holds and what to fix first, for the top of a domain page.
    /// </summary>
    public static string DomainVerdict(DomainAssessment domain) {
        string? strengths = DomainStrengths(domain);
        string[] fixes = FixOrder(domain.Checks)
            .Take(3)
            .Select(c => c.Title + (TopFinding(c) is { } finding ? " (" + Shorten(finding.TrimEnd('.'), 48) + ")" : string.Empty))
            .ToArray();
        string first = strengths == null ? string.Empty : strengths + " ";
        string second = fixes.Length == 0 ? domain.Checks.Any(c => !c.EvidenceComplete)
            ? IncompleteEvidence(domain.Checks) : "Every scored check passed." : "Fix first: " + string.Join("; ", fixes) + ".";
        return first + second;
    }

    /// <summary>What the domain's mail and DNS controls achieve, as one sentence, or null when nothing is known.</summary>
    public static string? DomainStrengths(DomainAssessment domain) {
        var strengths = new List<string>();
        CheckAssessment? dmarc = domain.Checks.FirstOrDefault(c => c.Key == "dmarc");
        CheckAssessment? spf = domain.Checks.FirstOrDefault(c => c.Key == "spf");
        string? policy = dmarc == null ? null : Metric(dmarc, "Policy");
        if (string.Equals(policy, "reject", StringComparison.OrdinalIgnoreCase)) strengths.Add("spoofed mail is rejected (DMARC reject)");
        else if (string.Equals(policy, "quarantine", StringComparison.OrdinalIgnoreCase)) strengths.Add("spoofed mail is quarantined (DMARC quarantine)");
        else if (dmarc != null && string.Equals(Metric(dmarc, "Record"), "Unknown", StringComparison.OrdinalIgnoreCase)) strengths.Add("the DMARC policy could not be read (DNS lookup failed)");
        else if (dmarc != null) strengths.Add("DMARC does not stop spoofed mail yet");
        if (spf != null && (Metric(spf, "Ends with") ?? string.Empty).StartsWith("-all", StringComparison.Ordinal)) strengths.Add("SPF hard-fails unknown senders");
        if (domain.Checks.FirstOrDefault(c => c.Key == "dnssec") is { Outcome: CheckOutcome.Pass, EvidenceComplete: true } dnssec
            && string.Equals(Fact(dnssec, "Validation status"), "Secure", StringComparison.OrdinalIgnoreCase)) strengths.Add("DNSSEC is valid");
        return strengths.Count == 0 ? null : Capitalize(string.Join(", ", strengths)) + ".";
    }

    /// <summary>
    /// Checks that need attention, in the order to fix them: security exposure first (see
    /// <see cref="DomainAssessmentCatalog.SecurityPriority"/>), then errors before warnings, then by what costs the score
    /// most (points lost times the check's weight).
    /// </summary>
    public static bool NeedsAttention(CheckAssessment check) => !check.EvidenceComplete
        || check.Outcome is CheckOutcome.Error or CheckOutcome.Warning or CheckOutcome.Incomplete;

    /// <summary>Shared assessment wording and selection for FixOrder.</summary>
    public static IEnumerable<CheckAssessment> FixOrder(IEnumerable<CheckAssessment> checks) => checks
        .Where(NeedsAttention)
        .OrderBy(static c => DomainAssessmentCatalog.SecurityPriority(c.Check))
        .ThenByDescending(static c => c.Outcome)
        .ThenByDescending(static c => (100 - c.Score) * Math.Max(1, c.Weight));


    /// <summary>Finds the displayed value of a named headline metric.</summary>
    public static string? Metric(CheckAssessment check, string label)
        => check.Metrics.FirstOrDefault(m => string.Equals(m.Label, label, StringComparison.OrdinalIgnoreCase))?.Value is { Length: > 0 } value ? value : null;

    /// <summary>Finds the displayed value of a named evidence fact.</summary>
    public static string? Fact(CheckAssessment check, string label)
        => check.Facts.FirstOrDefault(f => string.Equals(f.Label, label, StringComparison.OrdinalIgnoreCase))?.Value is { Length: > 0 } value ? value : null;


    /// <summary>The first non-informational finding in the check's display order.</summary>
    public static string? TopFinding(CheckAssessment check)
        => check.Findings.FirstOrDefault(static f => f.Severity != AssessmentSeverity.Info)?.Message;


    /// <summary>Shortens a sentence fragment with an ellipsis.</summary>
    public static string Shorten(string text, int max) => text.Length <= max ? text : text.Substring(0, max - 1).TrimEnd() + "…";

    /// <summary>Tests a wording fragment without case sensitivity.</summary>
    public static bool Has(string? text, string value) => text != null && text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;

    /// <summary>Capitalizes the first character of a sentence.</summary>
    public static string Capitalize(string text) => text.Length == 0 ? text : char.ToUpperInvariant(text[0]) + text.Substring(1);


    /// <summary>The key number for a check: a missing record first, otherwise the control's headline metric.</summary>
    public static CheckMetric? Headline(CheckAssessment check) {
        if (!check.EvidenceComplete) return null;
        if (check.Metrics.Count == 0) return null;
        if (check.Metrics[0].Label == "Record") return check.Metrics[0];
        string? preferred = Controls.FirstOrDefault(c => c.Key == check.Key).Headline;
        return (string.IsNullOrEmpty(preferred) ? null : check.Metrics.FirstOrDefault(m => m.Label == preferred)) ?? check.Metrics[0];
    }


    /// <summary>The reader-facing outcome word in every export.</summary>
    public static string OutcomeLabel(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => "Error",
        CheckOutcome.Warning => "Warning",
        CheckOutcome.Incomplete => "Incomplete",
        CheckOutcome.Pass => "Pass",
        _ => "Info"
    };

    /// <summary>The finding label distinguishes unavailable evidence from an observed error or warning.</summary>
    public static string FindingLabel(CheckFinding finding) => finding.IsEvidenceGap ? "Incomplete" : finding.Severity switch {
        AssessmentSeverity.Error => "Error",
        AssessmentSeverity.Warning => "Warning",
        _ => "Info"
    };


    /// <summary>The reader-facing analysis area label.</summary>
    public static string AreaLabel(AnalysisArea area) => area switch {
        AnalysisArea.DNS => "DNS",
        AnalysisArea.General => "Other",
        _ => area.ToString()
    };


    /// <summary>Formats an invariant count followed by the singular or plural noun.</summary>
    public static string Plural(int count, string noun)
        => $"{count.ToString("N0", CultureInfo.InvariantCulture)} {noun}{(count == 1 ? string.Empty : "s")}";

    /// <summary>Formats the report timestamp in UTC to the minute.</summary>
    public static string FormatTime(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);

    /// <summary>The verdict calculated from every check in the report.</summary>
    public static string ReportVerdict(DomainAssessmentReport report) {
        var checks = report.Domains.SelectMany(d => d.Checks).ToList();
        return report.Domains.Count == 0 ? "No domains were assessed." : ReportVerdict(report, checks.Count(c => c.Outcome == CheckOutcome.Error), checks.Count(c => c.Outcome == CheckOutcome.Warning));
    }

    /// <summary>The detail line for every check in the report.</summary>
    public static string ReportVerdictDetail(DomainAssessmentReport report) => ReportVerdictDetail(report, report.Domains.SelectMany(d => d.Checks).ToList());

    /// <summary>The score explanation, including evidence gaps and unscored areas.</summary>
    public static string ScoreNote(DomainAssessmentReport report) {
        var checks = report.Domains.SelectMany(d => d.Checks).ToList();
        if (checks.Any(c => c.Scored && !c.EvidenceComplete)) {
            var areas = DomainAssessmentCatalog.AreaOrder.Where(area => checks.Any(c => c.Area == area && c.Scored && !c.EvidenceComplete)).Select(AreaLabel).ToList();
            int incomplete = checks.Count(static c => c.Scored && !c.EvidenceComplete);
            string evidence = incomplete == 1
                ? $"{Plural(incomplete, "scored check")} has incomplete evidence." : "some scored checks have incomplete evidence.";
            return $"No overall grade: {evidence} Not scored: {JoinList(areas)}.";
        }
        return ScoreNote(report.Score, checks.Count(c => c.Outcome == CheckOutcome.Error), checks.Count(c => c.Outcome == CheckOutcome.Warning));
    }

    /// <summary>Prioritized actions with their owning domains, preserving input order on ties.</summary>
    public static IEnumerable<(DomainAssessment Domain, CheckAssessment Check)> DoFirst(DomainAssessmentReport report) => report.Domains
        .SelectMany(d => d.Checks.Select(c => (Domain: d, Check: c)))
        .Where(x => NeedsAttention(x.Check))
        .OrderBy(x => DomainAssessmentCatalog.SecurityPriority(x.Check.Check))
        .ThenByDescending(x => x.Check.Outcome)
        .ThenByDescending(x => (100 - x.Check.Score) * Math.Max(1, x.Check.Weight));

    /// <summary>Groups identical check/action messages across domains, ordered by severity then affected-domain count.</summary>
    public static IEnumerable<(DomainAssessment Domain, CheckAssessment Check, string AffectedDomains,
        IReadOnlyList<(DomainAssessment Domain, CheckAssessment Check)> Members)> DoFirstGroups(DomainAssessmentReport report)
        => DoFirst(report).GroupBy(action => (action.Check.Key, Message: DoFirstMessage(action.Check)))
            .Select(group => new {
                Action = group.OrderByDescending(action => ActionSeverity(action.Check)).First(),
                Domains = group.Select(action => action.Domain.Domain).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Members = (IReadOnlyList<(DomainAssessment Domain, CheckAssessment Check)>)group.ToList()
            })
            .OrderByDescending(group => ActionSeverity(group.Action.Check))
            .ThenByDescending(group => group.Domains.Count)
            .ThenBy(group => DomainAssessmentCatalog.SecurityPriority(group.Action.Check.Check))
            .Select(group => (group.Action.Domain, group.Action.Check, group.Domains.Count == 1 ? group.Domains[0]
                : group.Domains.Count == report.Domains.Count ? "All " + Plural(group.Domains.Count, "domain")
                : Plural(group.Domains.Count, "domain") + ": " + string.Join(", ", group.Domains), group.Members));

    private static int ActionSeverity(CheckAssessment check) => check.Outcome switch {
        CheckOutcome.Error => 3,
        CheckOutcome.Warning => 2,
        CheckOutcome.Incomplete => 1,
        _ => check.EvidenceComplete ? 0 : 1
    };

    /// <summary>The top action message, including the shared fallback for incomplete checks.</summary>
    public static string DoFirstMessage(CheckAssessment check) => TopFinding(check) ?? check.Summary ?? (!check.EvidenceComplete
        ? "The check has incomplete evidence. Retry it to complete the assessment." : check.Description ?? string.Empty);

    /// <summary>The action's area and count of additional warning/error findings.</summary>
    public static string DoFirstSource(CheckAssessment check) {
        int more = check.ErrorCount + check.WarningCount - 1;
        return more > 0 ? $"{AreaLabel(check.Area)} · and {Plural(more, "more finding")}" : AreaLabel(check.Area);
    }

    private static string IncompleteEvidence(IEnumerable<CheckAssessment> checks) {
        int incomplete = checks.Count(static c => !c.EvidenceComplete);
        return incomplete == 1 ? $"{Plural(incomplete, "check")} has incomplete evidence." : "Some checks have incomplete evidence.";
    }

    /// <summary>The complete area note, including the evidence qualification used by HTML.</summary>
    public static string AreaNote(DomainAssessmentReport report, List<CheckAssessment> checks) =>
        (checks.Any(c => c.Scored && !c.EvidenceComplete) ? "Incomplete evidence. " : string.Empty) + AreaLine(report, checks);

    /// <summary>The scoring facts printed in the HTML About section and paper appendix.</summary>
    public static IReadOnlyList<KeyValuePair<string, string>> ScoringFacts { get; } = Array.AsReadOnly(new[] {
        new KeyValuePair<string,string>("Check score", "100 when a check passes; 15 points off per warning (not below 50); with errors, 40 for the first, 10 less for each further error and 5 less per warning (not below 0)."),
        new KeyValuePair<string,string>("Domain score", "Weighted average of scored checks. DMARC counts three times, SPF, DKIM, MX and DNSSEC twice."),
        new KeyValuePair<string,string>("Informational checks", "Inventory and discovery checks (subdomains, DNS inventory, CT timeline, Microsoft 365, ...) are shown but not scored."),
        new KeyValuePair<string,string>("Grade", "A from 90, B from 80, C from 70, D from 60, otherwise F.")
    });
}
