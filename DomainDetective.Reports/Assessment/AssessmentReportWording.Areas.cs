using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>Shared wording for the area rows and control tiles.</summary>
public static partial class AssessmentReportWording {
    /// <summary>
    /// One or two plain sentences for the top of a domain page: what holds, and the first thing to fix. Raw errors stay in
    /// the findings.
    /// </summary>
    public static string DomainIntro(DomainAssessment domain) {
        string? strengths = DomainStrengths(domain);
        List<string> first = FixOrder(domain.Checks).Where(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
            .Select(static c => c.Title).Distinct(StringComparer.Ordinal).Take(3).ToList();
        // Name the checks only; their findings are printed in full where they are listed.
        string fix = first.Count == 0
            ? domain.Checks.Count == 0 ? "No checks ran." : "Nothing needs fixing."
            : "Fix first: " + JoinList(first) + ".";
        return strengths == null ? fix : strengths + " " + fix;
    }

    private static string FirstSentence(string text) {
        int end = text.IndexOf(". ", StringComparison.Ordinal);
        return end > 0 ? text.Substring(0, end + 1) : text;
    }

    private static string LowerFirst(string text) =>
        text.Length > 1 && char.IsUpper(text[0]) && char.IsLower(text[1]) ? char.ToLowerInvariant(text[0]) + text.Substring(1) : text;

    /// <summary>Summary for a domain without a CAA policy.</summary>
    public const string NoCaaPolicy = "No CAA policy is published, so any certificate authority may issue certificates for this domain.";

    /// <summary>Summary for a domain without a TLS-RPT record.</summary>
    public const string NoTlsRptRecord = "No TLS-RPT record is published, so mail TLS failures are not reported to this domain.";

    /// <summary>True for a CAA check that found no policy: unscored, and worded as "any CA may issue".</summary>
    public static bool IsNoCaaPolicy(CheckAssessment check) =>
        check.Key == "caa" && !check.Scored && string.Equals(check.Summary, NoCaaPolicy, StringComparison.Ordinal);

    /// <summary>True for a TLS-RPT check that found no record: unscored, and worded as "not reported".</summary>
    public static bool IsNoTlsRptRecord(CheckAssessment check) =>
        check.Key == "tlsrpt" && !check.Scored && string.Equals(check.Summary, NoTlsRptRecord, StringComparison.Ordinal);

    /// <summary>True for an optional policy the domain does not publish: neither a pass nor a failure.</summary>
    public static bool IsAbsentPolicy(CheckAssessment check) => IsNoCaaPolicy(check) || IsNoTlsRptRecord(check);

    /// <summary>"80%" for a coverage value, or "all" when complete.</summary>
    public static string CoveragePercent(double? coverage) =>
        !coverage.HasValue ? "none" : ((int)Math.Round(coverage.Value * 100, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture) + "%";

    /// <summary>Area status word: Errors, Needs attention, Incomplete, Passing or Informational.</summary>
    public static string AreaStatus(IReadOnlyCollection<CheckAssessment> checks) {
        if (checks.Any(static c => c.Outcome == CheckOutcome.Error)) return "Errors";
        if (checks.Any(static c => c.Outcome == CheckOutcome.Warning)) return "Needs attention";
        if (checks.Any(static c => c.Scored && !c.EvidenceComplete)) return "Partly checked";
        return checks.Any(static c => c.Scored) ? "Passing" : "Informational";
    }

    /// <summary>"6 checks: 4 pass, 2 need attention, 1 incomplete, 2 informational".</summary>
    public static string AreaCounts(IReadOnlyCollection<CheckAssessment> checks) {
        int pass = checks.Count(static c => c.Scored && c.Outcome == CheckOutcome.Pass);
        int attention = checks.Count(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning);
        int incomplete = checks.Count(static c => c.Scored && !c.EvidenceComplete && c.Outcome is not (CheckOutcome.Error or CheckOutcome.Warning));
        int info = checks.Count(static c => !c.Scored && c.Outcome is not (CheckOutcome.Error or CheckOutcome.Warning));
        var parts = new List<string>();
        if (pass > 0) parts.Add(pass.ToString(CultureInfo.InvariantCulture) + " pass");
        if (attention > 0) parts.Add(attention.ToString(CultureInfo.InvariantCulture) + (attention == 1 ? " needs attention" : " need attention"));
        if (incomplete > 0) parts.Add(incomplete.ToString(CultureInfo.InvariantCulture) + " couldn't be checked");
        if (info > 0) parts.Add(info.ToString(CultureInfo.InvariantCulture) + " informational");
        return Plural(checks.Count, "check") + (parts.Count > 0 ? ": " + string.Join(", ", parts) : string.Empty);
    }

    /// <summary>One short line on what an area's score leaves out or what to look at, or null.</summary>
    public static string? AreaMissing(IReadOnlyCollection<CheckAssessment> checks) {
        string[] incomplete = checks.Where(static c => c.Scored && !c.EvidenceComplete).Select(static c => c.Title).Distinct(StringComparer.Ordinal).ToArray();
        string[] attention = checks.Where(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
            .OrderByDescending(static c => c.Outcome).Select(static c => c.Title).Distinct(StringComparer.Ordinal).ToArray();
        var parts = new List<string>();
        if (attention.Length > 0) parts.Add("Look at " + ShortList(attention, 3));
        if (incomplete.Length > 0) parts.Add("couldn't check " + ShortList(incomplete, 3));
        return parts.Count == 0 ? null : Capitalize(string.Join("; ", parts)) + ".";
    }

    private static string ShortList(IReadOnlyList<string> items, int max) =>
        items.Count <= max ? JoinList(items.ToList()) : string.Join(", ", items.Take(max)) + " and " + (items.Count - max).ToString(CultureInfo.InvariantCulture) + " more";

    /// <summary>A control's headline value in words a reader understands: "Reject", "Strict (-all)", "2 selectors".</summary>
    public static string ControlValue(CheckAssessment check) {
        if (!check.EvidenceComplete && check.Outcome == CheckOutcome.Incomplete) return "Couldn't check";
        string? policy = Metric(check, "Policy");
        string? value = check.Key switch {
            "dmarc" => policy == null ? null : policy.ToLowerInvariant() switch {
                "reject" => "Reject", "quarantine" => "Quarantine", "none" => "Monitor only", _ => Capitalize(policy)
            },
            "spf" => Metric(check, "Ends with") is { } end ? SpfEnding(end) : null,
            "dkim" => Metric(check, "Selectors found") is { } found ? Plural(ParseCount(found), "selector") : null,
            "mx" => Metric(check, "Mail servers") is { } servers ? Plural(ParseCount(servers), "mail server") : null,
            "mtasts" => Metric(check, "Mode") is { } mode ? Capitalize(mode) : Metric(check, "Policy") is { } p ? Capitalize(p) : null,
            "tlsrpt" => IsNoTlsRptRecord(check) ? "Not published" : Metric(check, "Report addresses") is { } count ? Plural(ParseCount(count), "report address", "report addresses") : null,
            "bimi" => Metric(check, "Logo") is { } logo ? "Logo " + logo.ToLowerInvariant() : null,
            "dnssec" => check.Outcome == CheckOutcome.Pass ? "Signed and valid" : Fact(check, "Validation status"),
            "caa" => IsNoCaaPolicy(check) ? "No CAA policy"
                : Metric(check, "Issuers") is { } issuers ? Plural(ParseCount(issuers), "CA allowed", "CAs allowed") : null,
            _ => null
        };
        if (value != null) return value;
        CheckMetric? headline = Headline(check);
        if (headline != null && headline.Value.Length <= 18) return headline.Value;
        return check.Outcome switch {
            CheckOutcome.Pass => "Passes",
            CheckOutcome.Warning => "Needs attention",
            CheckOutcome.Error => "Failing",
            CheckOutcome.Incomplete => "Couldn't check",
            _ => "Informational"
        };
    }

    /// <summary>One line on why: the top finding, or what works, shortened to fit a tile.</summary>
    public static string ControlReason(CheckAssessment check) {
        string? reason = check.Outcome is CheckOutcome.Error or CheckOutcome.Warning or CheckOutcome.Incomplete
            ? TopFinding(check) ?? (check.EvidenceComplete ? null : "Evidence is incomplete.")
            : PassReason(check) ?? check.Positives.FirstOrDefault() ?? check.Summary;
        return reason == null ? string.Empty : Shorten(reason.Trim(), 90);
    }

    // What a passing control achieves, in words, for the controls whose positives are record-level detail.
    private static string? PassReason(CheckAssessment check) => check.Key switch {
        "dmarc" => (Metric(check, "Policy") ?? string.Empty).ToLowerInvariant() switch {
            "reject" => "Mail that fails authentication is rejected.",
            "quarantine" => "Mail that fails authentication goes to spam.",
            "none" => "Mail that fails authentication is still delivered.",
            _ => null
        },
        "spf" => Metric(check, "DNS lookups") is { } lookups ? (lookups.Contains("/") ? lookups : lookups + " / 10") + " DNS lookups used." : null,
        "dkim" => "Every published key is valid.",
        "dnssec" => "Answers are signed and validate.",
        "caa" => IsNoCaaPolicy(check) ? "Any certificate authority may issue certificates." : "Only the listed CAs may issue certificates.",
        "tlsrpt" => IsNoTlsRptRecord(check) ? "Mail TLS failures are not reported." : "Mail TLS failures are reported.",
        "mtasts" => "Senders must deliver over TLS.",
        _ => null
    };

    private static string SpfEnding(string end) {
        string mechanism = end.Split(' ')[0].Trim();
        return mechanism switch {
            "-all" => "Strict (-all)",
            "~all" => "Soft (~all)",
            "?all" => "Neutral (?all)",
            "+all" => "Open (+all)",
            _ => end
        };
    }

    private static int ParseCount(string value) {
        string digits = new string(value.TakeWhile(char.IsDigit).ToArray());
        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out int count) ? count : 0;
    }

    private static string Plural(int count, string singular, string plural) =>
        count.ToString("N0", CultureInfo.InvariantCulture) + " " + (count == 1 ? singular : plural);
}
