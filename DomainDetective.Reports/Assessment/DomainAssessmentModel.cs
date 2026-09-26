using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using DomainDetective.Narratives;

namespace DomainDetective.Reports;

/// <summary>
/// Format-independent result of a DomainDetective run: every domain, every check that ran, with outcome, score,
/// findings, evidence and guidance. HTML, JSON and other renderers read this model instead of the raw view objects.
/// </summary>
public sealed class DomainAssessmentReport {
    /// <summary>Report title.</summary>
    public string Title { get; set; } = "Domain assessment";

    /// <summary>Time the report model was built.</summary>
    public DateTimeOffset GeneratedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Overall score (0–100): the mean of the domain scores, or null when nothing was scored.</summary>
    public int? Score { get; set; }

    /// <summary>Letter grade derived from <see cref="Score"/>.</summary>
    public string Grade { get; set; } = "-";

    /// <summary>Assessed domains in report order.</summary>
    public List<DomainAssessment> Domains { get; set; } = new();

    /// <summary>Input objects that could not be assigned to a domain and check, by type name. Diagnostic only.</summary>
    public List<string> UnassignedInputs { get; set; } = new();
}

/// <summary>One domain and the checks that ran for it.</summary>
public sealed class DomainAssessment {
    /// <summary>Domain name (lower case, no trailing dot).</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Weighted score of the scored checks (0–100), or null when no scored check ran.</summary>
    public int? Score { get; set; }

    /// <summary>Letter grade derived from <see cref="Score"/>.</summary>
    public string Grade { get; set; } = "-";

    /// <summary>Scores per analysis area (Mail, DNS, Web, ...), in display order.</summary>
    public List<AreaScore> Areas { get; set; } = new();

    /// <summary>Checks in display order: by area, then canonical check order.</summary>
    public List<CheckAssessment> Checks { get; set; } = new();

    /// <summary>Number of checks whose outcome is <see cref="CheckOutcome.Error"/>.</summary>
    public int ErrorChecks { get; set; }

    /// <summary>Number of checks whose outcome is <see cref="CheckOutcome.Warning"/>.</summary>
    public int WarningChecks { get; set; }

    /// <summary>Number of checks whose outcome is <see cref="CheckOutcome.Pass"/>.</summary>
    public int PassedChecks { get; set; }
}

/// <summary>Score of one analysis area of a domain.</summary>
public sealed class AreaScore {
    /// <summary>Analysis area.</summary>
    public AnalysisArea Area { get; set; }

    /// <summary>Area score (0–100), or null when no scored check in the area ran.</summary>
    public int? Score { get; set; }

    /// <summary>Checks in the area.</summary>
    public int Checks { get; set; }

    /// <summary>Checks in the area with a warning or error outcome.</summary>
    public int Attention { get; set; }
}

/// <summary>Outcome of one check for one domain.</summary>
public enum CheckOutcome {
    /// <summary>The check passed.</summary>
    Pass,
    /// <summary>Informational check (inventory or discovery) with nothing to fix.</summary>
    Info,
    /// <summary>At least one warning, no errors.</summary>
    Warning,
    /// <summary>At least one error.</summary>
    Error
}

/// <summary>One check (SPF, DMARC, DNSSEC, ...) for one domain.</summary>
public sealed class CheckAssessment {
    /// <summary>Stable key, unique within a domain (for example <c>spf</c> or <c>smtptls</c>).</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Health check that produced the result, when known.</summary>
    public HealthCheckType? Check { get; set; }

    /// <summary>Short title, for example "SPF".</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>Expanded name, for example "Sender Policy Framework".</summary>
    public string? LongTitle { get; set; }

    /// <summary>What the check verifies, in one sentence.</summary>
    public string? Description { get; set; }

    /// <summary>Analysis area the check belongs to.</summary>
    public AnalysisArea Area { get; set; }

    /// <summary>Outcome derived from the findings.</summary>
    public CheckOutcome Outcome { get; set; }

    /// <summary>Whether the check counts toward the domain score. Inventory and discovery checks do not.</summary>
    public bool Scored { get; set; }

    /// <summary>Check score (0–100).</summary>
    public int Score { get; set; }

    /// <summary>Weight of the check in the domain score.</summary>
    public int Weight { get; set; } = 1;

    /// <summary>One-line summary from the check, when it provides one.</summary>
    public string? Summary { get; set; }

    /// <summary>Warnings and errors (and informational notes) raised by the check.</summary>
    public List<CheckFinding> Findings { get; set; } = new();

    /// <summary>What the domain does well for this check.</summary>
    public List<string> Positives { get; set; } = new();

    /// <summary>Short highlights provided by the check.</summary>
    public List<string> Highlights { get; set; } = new();

    /// <summary>Key facts (record present, lookup count, policy, ...).</summary>
    public List<CheckFact> Facts { get; set; } = new();

    /// <summary>Evidence blocks: raw records, lists and tables.</summary>
    public List<CheckEvidence> Evidence { get; set; } = new();

    /// <summary>Recommended actions with why and how.</summary>
    public List<CheckGuidance> Recommendations { get; set; } = new();

    /// <summary>Narrative guidance (why it matters, remediation) when the check provides one.</summary>
    public NarrativeSections? Narrative { get; set; }

    /// <summary>Remediation hint from the check catalogue.</summary>
    public string? Remediation { get; set; }

    /// <summary>Reference links (RFCs, vendor documentation).</summary>
    public List<string> References { get; set; } = new();

    /// <summary>Number of error findings.</summary>
    public int ErrorCount { get; set; }

    /// <summary>Number of warning findings.</summary>
    public int WarningCount { get; set; }

    /// <summary>Source view objects the check was built from. Not serialized.</summary>
    [JsonIgnore]
    public List<object> Sources { get; set; } = new();
}

/// <summary>A warning, error or note raised by a check.</summary>
public sealed class CheckFinding {
    /// <summary>Severity reported by the check.</summary>
    public AssessmentSeverity Severity { get; set; }

    /// <summary>Stable finding code, when provided.</summary>
    public string? Code { get; set; }

    /// <summary>Human-readable message.</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>Record, host or selector the finding applies to, when provided.</summary>
    public string? Target { get; set; }
}

/// <summary>A labelled value.</summary>
public sealed class CheckFact {
    /// <summary>Fact label.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Formatted value.</summary>
    public string Value { get; set; } = string.Empty;
}

/// <summary>Kind of evidence block.</summary>
public enum CheckEvidenceKind {
    /// <summary>Raw text such as a DNS record, shown monospaced.</summary>
    Code,
    /// <summary>A list of values.</summary>
    List,
    /// <summary>A table with columns and rows.</summary>
    Table
}

/// <summary>Evidence behind a check result.</summary>
public sealed class CheckEvidence {
    /// <summary>Evidence title.</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>How the evidence is presented.</summary>
    public CheckEvidenceKind Kind { get; set; }

    /// <summary>Text for <see cref="CheckEvidenceKind.Code"/> evidence.</summary>
    public string? Text { get; set; }

    /// <summary>Values for <see cref="CheckEvidenceKind.List"/> evidence.</summary>
    public List<string> Items { get; set; } = new();

    /// <summary>Column headers for <see cref="CheckEvidenceKind.Table"/> evidence.</summary>
    public List<string> Columns { get; set; } = new();

    /// <summary>Rows for <see cref="CheckEvidenceKind.Table"/> evidence.</summary>
    public List<List<string>> Rows { get; set; } = new();

    /// <summary>Rows or items left out because the evidence was longer than the configured limit.</summary>
    public int Omitted { get; set; }
}

/// <summary>A recommended action.</summary>
public sealed class CheckGuidance {
    /// <summary>Recommendation code.</summary>
    public string? Code { get; set; }

    /// <summary>Action title.</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>Why the action matters.</summary>
    public string? Why { get; set; }

    /// <summary>How to carry out the action.</summary>
    public string? How { get; set; }

    /// <summary>Expected impact.</summary>
    public string? Impact { get; set; }

    /// <summary>Implementation effort.</summary>
    public string? Effort { get; set; }

    /// <summary>How to verify the change.</summary>
    public string? Verify { get; set; }

    /// <summary>Links with more detail.</summary>
    public List<string> Links { get; set; } = new();
}
