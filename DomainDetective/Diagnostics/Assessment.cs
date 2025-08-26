using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Represents an assessment captured during analysis (warning, error, info).
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class Assessment {
    /// <summary>Severity of the assessment.</summary>
    public AssessmentSeverity Severity { get; set; }
    /// <summary>Short, human-readable message.</summary>
    public string Message { get; set; } = string.Empty;
    /// <summary>Optional stable code for programmatic use.</summary>
    public string? Code { get; set; }
    /// <summary>High-level category (e.g., DMARC, DNSSEC, DANE).</summary>
    public string Category { get; set; } = "General";
    /// <summary>Optional sub-source or component name.</summary>
    public string? Source { get; set; }
    /// <summary>Entity being assessed (domain, host, selector, etc.).</summary>
    public string? Target { get; set; }
    /// <summary>UTC timestamp when created.</summary>
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Optional metadata for additional context.</summary>
    public Dictionary<string, string> Metadata { get; set; } = new();
}

/// <summary>
/// Severity levels for assessments.
/// </summary>
public enum AssessmentSeverity {
    Info = 0,
    Warning = 1,
    Error = 2
}

/// <summary>
/// Optional interface for analysis classes that expose assessments.
/// </summary>
public interface IHasAssessments {
    List<Assessment> Assessments { get; }
}

