using System.Collections.Generic;

namespace DomainDetective.Views;

/// <summary>Report projection of a check that could not complete, retaining its check identity and assessment.</summary>
public sealed class CheckFailureInfo {
    internal CheckFailureInfo(HealthCheckType check, Assessment failure) {
        Check = check;
        Subject = failure.Target;
        Assessments = new[] { failure };
    }

    /// <summary>Check that failed.</summary>
    public HealthCheckType Check { get; }
    /// <summary>Area containing the failed check.</summary>
    public AnalysisArea Area => Converters.AreaFor(Check);
    /// <summary>Domain under verification.</summary>
    public string? Subject { get; }
    /// <summary>Execution failure recorded by the verification run.</summary>
    public IReadOnlyList<Assessment> Assessments { get; }
    /// <summary>Error status for the incomplete check.</summary>
    public string Status => "Error";
    /// <summary>Number of errors in this projection.</summary>
    public int ErrorCount => 1;
    /// <summary>Number of warnings in this projection.</summary>
    public int WarningCount => 0;
    /// <summary>Execution failure details.</summary>
    public string Summary => Assessments[0].Message;
    /// <summary>Catalog advice for the failure assessment, when available.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.FromProblems(Assessments);
}
