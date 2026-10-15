using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class DomainHealthCheck : IHasAssessments {
    internal string? VerificationDomain { get; private set; }
    private readonly Dictionary<HealthCheckType, Assessment> _checkFailures = new();

    /// <summary>Execution failures from the last verification run. Analysis findings are available through <see cref="GetAllAssessments"/>.</summary>
    public List<Assessment> Assessments { get; } = new();

    internal Assessment? GetCheckFailure(HealthCheckType check) {
        lock (_executionLock) {
            if (_checkFailures.TryGetValue(check, out var failure)) { return failure; }
            // Explicit view selections and policies may name a check that this run never admitted.
            // A manually assembled health object has no verification domain and remains convertible.
            return VerificationDomain != null && !LastVerifiedChecks.Contains(check) ? new Assessment {
                Severity = AssessmentSeverity.Warning, Code = "Verification.Check.NotRun",
                Category = check.ToString(), Source = nameof(Verify), Target = VerificationDomain,
                Message = $"{check}: no current result is available because this verification run did not admit the check."
            } : null;
        }
    }

    private void RecordCheckFailure(HealthCheckType check, string domain, Exception exception) {
        var failure = new Assessment {
            Severity = AssessmentSeverity.Error,
            Code = "Verification.Check.Failed",
            Category = check.ToString(),
            Source = nameof(Verify),
            Target = domain,
            Message = $"{check}: {exception.GetType().Name}: {exception.Message}"
        };
        lock (_executionLock) {
            _checkFailures[check] = failure;
            Assessments.Add(failure);
        }
        _logger.WriteErrorCode(failure.Code, "{0}", failure.Message);
    }

    private void RecordCheckCancellation(HealthCheckType check, string domain) {
        var incomplete = new Assessment {
            Severity = AssessmentSeverity.Warning, Code = "Verification.Check.Canceled",
            Category = check.ToString(), Source = nameof(Verify), Target = domain,
            Message = $"{check}: caller cancellation interrupted the check; its result is incomplete."
        };
        lock (_executionLock) {
            _checkFailures[check] = incomplete;
            Assessments.Add(incomplete);
        }
    }
}
