using System;
using System.Collections.Generic;

namespace DomainDetective;

public partial class DomainHealthCheck : IHasAssessments {
    private readonly Dictionary<HealthCheckType, Assessment> _checkFailures = new();

    /// <summary>Execution failures from the last verification run. Analysis findings are available through <see cref="GetAllAssessments"/>.</summary>
    public List<Assessment> Assessments { get; } = new();

    internal Assessment? GetCheckFailure(HealthCheckType check) {
        lock (_executionLock) {
            return _checkFailures.TryGetValue(check, out var failure) ? failure : null;
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
}
