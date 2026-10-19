using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;

namespace DomainDetective;

public partial class DomainHealthCheck : IHasAssessments {
    internal string? VerificationDomain { get; private set; }
    private readonly Dictionary<HealthCheckType, Assessment> _checkFailures = new();
    private readonly Dictionary<HealthCheckType, ExceptionDispatchInfo> _checkFailureExceptions = new();
    private readonly HashSet<HealthCheckType> _admittedVerificationChecks = new();

    /// <summary>Selected checks admitted by the last valid verification run, including explicitly recorded failures.</summary>
    public IReadOnlyList<HealthCheckType> LastVerifiedChecks { get; private set; } = Array.Empty<HealthCheckType>();

    private void MarkCheckAdmitted(HealthCheckType check) {
        lock (_executionLock) {
            _admittedVerificationChecks.Add(check);
            LastVerifiedChecks = VerificationRequestedChecks.Where(_admittedVerificationChecks.Contains).ToArray();
        }
    }

    private void ThrowRecordedCheckFailure() {
        ExceptionDispatchInfo? failure;
        lock (_executionLock) { failure = _checkFailureExceptions.Values.FirstOrDefault(); }
        failure?.Throw();
    }

    private bool HasCheckExecutionFailure(HealthCheckType check) {
        lock (_executionLock) { return _checkFailures.ContainsKey(check); }
    }

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
            _checkFailureExceptions[check] = ExceptionDispatchInfo.Capture(exception);
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
            if (_checkFailures.ContainsKey(check)) { return; }
            _checkFailures[check] = incomplete;
            Assessments.Add(incomplete);
        }
    }

    private void CopyExecutionFailuresTo(DomainHealthCheck filtered, HashSet<HealthCheckType> active) {
        filtered.LastVerifiedChecks = LastVerifiedChecks.Where(active.Contains).ToArray();
        filtered.VerificationDomain = VerificationDomain;
        lock (_executionLock) {
            foreach (var failure in _checkFailures) {
                if (!active.Contains(failure.Key)) { continue; }
                var copy = new Assessment {
                    Severity = failure.Value.Severity, Code = failure.Value.Code, Category = failure.Value.Category,
                    Source = failure.Value.Source, Target = failure.Value.Target, Message = failure.Value.Message,
                    Timestamp = failure.Value.Timestamp,
                    Metadata = new Dictionary<string, string>(failure.Value.Metadata ?? new Dictionary<string, string>())
                };
                filtered._checkFailures[failure.Key] = copy;
                filtered.Assessments.Add(copy);
            }
        }
    }
}
