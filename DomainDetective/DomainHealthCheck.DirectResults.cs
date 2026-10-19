using System;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    // Public per-check calls can retry a failed full-run owner. Their successful
    // result must replace that owner's failure without clearing another check.
    private Task CompleteDirectCheckAsync(HealthCheckType check, Func<Task> operation) {
        if (_runOperations != null) { return operation(); }
        var version = PrepareDirectRetry(check);
        return CompleteAsync(operation());

        async Task CompleteAsync(Task pending) {
            await pending.ConfigureAwait(false);
            CompleteDirectResult(check, version);
        }
    }

    private Task<T> CompleteDirectCheckAsync<T>(HealthCheckType check, Func<Task<T>> operation) {
        if (_runOperations != null) { return operation(); }
        var version = PrepareDirectRetry(check);
        return CompleteAsync(operation());

        async Task<T> CompleteAsync(Task<T> pending) {
            var result = await pending.ConfigureAwait(false);
            CompleteDirectResult(check, version);
            return result;
        }
    }

    private long PrepareDirectRetry(HealthCheckType check) {
        lock (_executionLock) {
            // A previous run's failed prerequisites cannot answer a fresh retry.
            if (_checkFailures.ContainsKey(check)) { ResetSharedExecutionState(); }
            if (_spfTask?.IsFaulted == true || _spfTask?.IsCanceled == true) { _spfTask = null; }
            if (_mxRecordsTask?.IsFaulted == true || _mxRecordsTask?.IsCanceled == true) { _mxRecordsTask = null; }
            if (_mxHostsTask?.IsFaulted == true || _mxHostsTask?.IsCanceled == true) { _mxHostsTask = null; }
            if (_reverseDnsTask?.IsFaulted == true || _reverseDnsTask?.IsCanceled == true) { _reverseDnsTask = null; }
            if (_daneTask?.IsFaulted == true || _daneTask?.IsCanceled == true) { _daneTask = null; _daneKey = null; }
            if (_smtpTlsTasks != null) {
                foreach (var key in _smtpTlsTasks.Where(pair => pair.Value.IsFaulted || pair.Value.IsCanceled).Select(pair => pair.Key).ToArray()) {
                    _smtpTlsTasks.Remove(key);
                }
            }
            return _executionStateVersion;
        }
    }

    private void CompleteDirectResult(HealthCheckType check, long version) {
        lock (_executionLock) {
            if (VerificationDomain == null || _executionStateVersion != version || _runOperations != null) { return; }
            _checkFailures.Remove(check);
            _checkFailureExceptions.Remove(check);
            Assessments.RemoveAll(value => value.Source == nameof(Verify) && value.Category == check.ToString()
                && (value.Code == "Verification.Check.Failed" || value.Code == "Verification.Check.Canceled"));
            _completedVerificationChecks.TryAdd(check, 0);
        }
    }
}
