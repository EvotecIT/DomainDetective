using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private readonly AsyncLocal<bool> _ownsVerification = new();

    // Public per-check calls can retry a failed full-run owner. Their successful
    // result must replace that owner's failure without clearing another check.
    private Task CompleteDirectCheckAsync(HealthCheckType check, Func<Task> operation,
        CancellationToken cancellationToken = default, string? ownerDomain = null) {
        if (_ownsVerification.Value) { return operation(); }
        if (VerificationDomain == null && _verificationAdmission.CurrentCount != 0) {
            PrepareDirectRetry(check);
            return operation();
        }
        return CompleteAsync();

        async Task CompleteAsync() {
            await _verificationAdmission.WaitAsync(cancellationToken).ConfigureAwait(false);
            _ownsVerification.Value = true;
            try {
                var version = PrepareDirectRetry(check);
                await operation().ConfigureAwait(false);
                CompleteDirectResult(check, version, ownerDomain);
            } finally {
                _ownsVerification.Value = false;
                _verificationAdmission.Release();
            }
        }
    }

    private Task<T> CompleteDirectCheckAsync<T>(HealthCheckType check, Func<Task<T>> operation,
        CancellationToken cancellationToken = default, string? ownerDomain = null) {
        if (_ownsVerification.Value) { return operation(); }
        if (VerificationDomain == null && _verificationAdmission.CurrentCount != 0) {
            PrepareDirectRetry(check);
            return operation();
        }
        return CompleteAsync();

        async Task<T> CompleteAsync() {
            await _verificationAdmission.WaitAsync(cancellationToken).ConfigureAwait(false);
            _ownsVerification.Value = true;
            try {
                var version = PrepareDirectRetry(check);
                var result = await operation().ConfigureAwait(false);
                CompleteDirectResult(check, version, ownerDomain);
                return result;
            } finally {
                _ownsVerification.Value = false;
                _verificationAdmission.Release();
            }
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

    private void CompleteDirectResult(HealthCheckType check, long version, string? ownerDomain) {
        lock (_executionLock) {
            if (VerificationDomain == null || _executionStateVersion != version || _runOperations != null) { return; }
            if (ownerDomain != null && !IsVerificationOwner(ownerDomain)) { return; }
            _checkFailures.Remove(check);
            _checkFailureExceptions.Remove(check);
            Assessments.RemoveAll(value => value.Source == nameof(Verify) && value.Category == check.ToString()
                && (value.Code == "Verification.Check.Failed" || value.Code == "Verification.Check.Canceled"));
            _completedVerificationChecks.TryAdd(check, 0);
        }
    }

    private bool IsVerificationOwner(string ownerDomain) {
        // URL- and host-based entry points may include a scheme or explicit port.
        // A direct result for another host cannot satisfy the stored run owner.
        if (!Uri.TryCreate(ownerDomain.Contains("://") ? ownerDomain : "http://" + ownerDomain, UriKind.Absolute, out var uri)) { return false; }
        try {
            return string.Equals(NormalizeDomain(uri.IdnHost.TrimEnd('.')), NormalizeDomain(VerificationDomain!), StringComparison.OrdinalIgnoreCase);
        } catch (ArgumentException) { return false; }
    }
}
