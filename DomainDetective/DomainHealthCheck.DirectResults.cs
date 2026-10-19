using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private readonly AsyncLocal<bool> _ownsVerification = new();

    // Public per-check calls can retry a failed full-run owner. Their successful
    // result must replace that owner's failure without clearing another check.
    private Task CompleteDirectCheckAsync(HealthCheckType check, Func<Task> operation,
        CancellationToken cancellationToken = default, string? ownerDomain = null, IEnumerable<string>? ownerDomains = null) {
        if (_ownsVerification.Value) { return operation(); }
        if (VerificationDomain == null && _verificationAdmission.CurrentCount != 0) {
            PrepareDirectRetry(check);
            return operation();
        }
        var owners = ownerDomains?.ToArray();
        return CompleteAsync();

        async Task CompleteAsync() {
            await _verificationAdmission.WaitAsync(cancellationToken).ConfigureAwait(false);
            _ownsVerification.Value = true;
            try {
                var version = PrepareDirectRetry(check);
                await operation().ConfigureAwait(false);
                CompleteDirectResult(check, version, ownerDomain, owners);
            } finally {
                _ownsVerification.Value = false;
                _verificationAdmission.Release();
            }
        }
    }

    private Task<T> CompleteDirectCheckAsync<T>(HealthCheckType check, Func<Task<T>> operation,
        CancellationToken cancellationToken = default, string? ownerDomain = null, IEnumerable<string>? ownerDomains = null) {
        if (_ownsVerification.Value) { return operation(); }
        if (VerificationDomain == null && _verificationAdmission.CurrentCount != 0) {
            PrepareDirectRetry(check);
            return operation();
        }
        var owners = ownerDomains?.ToArray();
        return CompleteAsync();

        async Task<T> CompleteAsync() {
            await _verificationAdmission.WaitAsync(cancellationToken).ConfigureAwait(false);
            _ownsVerification.Value = true;
            try {
                var version = PrepareDirectRetry(check);
                var result = await operation().ConfigureAwait(false);
                CompleteDirectResult(check, version, ownerDomain, owners);
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

    private void CompleteDirectResult(HealthCheckType check, long version, string? ownerDomain, string[]? ownerDomains) {
        lock (_executionLock) {
            if (VerificationDomain == null || _executionStateVersion != version || _runOperations != null) { return; }
            if (ownerDomain != null && !IsVerificationOwner(ownerDomain)) { return; }
            // A mixed or empty target set cannot repair the current domain's
            // failed owner. Raw-record APIs deliberately have no target set.
            if (ownerDomains != null && (ownerDomains.Length == 0 || !ownerDomains.All(IsVerificationOwner))) { return; }
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
        if (!TryOwnerUri(ownerDomain, out var incoming) || !TryOwnerUri(VerificationDomain!, out var stored)) { return false; }
        try {
            if (!string.Equals(NormalizeDomain(incoming!.IdnHost.TrimEnd('.')), NormalizeDomain(stored!.IdnHost.TrimEnd('.')), StringComparison.OrdinalIgnoreCase)) { return false; }
            return incoming.Port == stored.Port || incoming.Port < 0 && stored.Port is 80 or 443 || stored.Port < 0 && incoming.Port is 80 or 443;
        } catch (ArgumentException) { return false; }
    }

    private static bool TryOwnerUri(string value, out Uri? uri) {
        int scheme = value.IndexOf("://", StringComparison.Ordinal);
        // tcp has no implicit port, preserving explicit :80 and :443 too.
        string authority = scheme >= 0 ? value.Substring(scheme + 3) : EndpointHostNormalizer.FormatForUriAuthority(value);
        return Uri.TryCreate("tcp://" + authority, UriKind.Absolute, out uri);
    }
}
