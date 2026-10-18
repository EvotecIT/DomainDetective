using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private readonly SemaphoreSlim _verificationAdmission = new(1, 1);
    private Dictionary<HealthCheckType, Lazy<Task>>? _runOperations;
    private string? _runDomain;
    private HashSet<HealthCheckType>? _selectedRunChecks;
    private bool _runNeedsSmtpDane;
    private SemaphoreSlim? _runCheckAdmission;

    // Admit actual checks, not orchestration waiting on them. Composite and selected
    // paths share each leaf once without reserving a slot for an awaiting parent.
    private void ConfigureRunOperations(Dictionary<HealthCheckType, Func<Task>> actions, string domainName,
        HealthCheckType[] selectedChecks, SemaphoreSlim admission, bool sequential, CancellationToken cancellationToken) {
        _runCheckAdmission = admission;
        var operations = new Dictionary<HealthCheckType, Lazy<Task>>();
        foreach (var pair in actions) {
            var type = pair.Key;
            var action = pair.Value;
            operations[type] = new Lazy<Task>(async () => {
                // SMTP alignment awaits the selected DANE owner. With one slot,
                // establish that prerequisite before admitting SMTP itself.
                if (sequential && type == HealthCheckType.SMTPTLS && selectedChecks.Contains(HealthCheckType.DANE)) {
                    await operations[HealthCheckType.DANE].Value.ConfigureAwait(false);
                }
                if (type is HealthCheckType.MAILCLASSIFICATION or HealthCheckType.MICROSOFT365
                    or HealthCheckType.WEBSITE or HealthCheckType.DELEGATION) {
                    await action().ConfigureAwait(false);
                } else {
                    await RunAdmittedCheckAsync(action, cancellationToken, type.ToString()).ConfigureAwait(false);
                }
            }, LazyThreadSafetyMode.ExecutionAndPublication);
        }
        _runDomain = domainName;
        _selectedRunChecks = new HashSet<HealthCheckType>(selectedChecks);
        _runOperations = operations;
        foreach (var type in operations.Keys) {
            var operation = operations[type];
            actions[type] = () => operation.Value;
        }
    }

    private async Task RunAdmittedCheckAsync(Func<Task> action, CancellationToken cancellationToken, string? checkName = null) {
        var admission = _runCheckAdmission;
        if (admission == null) { await action().ConfigureAwait(false); return; }
        await admission.WaitAsync(cancellationToken).ConfigureAwait(false);
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        try {
            if (checkName != null) { _logger.WriteVerbose("Starting {0} check.", checkName); }
            await action().ConfigureAwait(false);
            if (checkName != null) { _logger.WriteVerbose("{0} check completed in {1} ms.", checkName, elapsed.ElapsedMilliseconds); }
        }
        catch {
            if (checkName != null) { _logger.WriteVerbose("{0} check failed after {1} ms.", checkName, elapsed.ElapsedMilliseconds); }
            throw;
        }
        finally { admission.Release(); }
    }

    private Task RunSignalCollectionAsync(string domain, CancellationToken cancellationToken, params Func<Task>[] actions) {
        if (_runOperations != null && string.Equals(_runDomain, domain, StringComparison.OrdinalIgnoreCase)) {
            return Task.WhenAll(actions.Select(action => action()));
        }
        int maximum = ExecutionOptions.EnableParallelism ? ExecutionOptions.GetEffectiveMaxParallelism() : 1;
        return Helpers.BoundedAsync.RunAsync(actions, async action => {
            await action().ConfigureAwait(false);
            return true;
        }, maximum, cancellationToken);
    }

    private Task RunPrerequisiteAsync(HealthCheckType type, string domainName, Func<Task> directOperation) {
        var operations = _runOperations;
        return operations != null && string.Equals(_runDomain, domainName, StringComparison.OrdinalIgnoreCase)
            && operations.TryGetValue(type, out var operation) ? operation.Value : directOperation();
    }

    private Task AwaitSelectedPrerequisiteAsync(HealthCheckType type, string domainName) =>
        _selectedRunChecks?.Contains(type) == true
            ? RunPrerequisiteAsync(type, domainName, () => Task.CompletedTask) : Task.CompletedTask;

    internal Task CollectMailClassificationSignalsAsync(string domain, CancellationToken cancellationToken) {
        if (_runOperations == null) { ResetExecutionState(); }
        return RunSignalCollectionAsync(domain, cancellationToken,
            () => AwaitSelectedPrerequisiteAsync(HealthCheckType.DMARC, domain),
            () => RunPrerequisiteAsync(HealthCheckType.MX, domain, () => VerifyMX(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.SPF, domain, () => VerifySPF(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.DKIM, domain, () => VerifyDKIM(domain, Array.Empty<string>(), cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.MTASTS, domain, () => VerifyMTASTS(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.TLSRPT, domain, () => VerifyTLSRPT(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.BIMI, domain, () => VerifyBIMI(domain, true, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.IDENTITYPROVIDER, domain, () => VerifyIdpInfo(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.DANE, domain, () => VerifyDANE(domain, new[] { ServiceType.SMTP }, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.APEXADDRESS, domain, () => VerifyApexAddresses(domain, cancellationToken)));
    }

    private Task CollectMicrosoft365SignalsAsync(string domain, CancellationToken cancellationToken) =>
        RunSignalCollectionAsync(domain, cancellationToken,
            () => RunPrerequisiteAsync(HealthCheckType.IDENTITYPROVIDER, domain, () => VerifyIdpInfo(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.DNSINVENTORY, domain, () => VerifyDnsInventoryAsync(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.SUBDOMAINS, domain, () => VerifySubdomainsAsync(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.AUTODISCOVER, domain, () => VerifyAutodiscover(domain, cancellationToken)),
            () => RunPrerequisiteAsync(HealthCheckType.DKIM, domain, () => VerifyDKIM(domain, Array.Empty<string>(), cancellationToken)));
}
