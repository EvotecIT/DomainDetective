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

    // A composite awaits the same operation as a selected top-level check. The
    // dependency runs outside the top-level gate, so a composite cannot occupy
    // the final slot while waiting for a prerequisite queued behind itself.
    private void ConfigureRunOperations(Dictionary<HealthCheckType, Func<Task>> actions, string domainName, HealthCheckType[] selectedChecks) {
        var operations = actions.ToDictionary(pair => pair.Key, pair => new Lazy<Task>(pair.Value,
            LazyThreadSafetyMode.ExecutionAndPublication));
        _runDomain = domainName;
        _selectedRunChecks = new HashSet<HealthCheckType>(selectedChecks);
        _runOperations = operations;
        foreach (var type in operations.Keys) {
            var operation = operations[type];
            actions[type] = () => operation.Value;
        }
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
        return Task.WhenAll(
            AwaitSelectedPrerequisiteAsync(HealthCheckType.DMARC, domain),
            RunPrerequisiteAsync(HealthCheckType.MX, domain, () => VerifyMX(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.SPF, domain, () => VerifySPF(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.DKIM, domain, () => VerifyDKIM(domain, Array.Empty<string>(), cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.MTASTS, domain, () => VerifyMTASTS(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.TLSRPT, domain, () => VerifyTLSRPT(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.BIMI, domain, () => VerifyBIMI(domain, true, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.IDENTITYPROVIDER, domain, () => VerifyIdpInfo(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.DANE, domain, () => VerifyDANE(domain, new[] { ServiceType.SMTP }, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.APEXADDRESS, domain, () => VerifyApexAddresses(domain, cancellationToken)));
    }

    private Task CollectMicrosoft365SignalsAsync(string domain, CancellationToken cancellationToken) =>
        Task.WhenAll(
            RunPrerequisiteAsync(HealthCheckType.IDENTITYPROVIDER, domain, () => VerifyIdpInfo(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.DNSINVENTORY, domain, () => VerifyDnsInventoryAsync(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.SUBDOMAINS, domain, () => VerifySubdomainsAsync(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.AUTODISCOVER, domain, () => VerifyAutodiscover(domain, cancellationToken)),
            RunPrerequisiteAsync(HealthCheckType.DKIM, domain, () => VerifyDKIM(domain, Array.Empty<string>(), cancellationToken)));
}
