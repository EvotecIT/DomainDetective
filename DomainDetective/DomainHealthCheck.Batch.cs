using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;

namespace DomainDetective;

/// <summary>
/// Result of a batch domain health check run.
/// </summary>
public sealed class DomainHealthCheckRun : IDisposable {
    private int _disposed;
    /// <summary>Creates a new batch run result.</summary>
    /// <param name="domainName">Domain name that was processed.</param>
    /// <param name="healthCheck">Health check instance (when available), whose ownership is transferred to this result.</param>
    /// <param name="error">Captured error, if any.</param>
    public DomainHealthCheckRun(string domainName, DomainHealthCheck? healthCheck, Exception? error)
        : this(domainName, healthCheck, error, ownsHealthCheck: true) {
    }

    internal DomainHealthCheckRun(string domainName, DomainHealthCheck? healthCheck, Exception? error, bool ownsHealthCheck) {
        OwnsHealthCheck = ownsHealthCheck;
        DomainName = domainName;
        HealthCheck = healthCheck;
        Error = error;
    }

    /// <summary>Domain name that was processed.</summary>
    public string DomainName { get; }

    /// <summary>Health check instance populated with results when successful.</summary>
    public DomainHealthCheck? HealthCheck { get; }

    /// <summary>Error captured during the run, if any.</summary>
    public Exception? Error { get; }

    /// <summary>True when the run completed without errors.</summary>
    public bool Success => Error == null;

    /// <summary>True when this result owns the health check and disposes it on request.</summary>
    public bool OwnsHealthCheck { get; }

    /// <summary>Releases an owned health check. Factory-supplied instances remain caller owned.</summary>
    public void Dispose() {
        if (OwnsHealthCheck && Interlocked.Exchange(ref _disposed, 1) == 0) {
            HealthCheck?.Dispose();
        }
    }
}

public partial class DomainHealthCheck {
    /// <summary>
    /// Runs domain health checks for multiple domains with optional parallelism.
    /// </summary>
    /// <remarks>Input is enumerated as workers admit domains. Results retain input order. Dispose
    /// returned results to release library-created health checks; on a failed or canceled batch,
    /// the library releases those instances after all workers finish.</remarks>
    /// <param name="domainNames">Domains to process.</param>
    /// <param name="healthCheckTypes">Health checks to execute or <c>null</c> for defaults.</param>
    /// <param name="dkimSelectors">DKIM selectors to use when verifying DKIM.</param>
    /// <param name="daneServiceType">DANE service types to inspect. When <c>null</c>, SMTP and HTTPS (port 443) are queried.</param>
    /// <param name="danePorts">Custom ports to check for DANE. Overrides <paramref name="daneServiceType"/> when provided.</param>
    /// <param name="portScanProfiles">Optional port scan profiles to use.</param>
    /// <param name="executionOptions">Optional execution settings for this batch run.</param>
    /// <param name="healthCheckFactory">Factory for independent per-domain <see cref="DomainHealthCheck"/> instances. Factory-supplied instances remain caller owned.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    public static async Task<IReadOnlyList<DomainHealthCheckRun>> VerifyBatchAsync(
        IEnumerable<string> domainNames,
        HealthCheckType[]? healthCheckTypes = null,
        string[]? dkimSelectors = null,
        ServiceType[]? daneServiceType = null,
        int[]? danePorts = null,
        PortScanProfile[]? portScanProfiles = null,
        HealthCheckExecutionOptions? executionOptions = null,
        Func<string, DomainHealthCheck>? healthCheckFactory = null,
        CancellationToken cancellationToken = default) {
        var resultsGate = new object();
        var results = new List<DomainHealthCheckRun?>();
        try {
            await RunBatchCoreAsync(domainNames, healthCheckTypes, dkimSelectors, daneServiceType,
                danePorts, portScanProfiles, executionOptions, healthCheckFactory, cancellationToken,
                retainResults: true,
                onAdmitted: _ => { lock (resultsGate) { results.Add(null); } },
                onResult: (index, result, _) => {
                    lock (resultsGate) { results[index] = result; }
                    return Task.CompletedTask;
                }).ConfigureAwait(false);
            return results.ConvertAll(result => result!).ToArray();
        } catch {
            foreach (DomainHealthCheckRun? result in results) { result?.Dispose(); }
            throw;
        }
    }
}
