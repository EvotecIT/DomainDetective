using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;

namespace DomainDetective;

/// <summary>
/// Result of a batch domain health check run.
/// </summary>
public sealed class DomainHealthCheckRun {
    /// <summary>Creates a new batch run result.</summary>
    /// <param name="domainName">Domain name that was processed.</param>
    /// <param name="healthCheck">Health check instance (when available).</param>
    /// <param name="error">Captured error, if any.</param>
    public DomainHealthCheckRun(string domainName, DomainHealthCheck? healthCheck, Exception? error) {
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
}

public partial class DomainHealthCheck {
    /// <summary>
    /// Runs domain health checks for multiple domains with optional parallelism.
    /// </summary>
    /// <param name="domainNames">Domains to process.</param>
    /// <param name="healthCheckTypes">Health checks to execute or <c>null</c> for defaults.</param>
    /// <param name="dkimSelectors">DKIM selectors to use when verifying DKIM.</param>
    /// <param name="daneServiceType">DANE service types to inspect. When <c>null</c>, SMTP and HTTPS (port 443) are queried.</param>
    /// <param name="danePorts">Custom ports to check for DANE. Overrides <paramref name="daneServiceType"/> when provided.</param>
    /// <param name="portScanProfiles">Optional port scan profiles to use.</param>
    /// <param name="executionOptions">Optional execution settings for this batch run.</param>
    /// <param name="healthCheckFactory">Factory for per-domain <see cref="DomainHealthCheck"/> instances.</param>
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
        if (domainNames == null) {
            return Array.Empty<DomainHealthCheckRun>();
        }

        var domains = domainNames
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .ToList();
        if (domains.Count == 0) {
            return Array.Empty<DomainHealthCheckRun>();
        }

        var options = executionOptions ?? new HealthCheckExecutionOptions();
        var maxParallel = options.EnableParallelism ? options.GetEffectiveDomainParallelism() : 1;
        if (maxParallel < 1) {
            maxParallel = 1;
        }

        async Task<DomainHealthCheckRun> RunAsync(string domain) {
            cancellationToken.ThrowIfCancellationRequested();
            var healthCheck = healthCheckFactory != null ? healthCheckFactory(domain) : new DomainHealthCheck();
            if (healthCheck == null) {
                throw new InvalidOperationException("Health check factory returned null.");
            }
            try {
                await healthCheck.Verify(
                    domain,
                    healthCheckTypes,
                    dkimSelectors,
                    daneServiceType,
                    danePorts,
                    portScanProfiles,
                    cancellationToken,
                    options);
                return new DomainHealthCheckRun(domain, healthCheck, null);
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                return new DomainHealthCheckRun(domain, healthCheck, ex);
            }
        }

        var results = new DomainHealthCheckRun[domains.Count];
        if (maxParallel == 1 || domains.Count == 1) {
            for (var i = 0; i < domains.Count; i++) {
                results[i] = await RunAsync(domains[i]);
            }
            return results;
        }

        using var gate = new SemaphoreSlim(maxParallel, maxParallel);
        var tasks = new Task[domains.Count];
        for (var i = 0; i < domains.Count; i++) {
            var idx = i;
            var domain = domains[idx];
            tasks[idx] = Task.Run(async () => {
                await gate.WaitAsync(cancellationToken);
                try {
                    results[idx] = await RunAsync(domain);
                } finally {
                    gate.Release();
                }
            }, cancellationToken);
        }
        await Task.WhenAll(tasks);
        return results;
    }
}
