using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
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
        if (domainNames == null) {
            return Array.Empty<DomainHealthCheckRun>();
        }

        cancellationToken.ThrowIfCancellationRequested();
        var options = executionOptions ?? new HealthCheckExecutionOptions();
        int maxParallel = options.EnableParallelism ? options.GetEffectiveDomainParallelism() : 1;
        bool ownsHealthChecks = healthCheckFactory == null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var gate = new object();
        var results = new List<DomainHealthCheckRun?>();
        ExceptionDispatchInfo? failure = null;
        IEnumerator<string>? input = null;

        async Task<DomainHealthCheckRun> RunAsync(string domain) {
            DomainHealthCheck? health = null;
            try {
                stop.Token.ThrowIfCancellationRequested();
                health = healthCheckFactory != null ? healthCheckFactory(domain) : new DomainHealthCheck();
                if (health == null) {
                    throw new InvalidOperationException("Health check factory returned null.");
                }
                await health.Verify(domain, healthCheckTypes, dkimSelectors, daneServiceType,
                    danePorts, portScanProfiles, stop.Token, options).ConfigureAwait(false);
                return new DomainHealthCheckRun(domain, health, null, ownsHealthChecks);
            } catch (OperationCanceledException) when (stop.IsCancellationRequested) {
                if (ownsHealthChecks) { health?.Dispose(); }
                throw;
            } catch (Exception ex) {
                return new DomainHealthCheckRun(domain, health, ex, ownsHealthChecks);
            }
        }

        async Task WorkerAsync() {
            try {
                while (true) {
                    string domain;
                    int index;
                    lock (gate) {
                        do {
                            stop.Token.ThrowIfCancellationRequested();
                            if (!input!.MoveNext()) { return; }
                            domain = input.Current;
                        } while (string.IsNullOrWhiteSpace(domain));
                        index = results.Count;
                        results.Add(null);
                    }
                    DomainHealthCheckRun result = await RunAsync(domain).ConfigureAwait(false);
                    lock (gate) { results[index] = result; }
                }
            } catch (Exception ex) {
                lock (gate) { failure ??= ExceptionDispatchInfo.Capture(ex); }
                stop.Cancel();
            }
        }

        try {
            input = domainNames.GetEnumerator();
            var workers = new Task[Math.Max(1, maxParallel)];
            for (int worker = 0; worker < workers.Length; worker++) {
                workers[worker] = Task.Run(WorkerAsync);
            }
            await Task.WhenAll(workers).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            failure?.Throw();
            // Enumerator disposal is part of completing the batch; a failure here also
            // releases owned results instead of losing their resources behind an exception.
            IEnumerator<string> completedInput = input;
            input = null;
            completedInput.Dispose();
            return results.ConvertAll(result => result!).ToArray();
        } catch {
            foreach (DomainHealthCheckRun? result in results) { result?.Dispose(); }
            throw;
        } finally {
            input?.Dispose();
        }
    }
}
