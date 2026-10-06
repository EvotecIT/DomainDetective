using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>Runs a bounded batch and processes each result without retaining the complete batch.</summary>
    /// <remarks>The callback is awaited as part of a domain's admission slot and may run concurrently
    /// up to <see cref="HealthCheckExecutionOptions.MaxDomainParallelism"/>. Results arrive as checks
    /// complete, rather than in input order. Library-created health checks are disposed after the
    /// callback completes; copy the required observations inside the callback. Factory-supplied
    /// health checks remain caller owned. Callback failure stops admission and drains active checks.</remarks>
    /// <param name="domainNames">Domains to process.</param>
    /// <param name="processResult">Asynchronous consumer of each completed result, including failed checks.</param>
    /// <param name="healthCheckTypes">Health checks to execute or <c>null</c> for defaults.</param>
    /// <param name="dkimSelectors">DKIM selectors to use when verifying DKIM.</param>
    /// <param name="daneServiceType">DANE service types to inspect.</param>
    /// <param name="danePorts">Custom DANE ports, overriding service types when provided.</param>
    /// <param name="portScanProfiles">Optional port scan profiles to use.</param>
    /// <param name="executionOptions">Optional execution settings for the batch and checks.</param>
    /// <param name="healthCheckFactory">Factory for independent caller-owned health checks.</param>
    /// <param name="cancellationToken">Token to cancel admission, checks and result processing.</param>
    public static Task ProcessBatchAsync(
        IEnumerable<string> domainNames,
        Func<DomainHealthCheckRun, CancellationToken, Task> processResult,
        HealthCheckType[]? healthCheckTypes = null,
        string[]? dkimSelectors = null,
        ServiceType[]? daneServiceType = null,
        int[]? danePorts = null,
        PortScanProfile[]? portScanProfiles = null,
        HealthCheckExecutionOptions? executionOptions = null,
        Func<string, DomainHealthCheck>? healthCheckFactory = null,
        CancellationToken cancellationToken = default) {
        if (processResult == null) { throw new ArgumentNullException(nameof(processResult)); }
        return RunBatchCoreAsync(domainNames, healthCheckTypes, dkimSelectors, daneServiceType,
            danePorts, portScanProfiles, executionOptions, healthCheckFactory, cancellationToken,
            retainResults: false, onAdmitted: null,
            onResult: (_, result, token) => processResult(result, token));
    }

    private static async Task RunBatchCoreAsync(
        IEnumerable<string> domainNames, HealthCheckType[]? healthCheckTypes, string[]? dkimSelectors,
        ServiceType[]? daneServiceType, int[]? danePorts, PortScanProfile[]? portScanProfiles,
        HealthCheckExecutionOptions? executionOptions, Func<string, DomainHealthCheck>? healthCheckFactory,
        CancellationToken cancellationToken, bool retainResults, Action<int>? onAdmitted,
        Func<int, DomainHealthCheckRun, CancellationToken, Task> onResult) {
        if (domainNames == null) { return; }
        cancellationToken.ThrowIfCancellationRequested();
        var options = executionOptions ?? new HealthCheckExecutionOptions();
        int maxParallel = options.EnableParallelism ? options.GetEffectiveDomainParallelism() : 1;
        bool ownsHealthChecks = healthCheckFactory == null;
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var gate = new object();
        int nextIndex = 0;
        ExceptionDispatchInfo? failure = null;
        IEnumerator<string>? input = null;

        async Task<DomainHealthCheckRun> RunAsync(string domain) {
            DomainHealthCheck? health = null;
            try {
                stop.Token.ThrowIfCancellationRequested();
                health = healthCheckFactory != null ? healthCheckFactory(domain) : new DomainHealthCheck();
                if (health == null) { throw new InvalidOperationException("Health check factory returned null."); }
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
                        index = nextIndex++;
                        onAdmitted?.Invoke(index);
                    }
                    DomainHealthCheckRun result = await RunAsync(domain).ConfigureAwait(false);
                    try {
                        stop.Token.ThrowIfCancellationRequested();
                        await onResult(index, result, stop.Token).ConfigureAwait(false);
                    } catch {
                        result.Dispose();
                        throw;
                    } finally {
                        if (!retainResults) { result.Dispose(); }
                    }
                }
            } catch (Exception ex) {
                lock (gate) { failure ??= ExceptionDispatchInfo.Capture(ex); }
                stop.Cancel();
            }
        }

        ExceptionDispatchInfo? primaryError = null;
        try {
            input = domainNames.GetEnumerator();
            var workers = new Task[Math.Max(1, maxParallel)];
            for (int worker = 0; worker < workers.Length; worker++) { workers[worker] = Task.Run(WorkerAsync); }
            await Task.WhenAll(workers).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            failure?.Throw();
        } catch (Exception ex) {
            primaryError = ExceptionDispatchInfo.Capture(ex);
        } finally {
            try { input?.Dispose(); }
            catch (Exception ex) { primaryError ??= ExceptionDispatchInfo.Capture(ex); }
        }
        primaryError?.Throw();
    }
}
