using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;

namespace DomainDetective.PowerShell {
    /// <summary>
    /// Base cmdlet providing parallel execution parameters and helpers.
    /// </summary>
    public abstract class ParallelAsyncPSCmdlet : AsyncPSCmdlet {
        /// <summary>Disable parallel execution for cmdlet-level work.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter DisableParallel { get; set; }

        /// <summary>Maximum number of concurrent items for cmdlet-level parallel work.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(ParallelExecutionDefaults.MinParallelism, ParallelExecutionDefaults.MaxParallelism)]
        public int? ThrottleLimit { get; set; }

        /// <summary>Maximum concurrent health checks within a single domain run.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(ParallelExecutionDefaults.MinParallelism, ParallelExecutionDefaults.MaxParallelism)]
        public int? MaxParallelism { get; set; }

        /// <summary>DNS resolver concurrency hint for health checks.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(ParallelExecutionDefaults.MinParallelism, ParallelExecutionDefaults.MaxParallelism)]
        public int? DnsParallelism { get; set; }

        /// <summary>Optional list of resolver endpoints to use (multi-resolver).</summary>
        [Parameter(Mandatory = false)]
        public DnsEndpoint[]? DnsEndpoints { get; set; }

        /// <summary>Strategy used when multiple DNS endpoints are provided.</summary>
        [Parameter(Mandatory = false)]
        public MultiResolverStrategy MultiResolverStrategy { get; set; } = MultiResolverStrategy.FirstSuccess;

        /// <summary>Maximum number of resolvers to query in parallel (null = all).</summary>
        [Parameter(Mandatory = false)]
        public int? MultiResolverMaxParallelism { get; set; }

        /// <summary>Applies shared execution options to a health check instance.</summary>
        protected void ApplyExecutionOptions(DomainHealthCheck healthCheck) {
            healthCheck.ExecutionOptions.EnableParallelism = !DisableParallel.IsPresent;
            if (MaxParallelism.HasValue) {
                healthCheck.ExecutionOptions.MaxParallelism = MaxParallelism.Value;
            }
            if (DnsParallelism.HasValue) {
                healthCheck.ExecutionOptions.DnsParallelism = DnsParallelism.Value;
                if (healthCheck.DnsConfiguration.SupportsResolverConcurrency) {
                    healthCheck.ResolverMaxConcurrency = DnsParallelism.Value;
                }
                if (!healthCheck.MultiResolverMaxParallelism.HasValue) {
                    healthCheck.MultiResolverMaxParallelism = DnsParallelism.Value;
                }
            }
            if (DnsEndpoints != null && DnsEndpoints.Length > 0)
            {
                healthCheck.DnsEndpoints.Clear();
                healthCheck.DnsEndpoints.AddRange(DnsEndpoints);
                healthCheck.MultiResolverStrategy = MultiResolverStrategy;
                if (MultiResolverMaxParallelism.HasValue)
                {
                    healthCheck.MultiResolverMaxParallelism = MultiResolverMaxParallelism.Value;
                }
            }
            healthCheck.ConfigureExecution();
        }

        /// <summary>Runs the provided action over inputs with optional throttling.</summary>
        protected async Task ForEachAsync<T>(IReadOnlyList<T> items, Func<T, Task> action) {
            if (items == null || items.Count == 0) {
                return;
            }
            async Task InvokeSafeAsync(T item) {
                var label = item?.ToString() ?? "<null>";
                var isVerbose = IsVerboseEnabled();
                Stopwatch? sw = null;
                if (isVerbose) {
                    WriteVerbose($"Starting item '{label}'.");
                    sw = Stopwatch.StartNew();
                }
                try {
                    await action(item);
                } catch (OperationCanceledException) {
                    throw;
                } catch (PipelineStoppedException) {
                    throw;
                } catch (Exception ex) {
                    WriteWarning($"Parallel item '{label}' failed: {ex.Message}");
                    WriteVerbose(ex.ToString());
                } finally {
                    if (sw != null) {
                        sw.Stop();
                        WriteVerbose($"Completed item '{label}' in {sw.ElapsedMilliseconds} ms.");
                    }
                }
            }
            if (DisableParallel.IsPresent || items.Count == 1) {
                foreach (var item in items) {
                    CancelToken.ThrowIfCancellationRequested();
                    await InvokeSafeAsync(item);
                }
                return;
            }

            var throttle = GetEffectiveThrottleLimit();
            WriteVerbose($"Parallel execution enabled: {items.Count} item(s), throttle {throttle}.");
            using var gate = new SemaphoreSlim(throttle, throttle);
            var tasks = new Task[items.Count];
            for (var i = 0; i < items.Count; i++) {
                var local = items[i];
                tasks[i] = Task.Run(async () => {
                    await gate.WaitAsync(CancelToken);
                    try {
                        await InvokeSafeAsync(local);
                    } finally {
                        gate.Release();
                    }
                }, CancelToken);
            }
            await Task.WhenAll(tasks);
        }

        /// <summary>Returns the effective throttle limit for cmdlet-level parallelism.</summary>
        protected int GetEffectiveThrottleLimit() {
            return ParallelExecutionDefaults.GetThrottleLimit(ThrottleLimit);
        }

        /// <summary>Returns true when verbose output is enabled for this invocation.</summary>
        protected bool IsVerboseEnabled() {
            if (MyInvocation?.BoundParameters?.ContainsKey("Verbose") == true) {
                return true;
            }
            var pref = GetVariableValue("VerbosePreference");
            if (pref is ActionPreference ap) {
                return ap != ActionPreference.SilentlyContinue;
            }
            return false;
        }
    }
}
