using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;

namespace DomainDetective.CLI;

internal static partial class CommandUtilities {
    private static async Task<IReadOnlyList<DomainHealthCheckRun>> RunDomainBatchAsync(string[] domains,
        HealthCheckType[] checks, int[]? danePorts, PortScanProfileDefinition.PortScanProfile[]? portProfiles,
        Func<string, DomainHealthCheck> factory, bool showProgress, bool includePlainHttp, bool includeTakeover, CancellationToken token) {
        // The core owns domain admission, shared DNS limits, cancellation and
        // result order. The CLI owns presentation and factory-created results.
        var owned = new List<DomainHealthCheck>();
        DomainHealthCheck Create(string domain) {
            var health = factory(domain);
            lock (owned) { owned.Add(health); }
            return health;
        }
        async Task<IReadOnlyList<DomainHealthCheckRun>> RunAsync() =>
            await DomainHealthCheck.VerifyBatchAsync(domains, checks, danePorts: danePorts,
                portScanProfiles: portProfiles, healthCheckFactory: Create,
                executionOptions: new HealthCheckExecutionOptions { IncludePlainHttp = includePlainHttp, IncludeTakeoverCname = includeTakeover }, cancellationToken: token).ConfigureAwait(false);
        try {
            if (!showProgress) { return await RunAsync().ConfigureAwait(false); }
            return await AnsiConsole.Status().StartAsync("Running domain health checks", async _ =>
                await RunAsync().ConfigureAwait(false)).ConfigureAwait(false);
        } catch {
            foreach (var health in owned) { health.Dispose(); }
            throw;
        }
    }
}
