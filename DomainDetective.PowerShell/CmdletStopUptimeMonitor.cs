using DomainDetective.Monitoring;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Stops a running uptime monitor.</summary>
    /// <para>Cancels the active probe and waits for its callbacks to finish.</para>
    /// <example>
    ///   <summary>Stop monitoring.</summary>
    ///   <code>Stop-DDUptimeMonitor -Monitor $monitor</code>
    /// </example>
    [Cmdlet(VerbsLifecycle.Stop, "DDUptimeMonitor")]
    [Alias("Stop-UptimeMonitor")]
    public sealed class CmdletStopUptimeMonitor : AsyncPSCmdlet {
        /// <summary>Monitor instance returned by Start-DDUptimeMonitor.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        public UptimeMonitor Monitor = null!;

        /// <summary>
        /// Stops the provided uptime monitor instance.
        /// </summary>
        /// <returns>A task that completes after the active probe and callbacks stop.</returns>
        protected override Task ProcessRecordAsync() {
            return Monitor.StopAsync();
        }
    }
}
