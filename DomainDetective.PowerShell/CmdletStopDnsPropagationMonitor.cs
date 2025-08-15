using DomainDetective.Monitoring;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Stops a running DNS propagation monitor.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Stop monitoring.</summary>
    ///   <code>Stop-DDDnsPropagationMonitor -Monitor $monitor</code>
    /// </example>
    [Cmdlet(VerbsLifecycle.Stop, "DDDnsPropagationMonitor")]
    [Alias("Stop-DnsPropagationMonitor")]
    public sealed class CmdletStopDnsPropagationMonitor : AsyncPSCmdlet {
        /// <summary>Monitor instance returned by Start-DnsPropagationMonitor.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        public DnsPropagationMonitor Monitor = null!;

        /// <summary>
        /// Stops the specified DNS propagation monitor instance.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task ProcessRecordAsync() {
            Monitor.Stop();
            return Task.CompletedTask;
        }
    }
}
