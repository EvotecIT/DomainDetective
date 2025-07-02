using DomainDetective.Monitoring;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Stops a running DNS propagation monitor.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Stop monitoring.</summary>
    ///   <code>Stop-DnsPropagationMonitor -Monitor $monitor</code>
    /// </example>
    [Cmdlet(VerbsLifecycle.Stop, "DnsPropagationMonitor")]
    public sealed class CmdletStopDnsPropagationMonitor : AsyncPSCmdlet {
        /// <param name="Monitor">Monitor instance returned by Start-DnsPropagationMonitor.</param>
        [Parameter(Mandatory = true, Position = 0)]
        public DnsPropagationMonitor Monitor = null!;

        protected override Task ProcessRecordAsync() {
            Monitor.Stop();
            return Task.CompletedTask;
        }
    }
}
