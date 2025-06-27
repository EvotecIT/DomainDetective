using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks connectivity to common service ports on a host.</summary>
    /// <example>
    ///   <summary>Check ports on a server.</summary>
    ///   <code>Test-PortAvailability -HostName mail.example.com -Ports 25,443</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "PortAvailability", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestPortAvailability : AsyncPSCmdlet {
        /// <param name="HostName">Host to test.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName;

        /// <param name="Ports">Ports to check.</param>
        [Parameter(Mandatory = false)]
        public int[] Ports = new[] { 25, 80, 443, 465, 587 };

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(internalLogger: _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking ports on {0}", HostName);
            await _healthCheck.CheckPortAvailability(HostName, Ports);
            WriteObject(_healthCheck.PortAvailabilityAnalysis.ServerResults, true);
        }
    }
}
