using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks if an SMTP server is an open relay.</summary>
    /// <para>Returns an <see cref="OpenRelayStatus"/> describing the result.</para>
    /// <example>
    ///   <summary>Test a mail server.</summary>
    /// <para>Part of the DomainDetective project.</para>
    ///   <code>Test-OpenRelay -HostName mail.example.com -Port 25</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "OpenRelay", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestOpenRelay : AsyncPSCmdlet {
        /// <param name="HostName">SMTP host name to check.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string HostName;

        /// <param name="Port">SMTP port number.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

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
            _logger.WriteVerbose("Checking open relay for {0}:{1}", HostName, Port);
            await _healthCheck.CheckOpenRelayHost(HostName, Port);
            WriteObject(_healthCheck.OpenRelayAnalysis.ServerResults[$"{HostName}:{Port}"]); 
        }
    }
}