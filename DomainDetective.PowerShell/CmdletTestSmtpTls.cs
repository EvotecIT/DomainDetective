using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks TLS configuration for a specific SMTP host.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Test mail server TLS.</summary>
    ///   <code>Test-SmtpTls -HostName mail.example.com -Port 587</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "SmtpTls", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestSmtpTls : AsyncPSCmdlet {
        /// <param name="HostName">SMTP host to check.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName;

        /// <param name="Port">SMTP port number.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        /// <param name="ShowChain">Output certificate chain information.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

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
            _logger.WriteVerbose("Checking SMTP TLS for {0}:{1}", HostName, Port);
            await _healthCheck.CheckSmtpTlsHost(HostName, Port);
            var result = _healthCheck.SmtpTlsAnalysis.ServerResults[$"{HostName}:{Port}"];
            WriteObject(result);
            if (ShowChain && result.Chain.Count > 0) {
                WriteObject(result.Chain, true);
            }
        }
    }
}