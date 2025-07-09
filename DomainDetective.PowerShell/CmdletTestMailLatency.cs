using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Measures SMTP connection and banner latency.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check mail latency for a server.</summary>
    ///   <code>Test-MailLatency -HostName mail.example.com -Port 25</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "MailLatency", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestMailLatency : AsyncPSCmdlet {
        /// <param name="HostName">SMTP host to check.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName;

        /// <param name="Port">SMTP port number.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var helper = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            helper.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(internalLogger: _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Measuring mail latency for {0}:{1}", HostName, Port);
            await _healthCheck.CheckMailLatency(HostName, Port);
            WriteObject(_healthCheck.MailLatencyAnalysis.ServerResults[$"{HostName}:{Port}"]);
        }
    }
}
