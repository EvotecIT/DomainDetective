using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves SMTP banner information from a host.</summary>
    /// <example>
    ///   <summary>Check SMTP banner.</summary>
    ///   <code>Test-SmtpBanner -HostName mail.example.com -Port 25</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "SmtpBanner", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestSmtpBanner : AsyncPSCmdlet {
        /// <param name="HostName">SMTP host to check.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName;

        /// <param name="Port">SMTP port number.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        /// <param name="ExpectedHostname">Hostname expected in the banner.</param>
        [Parameter(Mandatory = false)]
        public string ExpectedHostname;

        /// <param name="ExpectedSoftware">Software string expected in the banner.</param>
        [Parameter(Mandatory = false)]
        public string ExpectedSoftware;

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
            _logger.WriteVerbose("Checking SMTP banner for {0}:{1}", HostName, Port);
            _healthCheck.SmtpBannerAnalysis.ExpectedHostname = ExpectedHostname;
            _healthCheck.SmtpBannerAnalysis.ExpectedSoftware = ExpectedSoftware;
            await _healthCheck.CheckSmtpBannerHost(HostName, Port);
            WriteObject(_healthCheck.SmtpBannerAnalysis.ServerResults[$"{HostName}:{Port}"]);
        }
    }
}
