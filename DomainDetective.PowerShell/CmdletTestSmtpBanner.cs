using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves SMTP banner information from a host.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check SMTP banner.</summary>
    ///   <code>Test-DDSmtpBanner -HostName mail.example.com -Port 25</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDSmtpBanner", DefaultParameterSetName = "ServerName")]
    [Alias("Test-SmtpBanner")]
    public sealed class CmdletTestSmtpBanner : AsyncPSCmdlet {
        /// <summary>SMTP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        /// <summary>Hostname expected in the banner.</summary>
        [Parameter(Mandatory = false)]
        public string ExpectedHostname;

        /// <summary>Software string expected in the banner.</summary>
        [Parameter(Mandatory = false)]
        public string ExpectedSoftware;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(internalLogger: _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking SMTP banner for {0}:{1}", HostName, Port);
            _healthCheck.SmtpBannerAnalysis.ExpectedHostname = ExpectedHostname;
            _healthCheck.SmtpBannerAnalysis.ExpectedSoftware = ExpectedSoftware;
            await _healthCheck.CheckSmtpBannerHost(HostName, Port);
            WriteObject(_healthCheck.SmtpBannerAnalysis.ServerResults[$"{HostName}:{Port}"]);
        }
    }
}
