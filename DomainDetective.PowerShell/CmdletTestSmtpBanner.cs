using System.Management.Automation;
using DomainDetective.Views;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves SMTP banner information from a host or across MX hosts.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Returns a unified SmtpBannerInfo view. Use the DomainName parameter set to check all MX hosts.
    /// The returned view includes Assessments, Status, Counts, Recommendations, References and Raw (full analysis).
    /// </remarks>
    /// <example>
    ///   <summary>Check SMTP banner on a specific host.</summary>
    ///   <code>Test-DDEmailSmtpBanner -HostName mail.example.com -Port 25</code>
    /// </example>
    /// <example>
    ///   <summary>Check SMTP banner across MX hosts.</summary>
    ///   <code>Test-DDEmailSmtpBanner -DomainName example.com -Port 25</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDEmailSmtpBanner", DefaultParameterSetName = "ServerName")]
    [Alias("Test-EmailSmtpBanner", "Test-SmtpBanner")]
    [OutputType(typeof(SmtpBannerInfo))]
    public sealed class CmdletTestSmtpBanner : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        private const string ServerSet = "ServerName";
        private const string DomainSet = "DomainName";
        /// <summary>SMTP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = ServerSet)]
        public string HostName = string.Empty;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = ServerSet)]
        public int Port = 25;

        /// <summary>Domain to check (aggregates MX hosts).</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = DomainSet)]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <summary>Hostname expected in the banner.</summary>
        [Parameter(Mandatory = false)]
        public string ExpectedHostname = string.Empty;

        /// <summary>Software string expected in the banner.</summary>
        [Parameter(Mandatory = false)]
        public string ExpectedSoftware = string.Empty;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _healthCheck.SmtpBannerAnalysis.ExpectedHostname = ExpectedHostname;
            _healthCheck.SmtpBannerAnalysis.ExpectedSoftware = ExpectedSoftware;
            if (this.ParameterSetName == DomainSet) {
                _logger.WriteVerbose("Checking SMTP banner across MX for domain {0}:{1}", DomainName, Port);
                await _healthCheck.VerifySMTPBanner(DomainName, Port);
            } else {
                _logger.WriteVerbose("Checking SMTP banner for {0}:{1}", HostName, Port);
                await _healthCheck.CheckSmtpBannerHost(HostName, Port);
            }
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.SmtpBannerAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
