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
        private const string ServerSet = "ServerName";
        private const string DomainSet = "DomainName";

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;

        /// <summary>SMTP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = ServerSet)]
        public string HostName = string.Empty;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = ServerSet)]
        public int Port = 25;

        /// <summary>Domain(s) to check (aggregates MX hosts).</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = DomainSet, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>Hostname expected in the banner.</summary>
        [Parameter(Mandatory = false)]
        public string ExpectedHostname = string.Empty;

        /// <summary>Software string expected in the banner.</summary>
        [Parameter(Mandatory = false)]
        public string ExpectedSoftware = string.Empty;

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            if (this.ParameterSetName == DomainSet) {
                async Task ProcessDomainAsync(string domain) {
                    var logger = new InternalLogger(false);
                    var internalLoggerPowerShell = new InternalLoggerPowerShell(
                        logger,
                        this.WriteVerbose,
                        this.WriteWarning,
                        this.WriteDebug,
                        this.WriteError,
                        this.WriteProgress,
                        this.WriteInformation);
                    internalLoggerPowerShell.ResetActivityIdCounter();
                    var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                    ApplyExecutionOptions(healthCheck);

                    healthCheck.SmtpBannerAnalysis.ExpectedHostname = ExpectedHostname;
                    healthCheck.SmtpBannerAnalysis.ExpectedSoftware = ExpectedSoftware;
                    logger.WriteVerbose("Checking SMTP banner across MX for domain {0}:{1}", domain, Port);
                    await healthCheck.VerifySMTPBanner(domain, Port, cancellationToken: CancelToken);
                    var view = DomainDetective.Views.Converters.Convert(healthCheck.SmtpBannerAnalysis);
                    WriteObject(view);
                    if (IsExportRequested()) {
                        await ExportNotImplementedAsync("Test-DDEmailSmtpBanner");
                    }
                }

                await ForEachAsync(DomainName, ProcessDomainAsync);
                return;
            }

            var directLogger = new InternalLogger(false);
            var directLoggerPowerShell = new InternalLoggerPowerShell(
                directLogger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            directLoggerPowerShell.ResetActivityIdCounter();
            var directHealthCheck = new DomainHealthCheck(DnsEndpoint, directLogger);
            ApplyExecutionOptions(directHealthCheck);

            directHealthCheck.SmtpBannerAnalysis.ExpectedHostname = ExpectedHostname;
            directHealthCheck.SmtpBannerAnalysis.ExpectedSoftware = ExpectedSoftware;
            directLogger.WriteVerbose("Checking SMTP banner for {0}:{1}", HostName, Port);
            await directHealthCheck.CheckSmtpBannerHost(HostName, Port, cancellationToken: CancelToken);
            var directView = DomainDetective.Views.Converters.Convert(directHealthCheck.SmtpBannerAnalysis);
            WriteObject(directView);
            if (IsExportRequested()) {
                await ExportNotImplementedAsync("Test-DDEmailSmtpBanner");
            }
        }
    }
}
