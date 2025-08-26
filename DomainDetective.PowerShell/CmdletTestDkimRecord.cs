using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DKIM records for the specified selectors.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Verify DKIM selectors.</summary>
    ///   <code>Test-DDEmailDkimRecord -DomainName example.com -Selectors selector1</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailDkimRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailDkim")]
    public sealed class CmdletTestDkimRecord : ExportableAsyncPSCmdlet {
        /// <para>Domain to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <para>Selectors to validate.</para>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] Selectors;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Return full analysis result.</para>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        /// <para>Return raw response objects.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter Raw;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

        /// <summary>
        /// Initializes DKIM checking with the current settings.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }
        /// <summary>
        /// Validates DKIM records for the provided selectors.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying DKIM records for domain: {0}", DomainName);
            await healthCheck.VerifyDKIM(DomainName, Selectors);
            if (Raw) {
                WriteObject(healthCheck.DKIMAnalysis);
            } else {
                var output = OutputHelper.Convert(healthCheck.DKIMAnalysis);
                WriteObject(output, true);
            }
            if (IsExportRequested()) {
                await ExportNotImplementedAsync("Test-DDEmailDkimRecord"); // TODO: Dedicated DKIM report
                return;
            }
        }
    }
}
