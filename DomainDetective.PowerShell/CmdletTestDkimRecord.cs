using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DKIM records for the specified selectors.</summary>
    /// <example>
    ///   <summary>Verify DKIM selectors.</summary>
    ///   <code>Test-DkimRecord -DomainName example.com -Selectors selector1</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DkimRecord", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestDkimRecord : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="Selectors">Selectors to validate.</param>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] Selectors;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <param name="FullResponse">Return full analysis result.</param>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        /// <param name="Raw">Return raw response objects.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter Raw;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying DKIM records for domain: {0}", DomainName);
            await healthCheck.VerifyDKIM(DomainName, Selectors);
            if (Raw) {
                WriteObject(healthCheck.DKIMAnalysis);
            } else {
                var output = OutputHelper.Convert(healthCheck.DKIMAnalysis);
                WriteObject(output, true);
            }
        }
    }
}