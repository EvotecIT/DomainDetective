using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates SPF record for a domain.</summary>
    /// <example>
    ///   <summary>Check SPF configuration.</summary>
    ///   <code>Test-SpfRecord -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "SpfRecord", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestSpfRecord : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        //[Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        //public SwitchParameter FullResponse;

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
            _logger.WriteVerbose("Querying SPF record for domain: {0}", DomainName);
            await healthCheck.VerifySPF(DomainName);
            WriteObject(healthCheck.SpfAnalysis);
        }
    }
}