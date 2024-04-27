using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

using DnsClientX;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsDiagnostic.Test, "DkimRecord", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestDkimRecord : AsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string DomainName;

        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServerName")]
        public string[] Selectors;

        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying DKIM records for domain: {0}", DomainName);
            await healthCheck.VerifyDKIM(DomainName, Selectors);
            WriteObject(healthCheck.DKIMAnalysis);
        }
    }
}
