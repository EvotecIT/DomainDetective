using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsDiagnostic.Test, "TlsRptRecord", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestTlsRptRecord : AsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string DomainName;

        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying TLSRPT record for domain: {0}", DomainName);
            await healthCheck.VerifyTLSRPT(DomainName);
            WriteObject(healthCheck.TLSRPTAnalysis);
        }
    }
}
