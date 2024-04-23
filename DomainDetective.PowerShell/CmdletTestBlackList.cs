using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

using DnsClientX;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsDiagnostic.Test, "DomainBlacklist", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestBlackList : AsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string[] NameOrIpAddress;

        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
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
            _logger.WriteVerbose("Querying DNSBL BlackLists for names/ip addresses: {0}", string.Join(", ", NameOrIpAddress));
            await healthCheck.CheckDNSBL(NameOrIpAddress);
            if (NameOrIpAddress.Length == 1) {
                if (FullResponse) {
                    WriteObject(healthCheck.DNSBLAnalysis.Results[NameOrIpAddress[0]]);
                } else {
                    WriteObject(healthCheck.DNSBLAnalysis.Results[NameOrIpAddress[0]].DNSBLRecords);
                }
            } else {
                if (FullResponse) {
                    WriteObject(healthCheck.DNSBLAnalysis.Results);
                } else {
                    var dnsblRecords = healthCheck.DNSBLAnalysis.Results.Values.SelectMany(result => result.DNSBLRecords).ToList();
                    WriteObject(dnsblRecords);
                }
            }
        }
    }
}
