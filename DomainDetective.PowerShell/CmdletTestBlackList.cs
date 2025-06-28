using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Queries DNSBL providers to see if domains or IPs are listed.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check a single host.</summary>
    ///   <code>Test-DomainBlacklist -NameOrIpAddress example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DomainBlacklist", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestBlackList : AsyncPSCmdlet {
        /// <param name="NameOrIpAddress">Domain names or IP addresses to check.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] NameOrIpAddress;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <param name="FullResponse">Return full analysis result.</param>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

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