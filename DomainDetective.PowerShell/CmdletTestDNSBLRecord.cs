using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Enumerates raw DNSBL records for a domain or IP address.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>List DNSBL records.</summary>
    ///   <code>Test-DNSBLRecord -NameOrIpAddress example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DNSBLRecord", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletTestDNSBLRecord : AsyncPSCmdlet {
        /// <param name="NameOrIpAddress">Domain or IP to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string NameOrIpAddress;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
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
            _logger.WriteVerbose("Querying DNSBL records for name/ip address: {0}", NameOrIpAddress);
            await foreach (var record in healthCheck.DNSBLAnalysis.AnalyzeDNSBLRecords(NameOrIpAddress, _logger)) {
                WriteObject(record);
            }
        }
    }
}