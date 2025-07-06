using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves flattened SPF IP addresses for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <para>Use the <c>TestSpfRecord</c> parameter to supply an SPF record during tests.</para>
    /// <example>
    ///   <summary>Get flattened SPF IPs.</summary>
    ///   <code>Get-FlattenedSpfIp -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "FlattenedSpfIp", DefaultParameterSetName = "ServerName")]
    public sealed class CmdletGetFlattenedSpfIp : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <param name="TestSpfRecord">Optional SPF record used for testing to avoid DNS lookups.</param>
        [Parameter(Mandatory = false)]
        public string TestSpfRecord;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            if (!string.IsNullOrEmpty(TestSpfRecord)) {
                _healthCheck.SpfAnalysis.TestSpfRecords[DomainName] = TestSpfRecord;
            }
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Flattening SPF IPs for domain: {0}", DomainName);
            await _healthCheck.VerifySPF(DomainName);
            var ips = await _healthCheck.SpfAnalysis.GetFlattenedIpAddresses(DomainName, _logger);
            WriteObject(ips, true);
        }
    }
}
