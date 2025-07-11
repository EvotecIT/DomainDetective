using DomainDetective;
using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DNSSEC configuration for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check DNSSEC records.</summary>
    ///   <code>Test-DnsSec -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsSecStatus", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsSec")]
    public sealed class CmdletTestDnsSec : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="DnsEndpoint">DNS server used for queries.</param>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <param name="Raw">Return raw analysis object.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter Raw;

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
            _logger.WriteVerbose("Querying DNSSEC for domain: {0}", DomainName);
            await healthCheck.VerifyDNSSEC(DomainName);
            if (Raw) {
                WriteObject(healthCheck.DnsSecAnalysis);
            } else {
                DnsSecInfo info = DnsSecConverter.Convert(healthCheck.DnsSecAnalysis);
                WriteObject(info);
            }
        }
    }
}