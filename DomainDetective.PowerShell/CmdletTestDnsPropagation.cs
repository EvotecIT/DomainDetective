using DnsClientX;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks how DNS records propagate across public resolvers.</summary>
    /// <example>
    ///   <summary>Test propagation of an A record.</summary>
    ///   <code>Test-DnsPropagation -DomainName example.com -RecordType A -ServersFile ./PublicDNS.json</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DnsPropagation", DefaultParameterSetName = "ServersFile")]
    public sealed class CmdletTestDnsPropagation : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="RecordType">DNS record type to test.</param>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServersFile")]
        public DnsRecordType RecordType;

        /// <param name="ServersFile">Path to JSON file with DNS servers.</param>
        [Parameter(Mandatory = true, Position = 2, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        public string ServersFile;

        /// <param name="Country">Filter servers by country.</param>
        [Parameter(Mandatory = false)]
        public string Country;

        /// <param name="Location">Filter servers by location.</param>
        [Parameter(Mandatory = false)]
        public string Location;

        /// <param name="Take">Limit the number of servers queried.</param>
        [Parameter(Mandatory = false)]
        public int? Take;

        /// <param name="CompareResults">Return aggregated comparison of results.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter CompareResults;

        private InternalLogger _logger;
        private DnsPropagationAnalysis _analysis;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _analysis = new DnsPropagationAnalysis();
            _analysis.LoadServers(ServersFile, clearExisting: true);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            IEnumerable<PublicDnsEntry> servers = _analysis.FilterServers(Country, Location, Take);
            var results = await _analysis.QueryAsync(DomainName, RecordType, servers);
            if (CompareResults) {
                var comparison = DnsPropagationAnalysis.CompareResults(results);
                WriteObject(comparison);
            } else {
                WriteObject(results, true);
            }
        }
    }
}