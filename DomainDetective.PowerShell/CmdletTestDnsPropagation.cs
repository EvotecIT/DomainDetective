using DnsClientX;
using System;
using DomainDetective;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks how DNS records propagate across public resolvers.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Test propagation of an A record.</summary>
    ///   <code>$file = Join-Path (Split-Path ([System.Reflection.Assembly]::GetExecutingAssembly().Location)) 'Data/DNS/PublicDNS.json'; Test-DnsPropagation -DomainName example.com -RecordType A -ServersFile $file</code>
    /// </example>
    [Cmdlet(
        VerbsDiagnostic.Test,
        "DnsPropagation",
        DefaultParameterSetName = "Builtin")]
    public sealed class CmdletTestDnsPropagation : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to query.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Builtin")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="RecordType">DNS record type to test.</param>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Builtin")]
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServersFile")]
        public DnsRecordType RecordType;

        /// <param name="ServersFile">Path to JSON file with DNS servers.</param>
        [Parameter(Mandatory = true, Position = 2, ParameterSetName = "ServersFile")]
        public string ServersFile;

        /// <param name="Country">Filter servers by country.</param>
        [Parameter(Mandatory = false)]
        public CountryId? Country;

        /// <param name="Location">Filter servers by location.</param>
        [Parameter(Mandatory = false)]
        public LocationId? Location;

        /// <param name="Asn">Filter servers by ASN.</param>
        [Parameter(Mandatory = false)]
        public string? Asn;

        /// <param name="AsnName">Filter servers by ASN name.</param>
        [Parameter(Mandatory = false)]
        public string? AsnName;

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
            if (ParameterSetName == "ServersFile") {
                var path = Path.IsPathRooted(ServersFile)
                    ? ServersFile
                    : Path.Combine(
                        Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty,
                        ServersFile);
                _analysis.LoadServers(path, clearExisting: true);
            } else {
                _analysis.LoadBuiltinServers();
            }
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            IEnumerable<PublicDnsEntry> servers = _analysis.FilterServers(Country, Location, Take, Asn, AsnName);
            var serverList = servers.ToList();
            var progress = new Progress<double>(p => {
                var record = new ProgressRecord(1, "DnsPropagation", $"{p:F0}% complete") {
                    PercentComplete = (int)p
                };
                if (p >= 100) {
                    record.RecordType = ProgressRecordType.Completed;
                }
                WriteProgress(record);
            });
            var results = await _analysis.QueryAsync(DomainName, RecordType, serverList, CancelToken, progress);
            if (CompareResults) {
                var details = DnsPropagationAnalysis.GetComparisonDetails(results);
                WriteObject(details, true);
            } else {
                WriteObject(results, true);
            }
        }
    }
}