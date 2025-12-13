using DnsClientX;
using System;
using DomainDetective;
using System.Collections;
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
    ///   <code>$file = Join-Path (Split-Path ([System.Reflection.Assembly]::GetExecutingAssembly().Location)) 'Data/DNS/PublicDNS.json'; Test-DDDnsPropagation -DomainName example.com -RecordType A -ServersFile $file</code>
    /// </example>
    /// <example>
    ///   <summary>Select servers by country.</summary>
    ///   <code>Test-DDDnsPropagation -DomainName example.com -RecordType A -CountryCount @{PL=3;DE=2}</code>
    /// </example>
    [Cmdlet(
        VerbsDiagnostic.Test,
        "DDDnsPropagation",
        DefaultParameterSetName = "Builtin")]
[Alias("Test-DnsPropagation")]
    public sealed class CmdletTestDnsPropagation : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Builtin")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <summary>DNS record type to test.</summary>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Builtin")]
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServersFile")]
        public DnsRecordType RecordType;

        /// <summary>Path to JSON file with DNS servers.</summary>
        [Parameter(Mandatory = true, Position = 2, ParameterSetName = "ServersFile")]
        public string ServersFile = string.Empty;

        /// <summary>Filter servers by country.</summary>
        [Parameter(Mandatory = false)]
        public CountryId? Country;

        /// <summary>Filter servers by location.</summary>
        [Parameter(Mandatory = false)]
        public LocationId? Location;

        /// <summary>Limit the number of servers queried.</summary>
        [Parameter(Mandatory = false)]
        public int? Take;

        /// <summary>Select number of servers per country.</summary>
        [Parameter(Mandatory = false)]
        public Hashtable? CountryCount;

        /// <summary>Return aggregated comparison of results.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter CompareResults;

        /// <summary>Directory used to store DNS snapshots.</summary>
        [Parameter(Mandatory = false)]
        public string SnapshotPath = string.Empty;

        /// <summary>Return changes since last snapshot.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Diff;

        private InternalLogger _logger = null!;
        private DnsPropagationAnalysis _analysis = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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
            if (!string.IsNullOrEmpty(SnapshotPath)) {
                _analysis.SnapshotDirectory = SnapshotPath;
            }
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            IEnumerable<PublicDnsEntry> servers;
            if (CountryCount != null && CountryCount.Count > 0) {
                var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                foreach (DictionaryEntry de in CountryCount) {
                    if (de.Key == null || de.Value == null) {
                        continue;
                    }
                    if (int.TryParse(de.Value.ToString(), out var count)) {
                        dict[de.Key.ToString() ?? string.Empty] = count;
                    }
                }
                servers = _analysis.SelectServers(dict);
            } else {
                var query = DnsServerQuery.Create().FilterServers(Country, Location, Take);
                servers = _analysis.FilterServers(query);
            }
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
            IEnumerable<string>? changes = null;
            if (Diff.IsPresent) {
                changes = _analysis.GetSnapshotChanges(DomainName, RecordType, results);
            }
            if (CompareResults) {
                var details = DnsPropagationAnalysis.GetComparisonDetails(results);
                WriteObject(details, true);
            } else {
                WriteObject(results, true);
            }
            if (!string.IsNullOrEmpty(SnapshotPath)) {
                _analysis.SaveSnapshot(DomainName, RecordType, results);
            }
            if (changes != null && changes.Any()) {
                WriteObject(changes, true);
            }
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
