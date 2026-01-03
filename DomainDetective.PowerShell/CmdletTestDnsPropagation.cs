using DnsClientX;
using System;
using DomainDetective;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using DomainDetective.Helpers;
using System.Management.Automation;
using System.Reflection;
using System.Threading;
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
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Builtin")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

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

        /// <summary>Return a typed view object suitable for composition reports.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter AsView;

        /// <summary>Maximum number of resolver results retained in the view (default: 500).</summary>
        [Parameter(Mandatory = false)]
        public int MaxResultsToKeep = 500;

        /// <summary>Directory used to store DNS snapshots.</summary>
        [Parameter(Mandatory = false)]
        public string SnapshotPath = string.Empty;

        /// <summary>Return changes since last snapshot.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Diff;

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
	            protected override async Task ProcessRecordAsync() {
	            DnsPropagationAnalysis BuildAnalysis() {
	                var analysis = new DnsPropagationAnalysis();
	                if (ParameterSetName == "ServersFile") {
	                    var path = Path.IsPathRooted(ServersFile)
	                        ? Path.GetFullPath(ServersFile)
	                        : PathHelper.CombineUnderRoot(
	                            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty,
	                            ServersFile);
	                    analysis.LoadServers(path, clearExisting: true);
	                } else {
	                    analysis.LoadBuiltinServers();
	                }
	                if (!string.IsNullOrEmpty(SnapshotPath)) {
                    analysis.SnapshotDirectory = SnapshotPath;
                }
                return analysis;
            }

            var selectionAnalysis = BuildAnalysis();
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
                servers = selectionAnalysis.SelectServers(dict);
            } else {
                var query = DnsServerQuery.Create().FilterServers(Country, Location, Take);
                servers = selectionAnalysis.FilterServers(query);
            }
            var serverList = servers.ToList();
            var progressCounter = 0;

            async Task ProcessDomainAsync(string domain) {
                var analysis = new DnsPropagationAnalysis();
                if (!string.IsNullOrEmpty(SnapshotPath)) {
                    analysis.SnapshotDirectory = SnapshotPath;
                }
                var progressId = Interlocked.Increment(ref progressCounter);
                var progress = new Progress<double>(p => {
                    var record = new ProgressRecord(progressId, $"DnsPropagation ({domain})", $"{p:F0}% complete") {
                        PercentComplete = (int)p
                    };
                    if (p >= 100) {
                        record.RecordType = ProgressRecordType.Completed;
                    }
                    WriteProgress(record);
                });
                var results = await analysis.QueryAsync(domain, RecordType, serverList, CancelToken, progress);
                IEnumerable<string>? changes = null;
                if (Diff.IsPresent) {
                    changes = analysis.GetSnapshotChanges(domain, RecordType, results);
                }
                if (CompareResults) {
                    var details = DnsPropagationAnalysis.GetComparisonDetails(results);
                    WriteObject(details, true);
                } else if (AsView.IsPresent) {
                    var report = new DnsPropagationReportAnalysis();
                    report.Load(domain, RecordType, results, maxResultsToKeep: MaxResultsToKeep);
                    var view = DomainDetective.Views.Converters.Convert(report);
                    WriteObject(view);
                } else {
                    WriteObject(results, true);
                }
                if (!string.IsNullOrEmpty(SnapshotPath)) {
                    analysis.SaveSnapshot(domain, RecordType, results);
                }
                if (changes != null && changes.Any()) {
                    WriteObject(changes, true);
                }
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync();
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}


