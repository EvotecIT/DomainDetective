using DnsClientX;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsDiagnostic.Test, "DnsPropagation", DefaultParameterSetName = "ServersFile")]
    public sealed class CmdletTestDnsPropagation : AsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ServersFile")]
        public DnsRecordType RecordType;

        [Parameter(Mandatory = true, Position = 2, ParameterSetName = "ServersFile")]
        [ValidateNotNullOrEmpty]
        public string ServersFile;

        [Parameter(Mandatory = false)]
        public string Country;

        [Parameter(Mandatory = false)]
        public string Location;

        [Parameter(Mandatory = false)]
        public int? Take;

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