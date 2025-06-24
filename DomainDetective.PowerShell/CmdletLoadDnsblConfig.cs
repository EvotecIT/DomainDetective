using System.Management.Automation;

namespace DomainDetective.PowerShell {
    [Cmdlet("Load", "DnsblConfig")]
    public sealed class CmdletLoadDnsblConfig : PSCmdlet {
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        [Parameter(Mandatory = false)]
        public SwitchParameter OverwriteExisting { get; set; }

        [Parameter(Mandatory = false)]
        public SwitchParameter ClearExisting { get; set; }

        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.LoadDnsblConfig(Path, overwriteExisting: OverwriteExisting, clearExisting: ClearExisting);
            WriteObject(analysis);
        }
    }
}