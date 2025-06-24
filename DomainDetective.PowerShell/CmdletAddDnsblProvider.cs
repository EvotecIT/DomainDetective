using System.Management.Automation;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsCommon.Add, "DnsblProvider")]
    public sealed class CmdletAddDnsblProvider : PSCmdlet {
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Domain { get; set; }

        [Parameter(Mandatory = false)]
        public bool Enabled { get; set; } = true;

        [Parameter(Mandatory = false)]
        public string Comment { get; set; }

        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.AddDNSBL(Domain, Enabled, Comment);
            WriteObject(analysis);
        }
    }
}