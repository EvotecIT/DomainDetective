using System.Management.Automation;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsCommon.Remove, "DnsblProvider")]
    public sealed class CmdletRemoveDnsblProvider : PSCmdlet {
        [Parameter(Mandatory = true, Position = 0)]
        public string Domain { get; set; }

        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.RemoveDNSBL(Domain);
            WriteObject(analysis);
        }
    }
}
