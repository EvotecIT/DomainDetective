using System.Management.Automation;

namespace DomainDetective.PowerShell {
    [Cmdlet(VerbsCommon.Clear, "DnsblProvider")]
    public sealed class CmdletClearDnsblProvider : PSCmdlet {
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.ClearDNSBL();
            WriteObject(analysis);
        }
    }
}
