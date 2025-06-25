using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Removes all DNSBL providers from an analysis object.</summary>
    /// <example>
    ///   <summary>Clear the provider list.</summary>
    ///   <code>Clear-DnsblProvider</code>
    /// </example>
    [Cmdlet(VerbsCommon.Clear, "DnsblProvider")]
    public sealed class CmdletClearDnsblProvider : PSCmdlet {
        /// <param name="InputObject">Analysis object to modify.</param>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.ClearDNSBL();
            WriteObject(analysis);
        }
    }
}