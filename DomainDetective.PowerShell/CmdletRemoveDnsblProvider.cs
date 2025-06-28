using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Removes a DNSBL provider entry from an analysis object.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Remove a provider by domain.</summary>
    ///   <code>Remove-DnsblProvider -Domain dnsbl.example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.Remove, "DnsblProvider")]
    public sealed class CmdletRemoveDnsblProvider : PSCmdlet {
        /// <param name="Domain">Domain name of the provider to remove.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Domain { get; set; }

        /// <param name="InputObject">Analysis object to modify.</param>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.RemoveDNSBL(Domain);
            WriteObject(analysis);
        }
    }
}