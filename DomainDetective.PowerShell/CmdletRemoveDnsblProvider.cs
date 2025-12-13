using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Removes a DNSBL provider entry from an analysis object.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Remove a provider by domain.</summary>
    ///   <code>Remove-DDDnsblProvider -Domain dnsbl.example.com</code>
    /// </example>
[Cmdlet(VerbsCommon.Remove, "DDDnsblProvider")]
[Alias("Remove-DnsblProvider")]
    public sealed class CmdletRemoveDnsblProvider : PSCmdlet {
        /// <summary>Domain name of the provider to remove.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Domain { get; set; } = string.Empty;

        /// <summary>Analysis object to modify.</summary>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis? InputObject { get; set; }

        /// <summary>
        /// Removes the specified provider from the analysis object.
        /// </summary>
        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.RemoveDNSBL(Domain);
            WriteObject(analysis);
        }
    }
}
