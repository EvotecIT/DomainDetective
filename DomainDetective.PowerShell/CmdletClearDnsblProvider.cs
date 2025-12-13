using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Removes all DNSBL providers from an analysis object.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Clear the provider list.</summary>
    ///   <code>Clear-DDDnsblProviderList</code>
    /// </example>
[Cmdlet(VerbsCommon.Clear, "DDDnsblProviderList")]
[Alias("Clear-DnsblProvider")]
    public sealed class CmdletClearDnsblProvider : PSCmdlet {
        /// <summary>Analysis object to modify.</summary>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis? InputObject { get; set; }

        /// <summary>
        /// Clears all configured DNSBL providers from the analysis object.
        /// </summary>
        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.ClearDNSBL();
            WriteObject(analysis);
        }
    }
}
