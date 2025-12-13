using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Adds a DNSBL provider entry to an analysis object.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Add a provider and return the updated analysis.</summary>
    ///   <code>Add-DDDnsblProvider -Domain "dnsbl.example.com"</code>
    /// </example>
[Cmdlet(VerbsCommon.Add, "DDDnsblProvider")]
[Alias("Add-DnsblProvider")]
    public sealed class CmdletAddDnsblProvider : PSCmdlet {
        /// <para>Domain name of the DNSBL provider.</para>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Domain { get; set; } = string.Empty;

        /// <para>Sets the provider as enabled.</para>
        [Parameter(Mandatory = false)]
        public bool Enabled { get; set; } = true;

        /// <para>Optional descriptive comment.</para>
        [Parameter(Mandatory = false)]
        public string Comment { get; set; } = string.Empty;

        /// <para>Analysis object to add the provider to.</para>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis? InputObject { get; set; }

        /// <summary>Processes the cmdlet operation.</summary>
        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.AddDNSBL(Domain, Enabled, Comment);
            WriteObject(analysis);
        }
    }
}
