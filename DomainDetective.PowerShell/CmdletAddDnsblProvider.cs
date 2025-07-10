using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Adds a DNSBL provider entry to an analysis object.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Add a provider and return the updated analysis.</summary>
    ///   <code>Add-DnsblProvider -Domain "dnsbl.example.com"</code>
    /// </example>
[Cmdlet(VerbsCommon.Add, "DDDnsblProvider")]
[Alias("Add-DnsblProvider")]
    public sealed class CmdletAddDnsblProvider : PSCmdlet {
        /// <param name="Domain">Domain name of the DNSBL provider.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Domain { get; set; }

        /// <param name="Enabled">Sets the provider as enabled.</param>
        [Parameter(Mandatory = false)]
        public bool Enabled { get; set; } = true;

        /// <param name="Comment">Optional descriptive comment.</param>
        [Parameter(Mandatory = false)]
        public string Comment { get; set; }

        /// <param name="InputObject">Analysis object to add the provider to.</param>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        /// <summary>Processes the cmdlet operation.</summary>
        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.AddDNSBL(Domain, Enabled, Comment);
            WriteObject(analysis);
        }
    }
}