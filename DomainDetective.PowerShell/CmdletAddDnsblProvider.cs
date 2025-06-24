using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>
    ///     Adds a DNSBL provider entry to an existing <see cref="DNSBLAnalysis"/> instance.
    /// </summary>
    [Cmdlet(VerbsCommon.Add, "DnsblProvider")]
    public sealed class CmdletAddDnsblProvider : PSCmdlet {
        /// <summary>Domain name of the DNSBL provider.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Domain { get; set; }

        /// <summary>Sets the provider as enabled on creation.</summary>
        [Parameter(Mandatory = false)]
        public bool Enabled { get; set; } = true;

        /// <summary>Optional descriptive comment.</summary>
        [Parameter(Mandatory = false)]
        public string Comment { get; set; }

        /// <summary>Analysis object to add the provider to.</summary>
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