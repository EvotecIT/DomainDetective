using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Imports DNSBL provider configuration from a file.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Load providers from JSON.</summary>
    ///   <code>Import-DnsblConfig -Path ./DnsblProviders.json -OverwriteExisting</code>
    /// </example>
    [Cmdlet(VerbsData.Import, "DnsblConfig")]
    public sealed class CmdletImportDnsblConfig : PSCmdlet {
        /// <param name="Path">Path to the configuration file.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        /// <param name="OverwriteExisting">Replace existing providers.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter OverwriteExisting { get; set; }

        /// <param name="ClearExisting">Remove current providers before import.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter ClearExisting { get; set; }

        /// <param name="InputObject">Analysis object to modify.</param>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis InputObject { get; set; }

        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.LoadDnsblConfig(Path, overwriteExisting: OverwriteExisting, clearExisting: ClearExisting);
            WriteObject(analysis);
        }
    }
}