using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Imports DNSBL provider configuration from a file.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Load providers from JSON.</summary>
    ///   <code>Import-DDDnsblConfig -Path ./DnsblProviders.json -OverwriteExisting</code>
    /// </example>
[Cmdlet(VerbsData.Import, "DDDnsblConfig")]
[Alias("Import-DnsblConfig")]
    public sealed class CmdletImportDnsblConfig : PSCmdlet {
        /// <para>Path to the configuration file.</para>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; } = string.Empty;

        /// <para>Replace existing providers.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter OverwriteExisting { get; set; }

        /// <para>Remove current providers before import.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter ClearExisting { get; set; }

        /// <para>Analysis object to modify.</para>
        [Parameter(ValueFromPipeline = true)]
        public DNSBLAnalysis? InputObject { get; set; }

        /// <summary>
        /// Loads DNSBL configuration from the specified path.
        /// </summary>
        protected override void ProcessRecord() {
            var analysis = InputObject ?? new DNSBLAnalysis();
            analysis.LoadDnsblConfig(Path, overwriteExisting: OverwriteExisting, clearExisting: ClearExisting);
            WriteObject(analysis);
        }
    }
}
