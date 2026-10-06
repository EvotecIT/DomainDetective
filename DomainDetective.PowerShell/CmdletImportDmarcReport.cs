using DomainDetective;
using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Parses zipped DMARC feedback reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Import feedback from a zip file.</summary>
    ///   <code>Import-DDDmarcReport -Path ./report.zip</code>
    /// </example>
[Cmdlet(VerbsData.Import, "DDDmarcReport")]
[Alias("Import-DmarcReport")]
    public sealed class CmdletImportDmarcReport : PSCmdlet {
        /// <para>Path to the zipped XML file.</para>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; } = string.Empty;

        /// <para>Maximum expanded report size in MiB. The default is 50; 0 means unlimited.</para>
        [Parameter]
        [ValidateRange(0, int.MaxValue)]
        public int MaxUncompressedMb { get; set; } = 50;

        /// <summary>
        /// Parses the DMARC report archive and outputs each summary.
        /// </summary>
        protected override void ProcessRecord() {
            var report = DmarcReportParser.Parse(Path, null, (long)MaxUncompressedMb * 1024L * 1024L);
            foreach (var summary in report.Records) {
                WriteObject(summary);
            }
        }
    }
}
