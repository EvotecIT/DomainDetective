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

        /// <summary>
        /// Parses the DMARC report archive and outputs each summary.
        /// </summary>
        protected override void ProcessRecord() {
            var report = DmarcReportParser.Parse(Path);
            foreach (var summary in report.Records) {
                WriteObject(summary);
            }
        }
    }
}
