using DomainDetective.Reports;
using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Parses zipped DMARC feedback reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Import feedback from a zip file.</summary>
    ///   <code>Import-DmarcReport -Path ./report.zip</code>
    /// </example>
[Cmdlet(VerbsData.Import, "DDDmarcReport")]
[Alias("Import-DmarcReport")]
    public sealed class CmdletImportDmarcReport : PSCmdlet {
        /// <param name="Path">Path to the zipped XML file.</param>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        protected override void ProcessRecord() {
            foreach (var summary in DmarcReportParser.ParseZip(Path)) {
                WriteObject(summary);
            }
        }
    }
}
