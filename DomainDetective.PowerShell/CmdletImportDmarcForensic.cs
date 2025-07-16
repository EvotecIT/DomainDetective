using DomainDetective.Reports;
using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Parses zipped DMARC forensic reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Import forensic reports from a zip file.</summary>
    ///   <code>Import-DmarcForensic -Path ./forensic.zip</code>
    /// </example>
    [Cmdlet(VerbsData.Import, "DDDmarcForensic")]
    [Alias("Import-DmarcForensic")]
    [OutputType(typeof(DmarcForensicReport))]
    public sealed class CmdletImportDmarcForensic : PSCmdlet {
        /// <param name="Path">Path to the zipped report.</param>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        /// <summary>Parses forensic report archive and outputs each entry.</summary>
        protected override void ProcessRecord() {
            foreach (var report in DmarcForensicParser.ParseZip(Path)) {
                WriteObject(report);
            }
        }
    }
}
