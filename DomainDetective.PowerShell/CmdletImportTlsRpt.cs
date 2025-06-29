using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Imports TLSRPT JSON reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Import TLS report file.</summary>
    ///   <code>Import-TlsRpt -Path ./report.json</code>
    /// </example>
    [Cmdlet(VerbsData.Import, "TlsRpt")]
    [OutputType(typeof(TlsRptSummary))]
    public sealed class CmdletImportTlsRpt : PSCmdlet {
        /// <param name="Path">Path to the JSON report.</param>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        protected override void ProcessRecord() {
            var summaries = TlsRptJsonParser.ParseReport(Path);
            WriteObject(summaries, true);
        }
    }
}
