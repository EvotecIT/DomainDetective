using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Imports TLSRPT JSON reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Import TLS report file.</summary>
    ///   <code>Import-DDTlsRpt -Path ./report.json</code>
    /// </example>
    [Cmdlet(VerbsData.Import, "DDTlsRpt")]
    [Alias("Import-TlsRpt")]
    [OutputType(typeof(TlsRptSummary))]
    public sealed class CmdletImportTlsRpt : PSCmdlet {
        /// <summary>Path to the JSON report.</summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; }

        /// <summary>
        /// Reads a TLS-RPT JSON report and outputs the parsed summaries.
        /// </summary>
        protected override void ProcessRecord() {
            var summaries = TlsRptJsonParser.ParseReport(Path);
            WriteObject(summaries, true);
        }
    }
}
