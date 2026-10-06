using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Imports TLSRPT JSON reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Import TLS report file.</summary>
    ///   <code>Import-DDEmailTlsRpt -Path ./report.json</code>
    /// </example>
    [Cmdlet(VerbsData.Import, "DDEmailTlsRpt")]
    [Alias("Import-EmailTlsRpt", "Import-TlsRpt")]
    [OutputType(typeof(TlsRptSummary))]
    public sealed class CmdletImportTlsRpt : PSCmdlet {
        /// <summary>Path to the JSON report.</summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Path { get; set; } = string.Empty;

        /// <para>Maximum expanded report size in MiB. The default is 50; 0 means unlimited.</para>
        [Parameter]
        [ValidateRange(0, int.MaxValue)]
        public int MaxUncompressedMb { get; set; } = 50;

        /// <summary>
        /// Reads a TLS-RPT JSON report and outputs the parsed summaries.
        /// </summary>
        protected override void ProcessRecord() {
            var summaries = TlsRptJsonParser.ParseReport(Path, (long)MaxUncompressedMb * 1024L * 1024L);
            WriteObject(summaries, true);
        }
    }
}
