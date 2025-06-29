using System.Collections.Generic;
using System.Management.Automation;

namespace DomainDetective.PowerShell {
    /// <summary>Builds a DMARC record string.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Create a DMARC record.</summary>
    ///   <code>New-DmarcRecord -Policy reject -AggregateUri mailto:reports@example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.New, "DmarcRecord")]
    [OutputType(typeof(string))]
    public sealed class CmdletNewDmarcRecord : PSCmdlet {
        /// <param name="Policy">Main DMARC policy.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateSet("none", "quarantine", "reject")]
        public string Policy { get; set; }

        /// <param name="SubPolicy">Policy applied to subdomains.</param>
        [Parameter]
        [ValidateSet("none", "quarantine", "reject")]
        public string SubPolicy { get; set; }

        /// <param name="AggregateUri">Aggregate report URI(s).</param>
        [Parameter]
        public string AggregateUri { get; set; }

        /// <param name="ForensicUri">Forensic report URI(s).</param>
        [Parameter]
        public string ForensicUri { get; set; }

        /// <param name="Percent">Percentage of mail subjected to the policy.</param>
        [Parameter]
        [ValidateRange(0, 100)]
        public int? Percent { get; set; }

        /// <param name="DkimAlignment">DKIM alignment mode.</param>
        [Parameter]
        [ValidateSet("r", "s")]
        public string DkimAlignment { get; set; }

        /// <param name="SpfAlignment">SPF alignment mode.</param>
        [Parameter]
        [ValidateSet("r", "s")]
        public string SpfAlignment { get; set; }

        /// <param name="FailureOptions">Failure reporting options.</param>
        [Parameter]
        public string FailureOptions { get; set; }

        /// <param name="ReportingInterval">Reporting interval in seconds.</param>
        [Parameter]
        public int? ReportingInterval { get; set; }

        /// <summary>Outputs the composed DMARC record.</summary>
        protected override void EndProcessing() {
            var parts = new List<string> { "v=DMARC1", $"p={Policy}" };
            if (!string.IsNullOrWhiteSpace(SubPolicy)) {
                parts.Add($"sp={SubPolicy}");
            }
            if (!string.IsNullOrWhiteSpace(AggregateUri)) {
                parts.Add($"rua={AggregateUri}");
            }
            if (!string.IsNullOrWhiteSpace(ForensicUri)) {
                parts.Add($"ruf={ForensicUri}");
            }
            if (Percent.HasValue) {
                parts.Add($"pct={Percent.Value}");
            }
            if (!string.IsNullOrWhiteSpace(DkimAlignment)) {
                parts.Add($"adkim={DkimAlignment}");
            }
            if (!string.IsNullOrWhiteSpace(SpfAlignment)) {
                parts.Add($"aspf={SpfAlignment}");
            }
            if (!string.IsNullOrWhiteSpace(FailureOptions)) {
                parts.Add($"fo={FailureOptions}");
            }
            if (ReportingInterval.HasValue) {
                parts.Add($"ri={ReportingInterval.Value}");
            }
            var record = string.Join("; ", parts) + ";";
            WriteObject(record);
        }
    }
}
