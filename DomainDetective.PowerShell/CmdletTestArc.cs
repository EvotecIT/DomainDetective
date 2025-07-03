using DnsClientX;
using System.IO;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates ARC headers from raw input.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze ARC headers from a file.</summary>
    ///   <code>Test-Arc -File './headers.txt'</code>
    /// </example>
    /// <example>
    ///   <summary>Analyze ARC headers from pipeline input.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Test-Arc</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "Arc", DefaultParameterSetName = "Text")]
    public sealed class CmdletTestArc : AsyncPSCmdlet {
        /// <param name="HeaderText">Raw header text.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Text", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string HeaderText { get; set; } = string.Empty;

        /// <param name="File">Path to a file containing ARC headers.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty]
        public string File { get; set; } = string.Empty;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint.CloudflareWireFormat, _logger);
            return Task.CompletedTask;
        }

        protected override Task ProcessRecordAsync() {
            var text = ParameterSetName == "File"
                ? System.IO.File.ReadAllText(File)
                : HeaderText;
            var result = _healthCheck.VerifyARC(text, CancelToken);
            WriteObject(result);
            return Task.CompletedTask;
        }
    }
}
