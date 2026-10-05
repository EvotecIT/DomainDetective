using DnsClientX;
using System.Collections.Generic;
using System.Collections;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Parses raw email message headers.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze headers from a file.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Get-DDEmailMessageHeaderInfo -ExpectedMx 'mx1.gateway.example.net'</code>
    /// </example>
[Cmdlet(VerbsCommon.Get, "DDEmailMessageHeaderInfo", DefaultParameterSetName = "Text")]
[Alias("Get-EmailHeaderInfo")]
    public sealed class CmdletTestMessageHeader : ExportableAsyncPSCmdlet {
        /// <summary>Raw header text.</summary>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ParameterSetName = "Text")]
        [ValidateNotNullOrEmpty]
        public string HeaderText = string.Empty;

        /// <para>Local header or original MIME files. FileInfo objects supply FullName through the pipeline.</para>
        [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true, ParameterSetName = "File")]
        [Alias("FullName")]
        [ValidateNotNullOrEmpty]
        public string[] Path { get; set; } = System.Array.Empty<string>();

        /// <para>Exact authentication service identifiers trusted by the configured, sanitizing receiving gateway.</para>
        [Parameter]
        [ValidateNotNull]
        public string[] TrustedAuthServId { get; set; } = System.Array.Empty<string>();

        /// <para>Verify DKIM and ARC with the body. Text input is encoded as UTF-8; use Path to preserve original file bytes.</para>
        [Parameter]
        public SwitchParameter VerifySignatures { get; set; }

        /// <para>Allow public-key TXT lookups. Message content is never uploaded. DNS is disabled by default.</para>
        [Parameter]
        public SwitchParameter AllowDnsLookups { get; set; }

        /// <para>Offline public-key TXT records indexed by selector._domainkey.domain. Requires VerifySignatures.</para>
        [Parameter]
        public Hashtable? PublicKeyRecords { get; set; }

        /// <summary>Expected public MX hosts that should appear in the received path.</summary>
        [Parameter]
        public string[]? ExpectedMx { get; set; }

        private InternalLogger _logger = null!;
        private readonly List<object> _items = new();

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.ClearLoggedMessages();
            if (!VerifySignatures && (AllowDnsLookups || PublicKeyRecords != null)) { throw new System.ArgumentException("AllowDnsLookups and PublicKeyRecords require VerifySignatures."); }
            using var health = new DomainHealthCheck(DnsEndpoint.System, _logger);
            ApplyExecutionOptions(health);
            var options = new MessageVerificationOptions {
                HeaderOptions = new MessageHeaderAnalysisOptions { TrustedAuthServIds = TrustedAuthServId },
                AllowDnsLookups = AllowDnsLookups
            };
            if (PublicKeyRecords != null) {
                foreach (DictionaryEntry entry in PublicKeyRecords) { options.PublicKeyRecords.Add(System.Convert.ToString(entry.Key) ?? string.Empty, System.Convert.ToString(entry.Value) ?? string.Empty); }
            }
            if (ParameterSetName == "File") {
                foreach (var path in Path) {
                    var result = await health.AnalyzeMessageFileAsync(GetUnresolvedProviderPathFromPSPath(path), VerifySignatures, options, ExpectedMx, CancelToken);
                    Emit(result);
                }
            } else {
                var result = VerifySignatures
                    ? await health.AnalyzeMessageAsync(System.Text.Encoding.UTF8.GetBytes(HeaderText), options, CancelToken)
                    : health.AnalyzeMessageHeaders(HeaderText, options.HeaderOptions, ExpectedMx, CancelToken);
                if (VerifySignatures) { result.CompareExpectedMx(ExpectedMx, _logger); }
                Emit(result);
            }
        }

        private void Emit(MessageHeaderAnalysis result) {
            WriteObject(result);
            if (IsExportRequested()) { _items.Add(result); }
        }

        /// <summary>Writes a single export for all piped message header results.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) {
                return Task.CompletedTask;
            }

            var label = _items.Count == 1 ? "message-header" : "message-headers";
            try {
                var hadUnsupportedFormats = false;
                CompositionExportHelper.WriteReports(
                    _items,
                    GetRequestedFormatsOrDefault(ExportDefaults.Format),
                    ExportPath,
                    label,
                    DomainDetective.Reports.ReportScope.Normal,
                    "Email Message Header Report",
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    TryOpenReport,
                    out hadUnsupportedFormats);

                if (hadUnsupportedFormats) {
                    return ExportNotImplementedAsync("Get-DDEmailMessageHeaderInfo");
                }
            } catch (System.Exception ex) {
                WriteWarning($"Message header export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}

