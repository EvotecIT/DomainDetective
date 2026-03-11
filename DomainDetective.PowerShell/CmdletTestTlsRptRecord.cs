using System;
using System.Linq;
using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates TLS-RPT record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Check TLS report policy.</summary>
    ///   <code>Test-DDEmailTlsRptRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailTlsRptRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailTlsRpt")]
    public sealed class CmdletTestTlsRptRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain name(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();
        private readonly object _exportLock = new();
        private bool _hadUnsupportedFormats;

        // BeginProcessing handled per-domain to allow safe parallelism.

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    this.WriteVerbose,
                    this.WriteWarning,
                    this.WriteDebug,
                    this.WriteError,
                    this.WriteProgress,
                    this.WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Querying TLSRPT record for domain: {0}", domain);
                await healthCheck.VerifyTLSRPT(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.TLSRPTAnalysis);
                WriteObject(view);

                if (!IsExportRequested()) {
                    return;
                }
                var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
                var wantsComposition = fmts.Any(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html);
                var wantsJson = fmts.Contains(DomainDetective.Reports.ReportFormat.Json);
                var hasUnsupportedFormats = fmts.Any(f =>
                    f != DomainDetective.Reports.ReportFormat.Word
                    && f != DomainDetective.Reports.ReportFormat.Html
                    && f != DomainDetective.Reports.ReportFormat.Json);

                if (wantsComposition) {
                    lock (_exportLock) {
                        _items.Add(view);
                        if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                            _subjects.Add(domain);
                        }
                        _hadUnsupportedFormats |= hasUnsupportedFormats;
                    }
                }

                if (wantsJson) {
                    var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, DomainDetective.Reports.ReportFormat.Json, fmts);
                    try {
                        var json = System.Text.Json.JsonSerializer.Serialize(healthCheck.TLSRPTAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                        System.IO.File.WriteAllText(outPath, json);
                        WriteVerbose($"TLS-RPT JSON saved: {outPath}");
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                            TryOpenReport(outPath);
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"TLS-RPT export failed: {ex.Message}");
                    }
                }

                if (hasUnsupportedFormats) {
                    await ExportNotImplementedAsync("Test-DDEmailTlsRptRecord");
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        /// <summary>Finalizes multi-domain exports for Word/HTML by composing a single file.</summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) {
                return Task.CompletedTask;
            }
            var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format)
                .Where(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html)
                .ToArray();
            if (fmts.Length == 0) {
                return Task.CompletedTask;
            }

            var label = _subjects.Count switch {
                0 => "tlsrpt",
                1 => _subjects[0],
                2 => $"{_subjects[0]}+{_subjects[1]}",
                _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
            };
            try {
                var hadUnsupportedFormats = false;
                CompositionExportHelper.WriteReports(
                    _items,
                    fmts,
                    ExportPath,
                    label,
                    DomainDetective.Reports.ReportScope.Normal,
                    $"TLS-RPT Report - {label}",
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    TryOpenReport,
                    out hadUnsupportedFormats);

                if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                    return ExportNotImplementedAsync("Test-DDEmailTlsRptRecord");
                }
            } catch (System.Exception ex) {
                WriteWarning($"TLS-RPT export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}
