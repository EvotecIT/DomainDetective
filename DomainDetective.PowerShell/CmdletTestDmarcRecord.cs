using System;
using System.Linq;
using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DMARC record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check DMARC settings.</summary>
    ///   <code>Test-DDEmailDmarcRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailDmarcRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailDmarc")]
    public sealed class CmdletTestDmarcRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        // View-by-default: Raw analysis is attached to view.Raw

        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();
        private readonly object _exportLock = new();
        private bool _hadUnsupportedFormats;

        // BeginProcessing handled per-domain to allow safe parallelism.

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        /// <summary>Processes each domain, emits DMARC view, and accumulates for optional composition export.</summary>
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

                logger.WriteVerbose("Querying DMARC record for domain: {0}", domain);
                await healthCheck.VerifyDMARC(domain, cancellationToken: CancelToken);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.DmarcAnalysis);
                WriteObject(output);
                if (IsExportRequested()) {
                    var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format);
                    var wantsComposition = formats.Any(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html);
                    var wantsJson = formats.Contains(DomainDetective.Reports.ReportFormat.Json);
                    var hasUnsupportedFormats = formats.Any(f =>
                        f != DomainDetective.Reports.ReportFormat.Word
                        && f != DomainDetective.Reports.ReportFormat.Html
                        && f != DomainDetective.Reports.ReportFormat.Json);

                    if (wantsComposition) {
                        lock (_exportLock) {
                            _items.Add(output);
                            if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                                _subjects.Add(domain);
                            }
                            _hadUnsupportedFormats |= hasUnsupportedFormats;
                        }
                    }

                    if (wantsJson) {
                        var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, DomainDetective.Reports.ReportFormat.Json, formats);
                        try {
                            var json = System.Text.Json.JsonSerializer.Serialize(healthCheck.DmarcAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                            System.IO.File.WriteAllText(outPath, json);
                            WriteVerbose($"DMARC JSON saved: {outPath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                                TryOpenReport(outPath);
                            }
                        } catch (System.Exception ex) {
                            WriteWarning($"DMARC export failed: {ex.Message}");
                        }
                    }

                    if (!wantsComposition && !wantsJson) {
                        await ExportNotImplementedAsync("Test-DDEmailDmarcRecord");
                    } else if (hasUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDEmailDmarcRecord");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        /// <summary>Composes DMARC sections into one document for Word/HTML export.</summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format)
                .Where(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html)
                .ToArray();
            if (formats.Length == 0) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "dmarc",
                1 => _subjects[0],
                2 => $"{_subjects[0]}+{_subjects[1]}",
                _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
            };
            try {
                var hadUnsupportedFormats = false;
                CompositionExportHelper.WriteReports(
                    _items,
                    formats,
                    ExportPath,
                    label,
                    DomainDetective.Reports.ReportScope.Detailed,
                    $"DMARC Report — {label}",
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    TryOpenReport,
                    out hadUnsupportedFormats);

                if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                    return ExportNotImplementedAsync("Test-DDEmailDmarcRecord");
                }
            } catch (System.Exception ex) {
                WriteWarning($"DMARC export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}
