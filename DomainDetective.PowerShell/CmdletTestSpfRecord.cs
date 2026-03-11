using System;
using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates SPF record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check SPF configuration.</summary>
    ///   <code>Test-DDEmailSpfRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailSpfRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailSpf")]
    public sealed class CmdletTestSpfRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        //[Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        //public SwitchParameter FullResponse;

        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();
        private readonly object _exportLock = new();
        private bool _hadUnsupportedFormats;

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

                logger.WriteVerbose("Querying SPF record for domain: {0}", domain);
                await healthCheck.VerifySPF(domain, cancellationToken: CancelToken);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis);
                WriteObject(output);

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
                        _items.Add(output);
                        if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                            _subjects.Add(domain);
                        }
                        _hadUnsupportedFormats |= hasUnsupportedFormats;
                    }
                }

                if (wantsJson) {
                    var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, DomainDetective.Reports.ReportFormat.Json, fmts);
                    try {
                        var json = System.Text.Json.JsonSerializer.Serialize(healthCheck.SpfAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                        System.IO.File.WriteAllText(outPath, json);
                        WriteVerbose($"SPF JSON saved: {outPath}");
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                            TryOpenReport(outPath);
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"SPF export failed: {ex.Message}");
                    }
                }

                if (!wantsComposition && !wantsJson) {
                    await ExportNotImplementedAsync("Test-DDEmailSpfRecord");
                } else if (hasUnsupportedFormats) {
                    await ExportNotImplementedAsync("Test-DDEmailSpfRecord");
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        /// <summary>
        /// Finalizes multi-domain exports for Word/HTML by composing a single file.
        /// </summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format)
                .Where(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html)
                .ToArray();
            if (fmts.Length == 0) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "spf",
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
                    DomainDetective.Reports.ReportScope.Detailed,
                    $"SPF Report - {label}",
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    TryOpenReport,
                    out hadUnsupportedFormats);

                if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                    return ExportNotImplementedAsync("Test-DDEmailSpfRecord");
                }
            } catch (System.Exception ex) {
                WriteWarning($"SPF export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}
