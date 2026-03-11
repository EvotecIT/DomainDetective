using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text.Json;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;

namespace DomainDetective.PowerShell;

/// <summary>Verifies MTA-STS policy for one or more domains.</summary>
/// <para>Returns a view object with full raw analysis attached at Raw.</para>
/// <example>
///   <summary>Check MTA-STS for a domain.</summary>
///   <code>Test-DDEmailMtaSts -DomainName example.com</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailMtaSts", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailMtaSts")]
[OutputType(typeof(DomainDetective.Views.MtastsInfo))]
public sealed class CmdletTestMtaSts : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private readonly List<object> _items = new();
    private readonly List<string> _subjects = new();
    private readonly object _exportLock = new();
    private bool _hadUnsupportedFormats;

    // BeginProcessing handled per-domain to allow safe parallelism.

    /// <summary>Executes the cmdlet operation.</summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
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

            logger.WriteVerbose("Checking MTA-STS for domain: {0}", domain);
            await healthCheck.Verify(domain, new[] { HealthCheckType.MTASTS }, cancellationToken: CancelToken);

            var view = DomainDetective.Views.Converters.Convert(healthCheck.MTASTSAnalysis);
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
                    var json = JsonSerializer.Serialize(healthCheck.MTASTSAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                    File.WriteAllText(outPath, json);
                    WriteVerbose($"MTA-STS JSON saved: {outPath}");
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                        TryOpenReport(outPath);
                    }
                } catch (Exception ex) {
                    WriteWarning($"MTA-STS export failed: {ex.Message}");
                }
            }

            if (hasUnsupportedFormats) {
                await ExportNotImplementedAsync("Test-DDEmailMtaSts");
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
            0 => "mtasts",
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
                $"MTA-STS Report - {label}",
                OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                TryOpenReport,
                out hadUnsupportedFormats);

            if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                return ExportNotImplementedAsync("Test-DDEmailMtaSts");
            }
        } catch (Exception ex) {
            WriteWarning($"MTA-STS export failed: {ex.Message}");
        }
        return Task.CompletedTask;
    }
}
