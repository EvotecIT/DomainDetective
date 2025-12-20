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

/// <summary>Checks SMTP/IMAP/POP3 TLS configuration for a domain.</summary>
/// <para>Returns view objects with full raw analysis attached at Raw.</para>
/// <example>
///   <summary>Check mail TLS for a domain.</summary>
///   <code>Test-DDEmailProtocolTls -DomainName example.com</code>
/// </example>
/// <example>
///   <summary>Only run SMTP TLS checks.</summary>
///   <code>Test-DDEmailProtocolTls -DomainName example.com -Protocol Smtp</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailProtocolTls", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailProtocolTls", "Test-MailTls")]
[OutputType(typeof(DomainDetective.Views.MailTlsInfo))]
public sealed class CmdletTestEmailProtocolTls : ExportableAsyncPSCmdlet {
    /// <summary>Domain(s) to query.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Select mail protocols to evaluate.</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Smtp", "Imap", "Pop3")]
    public string[] Protocol = new[] { "Smtp", "Imap", "Pop3" };

    /// <summary>Disable parallel execution of health checks.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableParallel { get; set; }

    /// <summary>Maximum concurrent health checks.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 128)]
    public int? MaxParallelism { get; set; }

    /// <summary>DNS resolver concurrency hint.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 128)]
    public int? DnsParallelism { get; set; }

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;
    private readonly List<object> _items = new();
    private readonly List<string> _subjects = new();

    /// <summary>Initializes logging and helper classes.</summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
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
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        ApplyExecutionOptions();
        return Task.CompletedTask;
    }

    private void ApplyExecutionOptions() {
        _healthCheck.ExecutionOptions.EnableParallelism = !DisableParallel.IsPresent;
        if (MaxParallelism.HasValue) {
            _healthCheck.ExecutionOptions.MaxParallelism = MaxParallelism.Value;
        }
        if (DnsParallelism.HasValue) {
            _healthCheck.ExecutionOptions.DnsParallelism = DnsParallelism.Value;
        }
    }

    /// <summary>Executes the cmdlet operation.</summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync() {
        var protocolSet = new HashSet<string>(Protocol ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        if (protocolSet.Count == 0) {
            protocolSet.UnionWith(new[] { "Smtp", "Imap", "Pop3" });
        }
        var checkTypes = new List<HealthCheckType>();
        if (protocolSet.Contains("Smtp")) {
            checkTypes.Add(HealthCheckType.SMTPTLS);
        }
        if (protocolSet.Contains("Imap")) {
            checkTypes.Add(HealthCheckType.IMAPTLS);
        }
        if (protocolSet.Contains("Pop3")) {
            checkTypes.Add(HealthCheckType.POP3TLS);
        }
        if (checkTypes.Count == 0) {
            checkTypes.AddRange(new[] { HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS });
        }

        foreach (var domain in DomainName) {
            _logger.WriteVerbose("Checking mail protocol TLS for domain: {0}", domain);
            await _healthCheck.Verify(domain, checkTypes.ToArray(), cancellationToken: CancelToken);

            var hasAny = false;
            if (checkTypes.Contains(HealthCheckType.SMTPTLS)) {
                var view = DomainDetective.Views.Converters.Convert(_healthCheck.SmtpTlsAnalysis);
                WriteObject(view);
                AddForExport(view, domain);
                hasAny = true;
            }
            if (checkTypes.Contains(HealthCheckType.IMAPTLS)) {
                var view = DomainDetective.Views.Converters.Convert(_healthCheck.ImapTlsAnalysis);
                WriteObject(view);
                AddForExport(view, domain);
                hasAny = true;
            }
            if (checkTypes.Contains(HealthCheckType.POP3TLS)) {
                var view = DomainDetective.Views.Converters.Convert(_healthCheck.Pop3TlsAnalysis);
                WriteObject(view);
                AddForExport(view, domain);
                hasAny = true;
            }

            if (IsExportRequested() && hasAny) {
                var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
                foreach (var fmt in fmts) {
                    if (fmt == DomainDetective.Reports.ReportFormat.Json) {
                        var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, fmt, fmts);
                        try {
                            var payload = new {
                                Domain = domain,
                                SmtpTls = checkTypes.Contains(HealthCheckType.SMTPTLS) ? _healthCheck.SmtpTlsAnalysis : null,
                                ImapTls = checkTypes.Contains(HealthCheckType.IMAPTLS) ? _healthCheck.ImapTlsAnalysis : null,
                                Pop3Tls = checkTypes.Contains(HealthCheckType.POP3TLS) ? _healthCheck.Pop3TlsAnalysis : null
                            };
                            var json = JsonSerializer.Serialize(payload, DomainDetective.Helpers.JsonOptions.Default);
                            File.WriteAllText(outPath, json);
                            WriteVerbose($"Mail TLS JSON saved: {outPath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                                TryOpenReport(outPath);
                            }
                        } catch (Exception ex) {
                            WriteWarning($"Mail TLS export failed: {ex.Message}");
                        }
                    } else if (fmt != DomainDetective.Reports.ReportFormat.Word && fmt != DomainDetective.Reports.ReportFormat.Html) {
                        await ExportNotImplementedAsync("Test-DDEmailProtocolTls");
                    }
                }
            }
        }
    }

    private void AddForExport(object view, string domain) {
        if (!IsExportRequested()) {
            return;
        }
        var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
        foreach (var fmt in fmts) {
            if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                _items.Add(view);
                if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                    _subjects.Add(domain);
                }
            }
        }
    }

    /// <summary>Finalizes multi-domain exports for Word/HTML by composing a single file.</summary>
    protected override Task EndProcessingAsync() {
        if (_items.Count == 0) {
            return Task.CompletedTask;
        }
        var fmts = GetRequestedFormatsOrDefault(ExportDefaults.Format);
        var needsWord = Array.Exists(fmts.ToArray(), f => f == DomainDetective.Reports.ReportFormat.Word);
        var needsHtml = Array.Exists(fmts.ToArray(), f => f == DomainDetective.Reports.ReportFormat.Html);
        if (!needsWord && !needsHtml) {
            return Task.CompletedTask;
        }

        var label = _subjects.Count switch {
            0 => "mail-tls",
            1 => _subjects[0],
            2 => $"{_subjects[0]}+{_subjects[1]}",
            _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
        };
        try {
            if (needsWord) {
                var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, label, DomainDetective.Reports.ReportFormat.Word, fmts);
                DomainDetective.Reports.Office.WordCompositionReport.Generate(
                    outPath,
                    _items,
                    DomainDetective.Reports.ReportScope.Normal,
                    showInfoFindings: true,
                    narrativePlacement: ExportDefaults.NarrativePlacement,
                    titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"Mail TLS Report — {label}" : ExportDefaults.NarrativeTitle,
                    subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                    categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                    keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                    creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                    summaryColumnCap: ExportDefaults.SummaryColumnCap,
                    headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                    footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) {
                    TryOpenReport(outPath);
                }
            }
            if (needsHtml) {
                var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, label, DomainDetective.Reports.ReportFormat.Html, fmts);
                DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                    outPath,
                    _items,
                    DomainDetective.Reports.ReportScope.Normal,
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    ExportDefaults.NarrativePlacement,
                    titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                    authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                    descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
            }
        } catch (Exception ex) {
            WriteWarning($"Mail TLS export failed: {ex.Message}");
        }
        return Task.CompletedTask;
    }
}
