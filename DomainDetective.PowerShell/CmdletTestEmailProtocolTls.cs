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
    [ValidateDomainName]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Select mail protocols to evaluate.</summary>
    [Parameter(Mandatory = false)]
    [ValidateSet("Smtp", "Imap", "Pop3")]
    public string[] Protocol = new[] { "Smtp", "Imap", "Pop3" };

    /// <summary>Network address family used when connecting to discovered mail hosts.</summary>
    [Parameter(Mandatory = false)]
    public MailTransportAddressFamily AddressFamily = MailTransportAddressFamily.Any;

    private readonly List<object> _items = new();
    private readonly List<string> _subjects = new();
    private readonly object _exportLock = new();
    private bool _hadUnsupportedFormats;

    // BeginProcessing handled per-domain to allow safe parallelism.

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
            healthCheck.SmtpTlsAnalysis.AddressFamily = AddressFamily;
            healthCheck.ImapTlsAnalysis.AddressFamily = AddressFamily;
            healthCheck.Pop3TlsAnalysis.AddressFamily = AddressFamily;

            logger.WriteVerbose("Checking mail protocol TLS for domain: {0}", domain);
            await healthCheck.Verify(domain, checkTypes.ToArray(), cancellationToken: CancelToken);
            var exportFormats = IsExportRequested()
                ? GetRequestedFormatsOrDefault(ExportDefaults.Format)
                : Array.Empty<DomainDetective.Reports.ReportFormat>();
            var wantsComposition = exportFormats.Any(f =>
                f == DomainDetective.Reports.ReportFormat.Word
                || f == DomainDetective.Reports.ReportFormat.Html);
            var wantsJson = exportFormats.Contains(DomainDetective.Reports.ReportFormat.Json);
            var hasUnsupportedFormats = exportFormats.Any(f =>
                f != DomainDetective.Reports.ReportFormat.Word
                && f != DomainDetective.Reports.ReportFormat.Html
                && f != DomainDetective.Reports.ReportFormat.Json);

            var hasAny = false;
            if (checkTypes.Contains(HealthCheckType.SMTPTLS)) {
                var view = DomainDetective.Views.Converters.Convert(healthCheck.SmtpTlsAnalysis);
                WriteObject(view);
                if (wantsComposition) {
                    AddForExport(view, domain);
                }
                hasAny = true;
            }
            if (checkTypes.Contains(HealthCheckType.IMAPTLS)) {
                var view = DomainDetective.Views.Converters.Convert(healthCheck.ImapTlsAnalysis);
                WriteObject(view);
                if (wantsComposition) {
                    AddForExport(view, domain);
                }
                hasAny = true;
            }
            if (checkTypes.Contains(HealthCheckType.POP3TLS)) {
                var view = DomainDetective.Views.Converters.Convert(healthCheck.Pop3TlsAnalysis);
                WriteObject(view);
                if (wantsComposition) {
                    AddForExport(view, domain);
                }
                hasAny = true;
            }

            if (IsExportRequested() && hasAny) {
                if (wantsComposition) {
                    lock (_exportLock) {
                        _hadUnsupportedFormats |= hasUnsupportedFormats;
                    }
                }

                if (wantsJson) {
                    var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, DomainDetective.Reports.ReportFormat.Json, exportFormats);
                    try {
                        var payload = new {
                            Domain = domain,
                            SmtpTls = checkTypes.Contains(HealthCheckType.SMTPTLS) ? healthCheck.SmtpTlsAnalysis : null,
                            ImapTls = checkTypes.Contains(HealthCheckType.IMAPTLS) ? healthCheck.ImapTlsAnalysis : null,
                            Pop3Tls = checkTypes.Contains(HealthCheckType.POP3TLS) ? healthCheck.Pop3TlsAnalysis : null
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
                }

                if (hasUnsupportedFormats) {
                    await ExportNotImplementedAsync("Test-DDEmailProtocolTls");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }

    private void AddForExport(object view, string domain) {
        lock (_exportLock) {
            _items.Add(view);
            if (!_subjects.Contains(domain, StringComparer.OrdinalIgnoreCase)) {
                _subjects.Add(domain);
            }
        }
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
            0 => "mail-tls",
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
                $"Mail TLS Report - {label}",
                OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                TryOpenReport,
                out hadUnsupportedFormats);

            if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                return ExportNotImplementedAsync("Test-DDEmailProtocolTls");
            }
        } catch (Exception ex) {
            WriteWarning($"Mail TLS export failed: {ex.Message}");
        }
        return Task.CompletedTask;
    }
}
