using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective.PowerShell;

/// <summary>Classifies a domain's mail role based on DNS signals.</summary>
/// <para>Performs SPF, DKIM, MX, MTA-STS, TLS-RPT, DANE(SMTP) and BIMI checks to infer if the domain sends, receives, both, or is parked.</para>
/// <example>
///   <summary>Classify a single domain</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Get-DDMailDomainClassification -DomainName example.com</code>
///   <para>Returns category, confidence, signals, score, and RFC references.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDMailDomainClassification", DefaultParameterSetName = "ByName")]
[OutputType(typeof(MailDomainClassificationResult))]
public sealed class CmdletTestMailDomainClassification : ExportableAsyncPSCmdlet {
    /// <para>Domain(s) to analyze.</para>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = System.Array.Empty<string>();

    /// <para>DNS server used for queries.</para>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ByName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    private readonly System.Collections.Generic.List<object> _items = new();
    private readonly System.Collections.Generic.List<string> _subjects = new();
    private readonly object _exportLock = new();
    private bool _hadUnsupportedFormats;

    // BeginProcessing handled per-domain to allow safe parallelism.

    /// <summary>Executes classification for each domain.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
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

            var classifier = new MailDomainClassifier(healthCheck, logger);
            var result = await classifier.ClassifyAsync(domain);
            var view = DomainDetective.Views.Converters.Convert(result);
            WriteObject(view);

            // Short provider chain formatter for console output
            try
            {
                var primary = string.IsNullOrWhiteSpace(view.ProviderPrimary) ? "(unknown)" : view.ProviderPrimary;
                var gateways = (view.ProviderGateways != null && view.ProviderGateways.Count > 0) ? string.Join(", ", view.ProviderGateways) : "none";
                var outbound = (view.ProviderOutbound != null && view.ProviderOutbound.Count > 0) ? string.Join(", ", view.ProviderOutbound) : "none";
                var msg = $"Provider: {primary}; Gateways: {gateways}; Outbound: {outbound}";
                WriteInformation(msg, new string[] { "DomainDetective", "Mail", "Provider" });
            }
            catch { }

            // When exporting, enrich the composition with detailed MX/SPF/DKIM/DMARC/MTASTS/TLS-RPT sections
            if (IsExportRequested()) {
                var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format);
                var wantsComposition = formats.Any(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html);
                var hasUnsupportedFormats = formats.Any(f => f != DomainDetective.Reports.ReportFormat.Word && f != DomainDetective.Reports.ReportFormat.Html);

                if (wantsComposition) {
                    // Ensure DMARC is available (not required by classifier but expected in composed reports)
                    try { await healthCheck.VerifyDMARC(domain, cancellationToken: CancelToken); } catch { }

                    lock (_exportLock) {
                        _subjects.Add(domain);
                        _items.Add(view); // Mail Classification
                        if (healthCheck.MXAnalysis != null) _items.Add(DomainDetective.Views.Converters.Convert(healthCheck.MXAnalysis));
                        if (healthCheck.SpfAnalysis != null) _items.Add(DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis));
                        if (healthCheck.DKIMAnalysis != null) _items.AddRange(DomainDetective.Views.Converters.Convert(healthCheck.DKIMAnalysis));
                        if (healthCheck.DmarcAnalysis != null) _items.Add(DomainDetective.Views.Converters.Convert(healthCheck.DmarcAnalysis));
                        if (healthCheck.MTASTSAnalysis != null) _items.Add(DomainDetective.Views.Converters.Convert(healthCheck.MTASTSAnalysis));
                        if (healthCheck.TLSRPTAnalysis != null) _items.Add(DomainDetective.Views.Converters.Convert(healthCheck.TLSRPTAnalysis));
                        _hadUnsupportedFormats |= hasUnsupportedFormats;
                    }
                }

                if (!wantsComposition) {
                    await ExportNotImplementedAsync("Test-DDMailDomainClassification");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }

    /// <summary>When export is requested, compose Mail Classification sections into a single file.</summary>
    protected override Task EndProcessingAsync() {
        if (_items.Count == 0) return Task.CompletedTask;
        var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format)
            .Where(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html)
            .ToArray();
        if (formats.Length == 0) return Task.CompletedTask;

        var label = _subjects.Count switch {
            0 => "mail-classification",
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
                DomainDetective.Reports.ReportScope.Normal,
                $"Mail Classification — {label}",
                OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                TryOpenReport,
                out hadUnsupportedFormats);

            if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                return ExportNotImplementedAsync("Test-DDMailDomainClassification");
            }
        } catch (System.Exception ex) {
            WriteWarning($"Mail classification export failed: {ex.Message}");
        }
        return Task.CompletedTask;
    }
}
