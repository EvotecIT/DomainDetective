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
                var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
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
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDMailDomainClassification");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }

    /// <summary>When export is requested, compose Mail Classification sections into a single file.</summary>
    protected override Task EndProcessingAsync() {
        if (_items.Count == 0) return Task.CompletedTask;
        var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
        if (fmt != DomainDetective.Reports.ReportFormat.Word && fmt != DomainDetective.Reports.ReportFormat.Html) return Task.CompletedTask;

        var label = _subjects.Count switch {
            0 => "mail-classification",
            1 => _subjects[0],
            2 => $"{_subjects[0]}+{_subjects[1]}",
            _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
        };
        var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, fmt);
        try {
            if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                DomainDetective.Reports.Office.WordCompositionReport.Generate(
                    outPath,
                    _items,
                    DomainDetective.Reports.ReportScope.Normal,
                    showInfoFindings: true,
                    narrativePlacement: ExportDefaults.NarrativePlacement,
                    titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"Mail Classification — {label}" : ExportDefaults.NarrativeTitle,
                    subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                    categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                    keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                    creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                    summaryColumnCap: ExportDefaults.SummaryColumnCap,
                    headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                    footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
            } else {
                DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                    outPath,
                    _items,
                    DomainDetective.Reports.ReportScope.Normal,
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    narrativePlacement: ExportDefaults.NarrativePlacement,
                    titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                    authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                    descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
            }
        } catch (System.Exception ex) {
            WriteWarning($"Mail classification export failed: {ex.Message}");
        }
        return Task.CompletedTask;
    }
}

