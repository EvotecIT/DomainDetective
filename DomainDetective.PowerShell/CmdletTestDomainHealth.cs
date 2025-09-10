using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using System.Linq;

using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
namespace DomainDetective.PowerShell {
    /// <summary>Runs multiple domain health checks and returns the results.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Perform a full health test.</summary>
    ///   <code>Test-DDDomainOverallHealth -DomainName example.com -Verbose</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDomainOverallHealth", DefaultParameterSetName = "ServerName")]
[Alias("Test-DomainHealth")]
    [OutputType(typeof(DomainDetective.Views.DomainOverallInfo))]
    public sealed class CmdletTestDomainHealth : ExportableAsyncPSCmdlet {
        /// <summary>Domain to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string DomainName = string.Empty;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Optional list of DNS endpoints to use (multi-resolver).</summary>
        [Parameter(Mandatory = false)]
        public DnsEndpoint[]? DnsEndpoints { get; set; }

        /// <summary>Strategy used when multiple DNS endpoints are provided.</summary>
        [Parameter(Mandatory = false)]
        public MultiResolverStrategy MultiResolverStrategy { get; set; } = MultiResolverStrategy.FirstSuccess;

        /// <summary>Maximum number of resolvers to query in parallel (null = all).</summary>
        [Parameter(Mandatory = false)]
        public int? MultiResolverMaxParallelism { get; set; }

        /// <summary>Specific tests to run.</summary>
        [Parameter(Mandatory = false)]
        public HealthCheckType[]? HealthCheckType;

        /// <summary>DKIM selectors used when testing DKIM.</summary>
        [Parameter(Mandatory = false)]
        public string[]? DkimSelectors;

        /// <summary>Service types to check for DANE. HTTPS (port 443) is queried by default.</summary>
        [Parameter(Mandatory = false)]
        public ServiceType[]? DaneServiceType;

        /// <summary>Custom ports to check for DANE.</summary>
        [Parameter(Mandatory = false)]
        public int[]? DanePorts;

        /// <summary>Protected brand terms for typosquatting analysis.</summary>
        [Parameter(Mandatory = false)]
        public string[]? BrandKeyword;
        /// <summary>Port scan profiles to use.</summary>
        [Parameter(Mandatory = false)]
        public PortScanProfile[]? PortScanProfile;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

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
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            if (DnsEndpoints != null && DnsEndpoints.Length > 0)
            {
                _healthCheck.DnsEndpoints.AddRange(DnsEndpoints);
                _healthCheck.MultiResolverStrategy = MultiResolverStrategy;
                _healthCheck.MultiResolverMaxParallelism = MultiResolverMaxParallelism;
            }
            if (BrandKeyword != null)
            {
                _healthCheck.TyposquattingBrandKeywords.AddRange(BrandKeyword);
            }
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying domain health for domain: {0}", DomainName);
            // Always run checks first (simple flow), then export if requested.
            // Brand keywords already applied in BeginProcessing when provided.
            await _healthCheck.Verify(DomainName, HealthCheckType, DkimSelectors, DaneServiceType, DanePorts, PortScanProfile);

            // 1) Always return overall view with Raw property first
            var overall = DomainDetective.Views.Converters.Convert(_healthCheck, DomainName);
            WriteObject(overall);

            // 2) Export (post-run) if requested, after emitting data
            if (IsExportRequested()) {
                var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                var outPath = ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, DomainName, fmt);
                var wantArtifacts = ExportArtifacts.IsPresent || ExportDefaults.EmitArtifacts;

                // If specific HealthCheckType selection is provided and we support writers for it,
                // use the composition aggregators for Word/HTML to ensure identical section rendering.
                var wantsComposition = (fmt == ReportFormat.Word || fmt == ReportFormat.Html);
                if (wantsComposition) {
                    // Enrich with transport policies when user didn't specify a subset
                    if (HealthCheckType == null || HealthCheckType.Length == 0)
                    {
                        try { await _healthCheck.VerifyMTASTS(DomainName); } catch { }
                        try { await _healthCheck.VerifyTLSRPT(DomainName); } catch { }
                    }

                    var items = new System.Collections.Generic.List<object>();
                    var selection = HealthCheckType ?? new[] {
                        DomainDetective.HealthCheckType.SPF,
                        DomainDetective.HealthCheckType.DKIM,
                        DomainDetective.HealthCheckType.DMARC,
                        DomainDetective.HealthCheckType.MX,
                        DomainDetective.HealthCheckType.DNSSEC,
                        DomainDetective.HealthCheckType.DANE,
                        DomainDetective.HealthCheckType.MTASTS,
                        DomainDetective.HealthCheckType.TLSRPT,
                        DomainDetective.HealthCheckType.DNSBL,
                        DomainDetective.HealthCheckType.RPKI
                    };

                    foreach (var kind in selection) {
                        switch (kind) {
                            case DomainDetective.HealthCheckType.SPF:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.SpfAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.DKIM:
                                items.AddRange(DomainDetective.Views.Converters.Convert(_healthCheck.DKIMAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.DMARC:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.DmarcAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.MX:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.MXAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.DNSSEC:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.DnsSecAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.DANE:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.DaneAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.DNSBL:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.DNSBLAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.MTASTS:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.MTASTSAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.TLSRPT:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.TLSRPTAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.RPKI:
                                items.Add(DomainDetective.Views.Converters.Convert(_healthCheck.RpkiAnalysis));
                                break;
                            case DomainDetective.HealthCheckType.MAILCLASSIFICATION:
                                {
                                    var classifier = new MailDomainClassifier(_healthCheck, _logger);
                                    var mc = await classifier.ClassifyAsync(DomainName);
                                    items.Add(DomainDetective.Views.Converters.Convert(mc));
                                    break;
                                }
                            default:
                                break; // unsupported here falls back to default path
                        }
                    }

                    try {
                        if (fmt == ReportFormat.Word) {
                            DomainDetective.Reports.Office.WordCompositionReport.Generate(
                                outPath,
                                items,
                                Reports.ReportScope.Normal,
                                showInfoFindings: true,
                                narrativePlacement: ExportDefaults.NarrativePlacement,
                                titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"Security Report — {DomainName}" : ExportDefaults.NarrativeTitle,
                                subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                                categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                                keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                                creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                                companyName: ExportDefaults.CompanyName,
                                companyAddress: ExportDefaults.CompanyAddress,
                                companyYear: ExportDefaults.CompanyYear,
                                logoPath: string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                                headerText: string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                                watermarkText: string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText);
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpen(outPath);
                        } else {
                            DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                                outPath,
                                items,
                                Reports.ReportScope.Normal,
                                OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                                ExportDefaults.NarrativePlacement,
                                titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                                authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                                descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
                        }
                        return;
                    } catch (System.Exception ex) {
                        WriteWarning($"Composition export failed, falling back to default: {ex.Message}");
                        // fall through to default behavior
                    }
                }

                try {
                    if (wantArtifacts) {
                        var artDir = !string.IsNullOrWhiteSpace(this.ArtifactsDirectory)
                            ? this.ArtifactsDirectory
                            : (string.IsNullOrWhiteSpace(ExportDefaults.ArtifactsDirectory) ? null : ExportDefaults.ArtifactsDirectory);
                        var (dir, reportResult) = await DomainDetective.Reports.ReportRunService.ExportOnlyAsync(
                            _logger,
                            DomainName,
                            _healthCheck,
                            fmt,
                            outPath,
                            ExportDefaults.OutputDirectory,
                            false,
                            artDir);
                        WriteVerbose($"Artifacts written to {dir}.");
                        if (reportResult.Success) {
                            WriteVerbose($"Report generated successfully: {reportResult.FilePath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpen(reportResult.FilePath);
                        } else {
                        WriteWarning(reportResult.ErrorMessage ?? "Report generation failed.");
                        }
                    } else {
                        var dispatcher = new ReportDispatcher();
                        var options = new ReportOptions { Format = fmt, OutputPath = outPath };
                        options.CustomProperties["Domain"] = DomainName;
                        var reportResult = await dispatcher.GenerateAsync(_healthCheck, options, DomainName, false);
                        if (reportResult.Success) {
                            WriteVerbose($"Report generated successfully: {reportResult.FilePath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpen(reportResult.FilePath);
                        } else {
                    WriteWarning(reportResult.ErrorMessage ?? "Export failed.");
                        }
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"Export failed: {ex.Message}");
                }
            }
        }

        private void TryOpen(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            try {
                var psi = new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true };
                System.Diagnostics.Process.Start(psi);
            } catch { }
        }
    }
}
