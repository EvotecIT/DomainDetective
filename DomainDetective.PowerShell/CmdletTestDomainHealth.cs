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
        /// <summary>Domain(s) to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

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
                if (BrandKeyword != null) {
                    healthCheck.TyposquattingBrandKeywords.AddRange(BrandKeyword);
                }

                logger.WriteVerbose("Querying domain health for domain: {0}", domain);
                // Always run checks first (simple flow), then export if requested.
                await healthCheck.Verify(
                    domain,
                    HealthCheckType,
                    DkimSelectors,
                    DaneServiceType,
                    DanePorts,
                    PortScanProfile,
                    cancellationToken: CancelToken);

                // 1) Always return overall view with Raw property first
                var overall = DomainDetective.Views.Converters.Convert(healthCheck, domain);
                WriteObject(overall);

                // 2) Export (post-run) if requested, after emitting data
                if (IsExportRequested()) {
                    var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format)
                        .Distinct()
                        .ToArray();
                    var wantArtifacts = ExportArtifacts.IsPresent || ExportDefaults.EmitArtifacts;
                    var compositionFormats = formats
                        .Where(f => f == ReportFormat.Word || f == ReportFormat.Html)
                        .ToArray();
                    var dispatcherFormats = formats
                        .Where(f => f != ReportFormat.Word && f != ReportFormat.Html)
                        .ToList();

                    if (wantArtifacts) {
                        try {
                            var artDir = !string.IsNullOrWhiteSpace(this.ArtifactsDirectory)
                                ? this.ArtifactsDirectory
                                : (string.IsNullOrWhiteSpace(ExportDefaults.ArtifactsDirectory) ? null : ExportDefaults.ArtifactsDirectory);
                            var dir = DomainDetective.Reports.ReportRunService.WriteArtifactsOnly(
                                logger,
                                domain,
                                healthCheck,
                                ExportPath,
                                ExportDefaults.OutputDirectory,
                                artDir);
                            WriteVerbose($"Artifacts written to {dir}.");
                        } catch (System.Exception ex) {
                            WriteWarning($"Artifact export failed: {ex.Message}");
                        }
                    }

                    // If specific HealthCheckType selection is provided and we support writers for it,
                    // use the composition aggregators for Word/HTML to ensure identical section rendering.
                    if (compositionFormats.Length > 0) {
                        // Enrich with transport policies when user didn't specify a subset
                        if (HealthCheckType == null || HealthCheckType.Length == 0) {
                            try { await healthCheck.VerifyMTASTS(domain, CancelToken); } catch { }
                            try { await healthCheck.VerifyTLSRPT(domain, CancelToken); } catch { }
                        }

                        var items = new System.Collections.Generic.List<object>();
                        // Export exactly what ran: the default checks plus the transport policies verified above.
                        var selection = HealthCheckType ?? DomainDetective.DomainHealthCheck.DefaultChecks
                            .Concat(new[] { DomainDetective.HealthCheckType.MTASTS, DomainDetective.HealthCheckType.TLSRPT })
                            .Distinct()
                            .ToArray();

                        // Mail classification is computed on demand; every other check converts through the
                        // library's shared check-to-view conversion. Input order is kept for the legacy layouts.
                        var conversionErrors = new System.Collections.Generic.List<string>();
                        foreach (var kind in selection) {
                            if (kind == DomainDetective.HealthCheckType.MAILCLASSIFICATION) {
                                var classifier = new MailDomainClassifier(healthCheck, logger);
                                var mc = await classifier.ClassifyAsync(domain);
                                items.Add(DomainDetective.Views.Converters.Convert(mc));
                            } else {
                                items.AddRange(DomainDetective.Views.Converters.ConvertChecks(healthCheck, new[] { kind }, conversionErrors));
                            }
                        }
                        foreach (var conversionError in conversionErrors) WriteWarning($"Report section skipped: {conversionError}");

                        try {
                            var hadUnsupportedFormats = false;
                            CompositionExportHelper.WriteReports(
                                items,
                                compositionFormats,
                                ExportPath,
                                domain,
                                Reports.ReportScope.Normal,
                                $"Security Report — {domain}",
                                OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                                TryOpen,
                                out hadUnsupportedFormats);
                        } catch (System.Exception ex) {
                            WriteWarning($"Composition export failed, falling back to default: {ex.Message}");
                            dispatcherFormats.InsertRange(0, compositionFormats);
                        }
                    }

                    if (dispatcherFormats.Count > 0) {
                        var dispatcher = new ReportDispatcher();
                        foreach (var format in dispatcherFormats.Distinct()) {
                            try {
                                var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, domain, format, formats);
                                var options = new ReportOptions { Format = format, OutputPath = outPath };
                                options.CustomProperties["Domain"] = domain;
                                var reportResult = await dispatcher.GenerateAsync(
                                    healthCheck,
                                    options,
                                    domain,
                                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser);

                            if (reportResult.Success) {
                                WriteVerbose($"Report generated successfully: {reportResult.FilePath}");
                                if (!string.IsNullOrWhiteSpace(reportResult.ErrorMessage)) WriteWarning(reportResult.ErrorMessage!);
                            } else {
                                WriteWarning(reportResult.ErrorMessage ?? "Export failed.");
                            }
                            } catch (System.Exception ex) {
                                WriteWarning($"Export failed: {ex.Message}");
                            }
                        }
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }

        private void TryOpen(string? path) {
            if (string.IsNullOrWhiteSpace(path)) {
                return;
            }
            try {
                var psi = new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true };
                System.Diagnostics.Process.Start(psi);
            } catch { }
        }
    }
}

