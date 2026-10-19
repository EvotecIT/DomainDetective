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
                // Acquire default document transport policies through the same run owner,
                // rather than retrying them while converting its results.
                var requestedChecks = HealthCheckType;
                if ((requestedChecks == null || requestedChecks.Length == 0) && IsExportRequested()
                    && GetRequestedFormatsOrDefault(ExportDefaults.Format).Any(format => format is ReportFormat.Word or ReportFormat.Html)) {
                    requestedChecks = DomainHealthCheck.DefaultChecks.Concat(new[] {
                        DomainDetective.HealthCheckType.MTASTS, DomainDetective.HealthCheckType.TLSRPT
                    }).Distinct().ToArray();
                }
                System.Exception? verificationFailure = null;
                try {
                    await healthCheck.Verify(
                        domain,
                        requestedChecks,
                        DkimSelectors,
                        DaneServiceType,
                        DanePorts,
                        PortScanProfile,
                        cancellationToken: CancelToken);
                } catch (System.OperationCanceledException) when (CancelToken.IsCancellationRequested) { throw; }
                catch (System.Exception exception) when (exception is not System.OutOfMemoryException
                    && exception is not PipelineStoppedException && exception is not ActionPreferenceStopException) {
                    verificationFailure = exception;
                }

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
                        // Conversion retains existing execution evidence and never reruns failed checks.
                        var conversionErrors = new System.Collections.Generic.List<string>();
                        var items = DomainDetective.Views.Converters.ConvertChecks(healthCheck, healthCheck.LastVerifiedChecks, conversionErrors);
                        foreach (var conversionError in conversionErrors) {
                            WriteWarning($"Report evidence is incomplete: {conversionError}");
                        }

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
                            } else {
                                WriteWarning(reportResult.ErrorMessage ?? "Export failed.");
                            }
                            } catch (System.Exception ex) {
                                WriteWarning($"Export failed: {ex.Message}");
                            }
                        }
                    }
                }
                if (verificationFailure != null) {
                    WriteError(new ErrorRecord(verificationFailure, "DomainCheckFailed", ErrorCategory.InvalidOperation, domain));
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

