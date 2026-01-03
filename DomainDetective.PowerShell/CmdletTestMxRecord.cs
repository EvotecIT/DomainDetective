using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves MX records for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check MX configuration.</summary>
    ///   <code>Test-DDDnsMxRecord -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsMxRecord", DefaultParameterSetName = "ServerName")]
    [Alias("Test-DnsMx", "Test-MxRecord")]
    public sealed class CmdletTestMxRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

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

                logger.WriteVerbose("Querying MX record for domain: {0}", domain);
                await healthCheck.VerifyMX(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.MXAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                    if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                        var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, domain, fmt);
                        try {
                            DomainDetective.Reports.Office.WordCompositionReport.Generate(
                                outPath,
                                new System.Collections.Generic.List<object> { view },
                                DomainDetective.Reports.ReportScope.Normal,
                                showInfoFindings: true,
                                narrativePlacement: ExportDefaults.NarrativePlacement,
                                titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"MX Report — {domain}" : ExportDefaults.NarrativeTitle,
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
                        } catch (System.Exception ex) {
                            WriteWarning($"MX export failed: {ex.Message}");
                        }
                    } else {
                        await ExportNotImplementedAsync("Test-DDDnsMxRecord");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}



