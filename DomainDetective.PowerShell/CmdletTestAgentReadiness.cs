using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Assesses whether a website exposes machine-readable resources useful to AI crawlers and agents.</summary>
/// <para>Checks robots.txt, llms.txt, markdown alternates, Content-Signal policy, Link headers, API Catalog, Agent Skills, agents.json, OpenAPI, and trust headers.</para>
/// <example>
///   <summary>Scan a domain for agent readiness.</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Test-DDAgentReadiness -Subject evotec.xyz</code>
/// </example>
/// <example>
///   <summary>Scan a URL and use the Cloudflare-like score profile.</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Test-DDAgentReadiness -Subject https://example.com/ -ScoreProfile CloudflareLike</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDAgentReadiness")]
[Alias("Test-AgentReadiness")]
[OutputType(typeof(DomainDetective.Views.AgentReadinessInfo))]
public sealed class CmdletTestAgentReadiness : ExportableAsyncPSCmdlet {
    /// <para>Domain, host, or absolute HTTP/HTTPS URL to scan.</para>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string[] Subject = Array.Empty<string>();

    /// <para>Score profile used for category weights.</para>
    [Parameter(Mandatory = false)]
    public AgentReadinessScoreProfile ScoreProfile { get; set; } = AgentReadinessScoreProfile.DomainDetectiveDefault;

    /// <para>HTTP timeout in seconds for each probe.</para>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 300)]
    public int TimeoutSeconds { get; set; } = 20;

    /// <para>Do not fall back to HTTP when HTTPS probing fails.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoHttpFallback { get; set; }

    /// <para>Optional user agent sent with probes.</para>
    [Parameter(Mandatory = false)]
    public string UserAgent { get; set; } = "Mozilla/5.0 (compatible; DomainDetective-AgentReadiness)";

    /// <summary>Runs the agent readiness scan.</summary>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync() {
        async Task ProcessSubjectAsync(string subject) {
            var logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                logger,
                WriteVerbose,
                WriteWarning,
                WriteDebug,
                WriteError,
                WriteProgress,
                WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();

            logger.WriteVerbose("Checking agent readiness for {0}", subject);
            var analysis = new AgentReadinessAnalysis();
            var options = new AgentReadinessOptions {
                ScoreProfile = ScoreProfile,
                Timeout = TimeSpan.FromSeconds(TimeoutSeconds),
                AllowHttpFallback = !NoHttpFallback.IsPresent,
                UserAgent = UserAgent
            };

            await analysis.AnalyzeAsync(subject, logger, options, CancelToken).ConfigureAwait(false);
            var view = DomainDetective.Views.Converters.Convert(analysis);
            WriteObject(view);

            if (IsExportRequested()) {
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new List<object> { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        subject,
                        DomainDetective.Reports.ReportScope.Normal,
                        $"Agent Readiness Report - {subject}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDAgentReadiness").ConfigureAwait(false);
                    }
                } catch (Exception ex) {
                    WriteWarning($"Agent readiness export failed: {ex.Message}");
                }
            }
        }

        await ForEachAsync(Subject, ProcessSubjectAsync).ConfigureAwait(false);
    }
}
