using System;
using System.IO;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.DesiredState;

namespace DomainDetective.PowerShell;

/// <summary>Validates domains against an organization-specific desired state baseline.</summary>
/// <para>Loads a JSON desired state configuration and evaluates non-conformance for each domain.</para>
/// <example>
///   <summary>Test a domain against a baseline</summary>
///   <prefix>PS&gt; </prefix>
///   <code>Test-DDDesiredState -DomainName example.com -DesiredStatePath .\desired-state.json</code>
///   <para>Returns desired state conformance results and issues.</para>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDesiredState", DefaultParameterSetName = "ByName")]
[Alias("Test-DesiredState")]
[OutputType(typeof(DomainDetective.Views.DesiredStateInfo))]
public sealed class CmdletTestDesiredState : ExportableAsyncPSCmdlet {
    /// <para>Domain(s) to analyze.</para>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ByConfiguration", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = Array.Empty<string>();

    /// <para>Path to a desired state JSON configuration file.</para>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ByName")]
    [ValidateNotNullOrEmpty]
    public string DesiredStatePath = string.Empty;

    /// <para>In-memory desired state configuration object.</para>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ByConfiguration")]
    [ValidateNotNull]
    public DesiredStateConfiguration? Configuration { get; set; }

    /// <para>DNS server used for queries.</para>
    [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ByName")]
    [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ByConfiguration")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <para>Do not run mail classification even if the baseline contains classification-specific overrides.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter NoClassification { get; set; }

    /// <para>Controls how desired state and best-practice findings are separated for reporting.</para>
    [Parameter(Mandatory = false)]
    public DesiredStateMode? DesiredStateMode { get; set; }

    /// <para>When set, throws on evaluation exceptions instead of logging and continuing.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter FailFast { get; set; }

    /// <para>When set, logs evaluation exceptions as errors instead of warnings.</para>
    [Parameter(Mandatory = false)]
    public SwitchParameter LogEvaluationErrorsAsErrors { get; set; }

    /// <summary>Executes desired state evaluation for each domain.</summary>
    protected override async Task ProcessRecordAsync() {
        DesiredStateConfiguration config;
        if (Configuration != null) {
            config = Configuration;
        } else {
            try {
                config = DesiredStateConfiguration.Load(DesiredStatePath);
            } catch (Exception ex) {
                WriteError(new ErrorRecord(ex, "DesiredStateLoadFailed", ErrorCategory.InvalidData, DesiredStatePath));
                return;
            }
        }

        var wantsClassification = !NoClassification.IsPresent && config.RequiresMailClassification();
        var mode = DesiredStateMode ?? config.Mode;

        async Task ProcessDomainAsync(string domain) {
            try {
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

                DomainDetective.Definitions.MailDomainClassificationCategory? classification = null;
                if (wantsClassification) {
                    var classifier = new MailDomainClassifier(healthCheck, logger);
                    var mc = await classifier.ClassifyAsync(domain, CancelToken);
                    classification = mc.Classification;
                }

                var profile = config.ResolveProfile(domain, classification);
                var toRun = config.GetChecksToRun(profile, mode);

                string[]? dkimSelectors = null;
                if (profile.Dkim != null && profile.Dkim.Enabled != false && profile.Dkim.RequiredSelectors != null && profile.Dkim.RequiredSelectors.Length > 0) {
                    dkimSelectors = profile.Dkim.RequiredSelectors;
                    healthCheck.ExecutionOptions.IncludeMissingDkimSelectors = true;
                }

                ServiceType[]? daneServiceTypes = null;
                if (profile.Dane != null && profile.Dane.Enabled != false && profile.Dane.RequiredServices != null && profile.Dane.RequiredServices.Length > 0) {
                    daneServiceTypes = profile.Dane.RequiredServices;
                }

                if (profile.Bimi != null && profile.Bimi.Enabled != false && profile.Bimi.SkipIndicatorDownload == true) {
                    healthCheck.ExecutionOptions.SkipBimiIndicatorDownload = true;
                }

                await healthCheck.Verify(
                    domain,
                    healthCheckTypes: toRun,
                    dkimSelectors: dkimSelectors,
                    daneServiceType: daneServiceTypes,
                    cancellationToken: CancelToken,
                    useDefaultChecksWhenEmpty: false);

                var desired = DesiredStateEvaluator.Evaluate(domain, healthCheck, profile, classification, new DesiredStateEvaluationOptions {
                    ThrowOnError = FailFast.IsPresent,
                    LogExceptionsAsErrors = LogEvaluationErrorsAsErrors.IsPresent
                });
                desired.Mode = mode;
                var view = DomainDetective.Views.Converters.Convert(desired, profile, mode);
                WriteObject(view);

                if (IsExportRequested()) {
                    var request = CreateExportRequest(
                        new object[] { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        OpenInBrowser.IsPresent,
                        ExportDefaults.OpenInBrowser);
                    await DomainDetective.Reports.CompositionExportService.ExportAsync(request, logger, CancelToken).ConfigureAwait(false);
                }
            } catch (OperationCanceledException) {
                throw;
            } catch (PipelineStoppedException) {
                throw;
            } catch (Exception ex) {
                WriteError(new ErrorRecord(ex, "DesiredStateDomainFailed", ErrorCategory.NotSpecified, domain));
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }

    internal static DomainDetective.Reports.CompositionExportRequest CreateExportRequest(
        IReadOnlyList<object> items,
        IReadOnlyList<DomainDetective.Reports.ReportFormat> formats,
        string? exportPath,
        bool openInBrowserRequested,
        bool defaultOpenInBrowser)
    {
        return new DomainDetective.Reports.CompositionExportRequest {
            Items = items ?? Array.Empty<object>(),
            Formats = formats ?? Array.Empty<DomainDetective.Reports.ReportFormat>(),
            ExportPath = exportPath,
            DefaultOutputDirectory = ExportDefaults.OutputDirectory,
            OpenInBrowser = openInBrowserRequested || defaultOpenInBrowser,
            NarrativePlacement = ExportDefaults.NarrativePlacement,
            CompanyName = string.IsNullOrWhiteSpace(ExportDefaults.CompanyName) ? null : ExportDefaults.CompanyName,
            CompanyAddress = string.IsNullOrWhiteSpace(ExportDefaults.CompanyAddress) ? null : ExportDefaults.CompanyAddress,
            CompanyYear = string.IsNullOrWhiteSpace(ExportDefaults.CompanyYear) ? null : ExportDefaults.CompanyYear,
            LogoPath = string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
            HeaderText = string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
            FooterText = string.IsNullOrWhiteSpace(ExportDefaults.FooterText) ? null : ExportDefaults.FooterText,
            WatermarkText = string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText,
            HeaderLogoSizePx = ExportDefaults.HeaderLogoSizePx,
            FooterLogoSizePx = ExportDefaults.FooterLogoSizePx,
            AutoCollectTtl = true
        };
    }
}
