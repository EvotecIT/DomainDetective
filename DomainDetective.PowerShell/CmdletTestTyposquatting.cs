using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Generates and evaluates typosquatting candidates for a domain.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Check a brand domain for lookalike candidates.</summary>
///   <code>Test-DDDomainTyposquatting -DomainName example.com -BrandKeyword paypal</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDomainTyposquatting", DefaultParameterSetName = "ServerName")]
[Alias("Test-DomainTyposquatting")]
public sealed class CmdletTestTyposquatting : ExportableAsyncPSCmdlet
{
    /// <summary>Domain(s) to analyze.</summary>
    [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    [ValidateDomainName]
    public string[] DomainName = Array.Empty<string>();

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Protected brand terms to combine with the analyzed domain label.</summary>
    [Parameter(Mandatory = false)]
    public string[]? BrandKeyword;

    /// <summary>Additional dictionary words used for candidate generation.</summary>
    [Parameter(Mandatory = false)]
    public string[]? DictionaryWord;

    /// <summary>Alternative TLDs used for TLD swap candidate generation.</summary>
    [Parameter(Mandatory = false)]
    public string[]? AlternativeTld;

    /// <summary>Maximum Levenshtein distance used for edit-distance-based candidate generation.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(0, 10)]
    public int LevenshteinThreshold = 1;

    /// <summary>When specified, visual similarity uses reusable favicon and social-image fingerprinting.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnableVisualSimilarity;

    /// <summary>Maximum number of candidates included in visual similarity comparison.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 50)]
    public int VisualMaxCandidates = 5;

    /// <summary>Maximum number of visual assets compared per analyzed page.</summary>
    [Parameter(Mandatory = false)]
    [ValidateRange(1, 10)]
    public int VisualMaxAssetsPerPage = 3;

    /// <summary>Executes the cmdlet operation.</summary>
    protected override async Task ProcessRecordAsync()
    {
        async Task ProcessDomainAsync(string domain)
        {
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
            var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
            ApplyExecutionOptions(healthCheck);
            healthCheck.TyposquattingLevenshteinThreshold = LevenshteinThreshold;
            healthCheck.TyposquattingBrandKeywords.Clear();
            if (BrandKeyword != null)
            {
                healthCheck.TyposquattingBrandKeywords.AddRange(BrandKeyword);
            }

            healthCheck.TyposquattingAnalysis.DictionaryWords.Clear();
            if (DictionaryWord != null)
            {
                healthCheck.TyposquattingAnalysis.DictionaryWords.AddRange(DictionaryWord);
            }

            healthCheck.TyposquattingAnalysis.AlternativeTlds.Clear();
            if (AlternativeTld != null)
            {
                healthCheck.TyposquattingAnalysis.AlternativeTlds.AddRange(AlternativeTld);
            }

            logger.WriteVerbose("Querying typosquatting candidates for domain: {0}", domain);
            healthCheck.TyposquattingEnableVisualSimilarity = EnableVisualSimilarity.IsPresent;
            healthCheck.TyposquattingVisualMaxCandidates = VisualMaxCandidates;
            healthCheck.TyposquattingVisualMaxAssetsPerPage = VisualMaxAssetsPerPage;
            await healthCheck.VerifyTyposquatting(domain, CancelToken);
            var view = DomainDetective.Views.Converters.Convert(healthCheck.TyposquattingAnalysis);
            WriteObject(view);
            if (IsExportRequested())
            {
                try
                {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new System.Collections.Generic.List<object> { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        domain,
                        DomainDetective.Reports.ReportScope.Normal,
                        $"Typosquatting — {domain}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats)
                    {
                        await ExportNotImplementedAsync("Test-DDDomainTyposquatting");
                    }
                }
                catch (System.Exception ex)
                {
                    WriteWarning($"Typosquatting export failed: {ex.Message}");
                }
            }
        }

        await ForEachAsync(DomainName, ProcessDomainAsync);
    }
}
