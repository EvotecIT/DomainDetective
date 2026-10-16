using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Generates common typosquatting variants and checks if they resolve.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public partial class TyposquattingAnalysis : IHasAssessments
{
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; private set; }

    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override DNS query logic.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    internal PublicSuffixList PublicSuffixList { get; set; } = new();
    
    /// <summary>All generated variants.</summary>
    public List<string> Variants { get; private set; } = new();

    /// <summary>Variants that resolve in DNS.</summary>
    public List<string> ActiveDomains { get; private set; } = new();

    /// <summary>Variants that appear registered based on DNS footprint.</summary>
    public List<string> RegisteredDomains { get; private set; } = new();

    /// <summary>Structured candidate details for generated variants.</summary>
    public IReadOnlyList<TyposquattingCandidate> Candidates { get; private set; } = Array.Empty<TyposquattingCandidate>();

    /// <summary>Protected brand keywords for impersonation detection.</summary>
    public List<string> BrandKeywords { get; } = new();

    /// <summary>Additional dictionary words used for candidate generation.</summary>
    public List<string> DictionaryWords { get; } = new();

    /// <summary>Alternative TLDs used for TLD swap generation.</summary>
    public List<string> AlternativeTlds { get; } = new();

    /// <summary>Optional downstream enrichment for promising candidates.</summary>
    public TyposquattingEnrichmentOptions EnrichmentOptions { get; } = new();

    /// <summary>Optional ownership profile comparison against the source domain.</summary>
    public TyposquattingOwnershipProfileOptions OwnershipProfileOptions { get; } = new();

    /// <summary>Optional content similarity comparison against the source domain.</summary>
    public TyposquattingContentSimilarityOptions ContentSimilarityOptions { get; } = new();

    /// <summary>Optional visual similarity comparison against the source domain.</summary>
    public TyposquattingVisualSimilarityOptions VisualSimilarityOptions { get; } = new();

    /// <summary>Maximum allowed Levenshtein distance when generating variants.</summary>
    public int LevenshteinThreshold { get; set; } = 1;

    /// <summary>Flag to detect homoglyph characters in input.</summary>
    public bool DetectHomoglyphs { get; set; } = true;

    /// <summary>Indicates whether input contains homoglyph characters.</summary>
    public bool ContainsHomoglyphs { get; private set; }

    /// <summary>When true, candidate enrichment includes NS and MX record checks.</summary>
    public bool IncludeNsAndMxChecks { get; set; } = true;

    /// <summary>Maximum candidates queried concurrently. Each candidate uses up to four independent DNS queries.</summary>
    public int MaxDnsParallelism { get; set; } = 8;

    /// <summary>Whole-analysis cancellation budget, including optional enrichment. Admitted callbacks are observed before returning.</summary>
    public TimeSpan AnalysisTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Whether the analysis and all candidate DNS checks completed.</summary>
    public bool AnalysisComplete { get; private set; }

    /// <summary>Ownership baseline built for the analyzed source domain.</summary>
    public TyposquattingOwnershipProfile? SourceOwnershipProfile { get; private set; }

    /// <summary>Source-domain content fingerprint used for similarity comparison.</summary>
    public TyposquattingSourceContentProfile? SourceContentProfile { get; private set; }

    /// <summary>Source-domain visual fingerprint used for screenshot-style comparison.</summary>
    public TyposquattingSourceVisualProfile? SourceVisualProfile { get; private set; }

    /// <summary>Shared external infrastructure clusters across generated candidates.</summary>
    public IReadOnlyList<TyposquattingInfrastructureCluster> InfrastructureClusters { get; private set; } = Array.Empty<TyposquattingInfrastructureCluster>();

    /// <summary>Campaign-level rollups for shared suspicious infrastructure.</summary>
    public IReadOnlyList<TyposquattingInfrastructureCampaign> InfrastructureCampaigns { get; private set; } = Array.Empty<TyposquattingInfrastructureCampaign>();

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (QueryDnsOverride != null)
        {
            var answers = await QueryDnsOverride(name, type);
            ct.ThrowIfCancellationRequested();
            return answers;
        }

        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: ct);
    }

    /// <summary>
    /// Generates variants of <paramref name="domainName"/> and enriches them with DNS evidence.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        if (AnalysisTimeout <= TimeSpan.Zero) { throw new ArgumentOutOfRangeException(nameof(AnalysisTimeout)); }
        if (MaxDnsParallelism <= 0) { throw new ArgumentOutOfRangeException(nameof(MaxDnsParallelism)); }
        AnalysisComplete = false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(AnalysisTimeout);
        try {
            await AnalyzeCore(domainName, logger, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            ct.ThrowIfCancellationRequested();
            AnalysisComplete = Candidates.All(candidate => !candidate.DnsChecksIncomplete);
        } catch (OperationCanceledException) when (!ct.IsCancellationRequested && deadline.IsCancellationRequested) {
            logger?.WriteInformationCode("TYPOSQUAT.Analysis.Incomplete", "Typosquatting analysis budget exhausted; unchecked candidates remain unknown.");
        }
    }

    private async Task AnalyzeCore(string domainName, InternalLogger logger, CancellationToken ct) {
        if (string.IsNullOrWhiteSpace(domainName))
        {
            throw new ArgumentNullException(nameof(domainName));
        }

        Subject = domainName.Trim();
        var list = PublicSuffixList ?? new PublicSuffixList();
        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "TYPOSQUAT", target: domainName) : null;
        ContainsHomoglyphs = DetectHomoglyphs && StringAlgorithms.ContainsHomoglyphs(domainName);
        if (ContainsHomoglyphs)
        {
            logger?.WriteWarningCode(TyposquattingCodes.ContainsHomoglyphs, "Domain contains homoglyph characters: {0}", domainName);
        }

        var builtCandidates = BuildCandidates(domainName, list, LevenshteinThreshold, BrandKeywords, DictionaryWords, AlternativeTlds).ToList();
        Candidates = builtCandidates;
        Variants = builtCandidates.Select(candidate => candidate.Domain).ToList();
        ActiveDomains = new List<string>();
        RegisteredDomains = new List<string>();
        SourceOwnershipProfile = null;
        SourceContentProfile = null;
        SourceVisualProfile = null;
        InfrastructureClusters = Array.Empty<TyposquattingInfrastructureCluster>();
        InfrastructureCampaigns = Array.Empty<TyposquattingInfrastructureCampaign>();

        foreach (var candidate in builtCandidates) { candidate.DnsChecksIncomplete = true; }
        try {
            await AuthoritativeDnsProbes.RunAsync(builtCandidates, async candidate => {
                var types = IncludeNsAndMxChecks
                    ? new[] { DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.NS, DnsRecordType.MX }
                    : new[] { DnsRecordType.A, DnsRecordType.AAAA };
                var responses = await Task.WhenAll(types.Select(type => QueryCandidateDnsAsync(candidate.Domain, type, ct))).ConfigureAwait(false);
                candidate.ARecords = NormalizeDnsAnswers(responses[0].Answers);
                candidate.AaaaRecords = NormalizeDnsAnswers(responses[1].Answers);
                if (IncludeNsAndMxChecks) {
                    candidate.NsRecords = NormalizeDnsAnswers(responses[2].Answers);
                    candidate.MxRecords = NormalizeDnsAnswers(responses[3].Answers);
                }
                candidate.DnsQueryErrors = responses.Where(response => !string.IsNullOrEmpty(response.Error))
                    .Select(response => response.Error!).ToArray();
                candidate.DnsChecksIncomplete = candidate.DnsQueryErrors.Count > 0;
                return candidate;
            }, MaxDnsParallelism, ct).ConfigureAwait(false);
        } finally {
            foreach (var candidate in builtCandidates) {
                if (candidate.AppearsRegistered) { RegisteredDomains.Add(candidate.Domain); }
                if (candidate.Resolves) {
                    ActiveDomains.Add(candidate.Domain);
                    logger?.WriteWarningCode(TyposquattingCodes.VariantActive,
                        "Potential typosquat detected: {0} ({1})", candidate.Domain, candidate.Kind);
                }
            }
        }

        if (EnrichmentOptions.HasAnyEnabledChecks)
        {
            var pipeline = new TyposquattingEnrichmentPipeline
            {
                DnsConfiguration = DnsConfiguration,
                GetRegistrableDomain = list.GetRegistrableDomain
            };
            await pipeline.EnrichAsync(builtCandidates, EnrichmentOptions, logger, ct).ConfigureAwait(false);
        }

        if (OwnershipProfileOptions.Enabled)
        {
            SourceOwnershipProfile = await TyposquattingOwnershipAnalyzer.BuildProfileAsync(
                domainName,
                DnsConfiguration,
                (name, type) => QueryDns(name, type, ct),
                OwnershipProfileOptions,
                ct).ConfigureAwait(false);
            TyposquattingOwnershipAnalyzer.CompareCandidates(builtCandidates, SourceOwnershipProfile);
        }

        if (ContentSimilarityOptions.Enabled)
        {
            SourceContentProfile = await TyposquattingContentSimilarityAnalyzer.BuildProfileAsync(
                domainName,
                DnsConfiguration,
                list.GetRegistrableDomain,
                ContentSimilarityOptions,
                ct).ConfigureAwait(false);
            TyposquattingContentSimilarityAnalyzer.CompareCandidates(builtCandidates, SourceContentProfile, ContentSimilarityOptions);
        }

        if (VisualSimilarityOptions.Enabled)
        {
            SourceVisualProfile = await TyposquattingVisualSimilarityAnalyzer.BuildProfileAsync(
                domainName,
                VisualSimilarityOptions,
                ct).ConfigureAwait(false);
            await TyposquattingVisualSimilarityAnalyzer.CompareCandidatesAsync(
                builtCandidates,
                SourceVisualProfile,
                VisualSimilarityOptions,
                ct).ConfigureAwait(false);
        }

        InfrastructureClusters = TyposquattingInfrastructureClusterAnalyzer.BuildClusters(builtCandidates);
        TyposquattingCandidateScorer.ScoreCandidates(builtCandidates);
        InfrastructureClusters = TyposquattingInfrastructureClusterAnalyzer.BuildClusters(builtCandidates);
        TyposquattingDispositionAnalyzer.Apply(builtCandidates);
        InfrastructureCampaigns = TyposquattingInfrastructureCampaignAnalyzer.BuildCampaigns(InfrastructureClusters, builtCandidates);

        if (ActiveDomains.Count == 0 && builtCandidates.All(candidate => !candidate.DnsChecksIncomplete))
        {
            logger?.WriteInformationCode(TyposquattingCodes.VariantNone, "No active typosquat variants detected");
        }

        if (RegisteredDomains.Count > 0)
        {
            logger?.WriteInformationCode(TyposquattingCodes.DefensiveRegistered, $"{RegisteredDomains.Count} variant(s) show a DNS footprint");
        }
    }

    private async Task<DnsResponse> QueryCandidateDnsAsync(string name, DnsRecordType type, CancellationToken ct) {
        ct.ThrowIfCancellationRequested();
        if (QueryDnsOverride != null) {
            var answers = await QueryDnsOverride(name, type).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            return new DnsResponse { Status = DnsResponseCode.NoError, Answers = answers };
        }
        var response = await DnsConfiguration.QueryDNSResponse(name, type, cancellationToken: ct).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(response.Error) || response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
            return new DnsResponse {
                Status = response.Status,
                Error = $"{type}: {response.Error ?? response.Status.ToString()}",
                Answers = Array.Empty<DnsAnswer>()
            };
        }
        return response;
    }

    private static IReadOnlyList<string> NormalizeDnsAnswers(DnsAnswer[]? answers)
    {
        if (answers == null || answers.Length == 0)
        {
            return Array.Empty<string>();
        }

        return answers
            .Select(static answer => (answer.Data ?? answer.DataRaw ?? string.Empty).Trim().TrimEnd('.'))
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
