using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Reusable orchestration for enriching typosquatting candidates with existing DD analyses.
/// </summary>
public sealed class TyposquattingEnrichmentPipeline
{
    /// <summary>DNS configuration reused by downstream analyses.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Optional registrable domain resolver used by web/static analyses.</summary>
    public Func<string, string>? GetRegistrableDomain { get; set; }

    /// <summary>
    /// Enriches selected candidates in place using existing DD protocol analyses.
    /// </summary>
    public async Task EnrichAsync(
        IReadOnlyList<TyposquattingCandidate> candidates,
        TyposquattingEnrichmentOptions options,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        if (candidates == null || candidates.Count == 0 || options == null || !options.HasAnyEnabledChecks)
        {
            return;
        }

        var selected = candidates
            .Where(candidate => candidate != null)
            .Where(candidate => !options.RegisteredOnly || candidate.AppearsRegistered)
            .OrderByDescending(candidate => candidate.Resolves)
            .ThenByDescending(candidate => candidate.AppearsRegistered)
            .ThenBy(candidate => candidate.EditDistance)
            .ThenBy(candidate => candidate.Domain, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(0, options.MaxCandidates))
            .ToList();

        if (selected.Count == 0)
        {
            return;
        }

        using var gate = new SemaphoreSlim(Math.Max(1, options.MaxParallelism));
        var tasks = selected.Select(async candidate =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                candidate.Enrichment = await EnrichCandidateAsync(candidate, options, logger, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task<TyposquattingCandidateEnrichment> EnrichCandidateAsync(
        TyposquattingCandidate candidate,
        TyposquattingEnrichmentOptions options,
        InternalLogger? logger,
        CancellationToken cancellationToken)
    {
        var enrichment = new TyposquattingCandidateEnrichment
        {
            Domain = candidate.Domain,
            EnrichedAtUtc = DateTimeOffset.UtcNow
        };

        if (options.IncludeWhois && candidate.AppearsRegistered)
        {
            enrichment.Whois = await BuildWhoisAsync(candidate.Domain, options, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeHttp && candidate.Resolves)
        {
            enrichment.Http = await BuildHttpAsync(candidate.Domain, options, logger, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeWebStaticScan && candidate.Resolves)
        {
            enrichment.WebStaticScan = await BuildWebStaticScanAsync(candidate.Domain, options, logger, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeThreatIntel && candidate.AppearsRegistered)
        {
            enrichment.ThreatIntel = await BuildThreatIntelAsync(candidate.Domain, options, logger, cancellationToken).ConfigureAwait(false);
        }

        if (options.IncludeIpEnrichment && candidate.Resolves)
        {
            enrichment.IpEnrichment = await BuildIpEnrichmentAsync(candidate.Domain, options, logger, cancellationToken).ConfigureAwait(false);
        }

        return enrichment;
    }

    private async Task<WhoisAnalysis?> BuildWhoisAsync(string domain, TyposquattingEnrichmentOptions options, CancellationToken cancellationToken)
    {
        if (options.WhoisOverride != null)
        {
            return await options.WhoisOverride(domain, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new WhoisAnalysis
        {
            DnsConfiguration = DnsConfiguration
        };
        await analysis.QueryWhoisServer(domain, cancellationToken).ConfigureAwait(false);
        await analysis.QueryIana(domain, cancellationToken).ConfigureAwait(false);
        return analysis;
    }

    private async Task<HttpAnalysis?> BuildHttpAsync(string domain, TyposquattingEnrichmentOptions options, InternalLogger? logger, CancellationToken cancellationToken)
    {
        if (options.HttpOverride != null)
        {
            return await options.HttpOverride(domain, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new HttpAnalysis
        {
            Subject = $"https://{domain}"
        };
        await analysis.AnalyzeUrl(
            analysis.Subject,
            checkHsts: true,
            logger: logger ?? new InternalLogger(),
            collectHeaders: true,
            captureBody: options.CaptureHttpBody,
            cancellationToken: cancellationToken,
            requestOptions: options.HttpRequestOptions).ConfigureAwait(false);
        return analysis;
    }

    private async Task<WebStaticScanAnalysis?> BuildWebStaticScanAsync(string domain, TyposquattingEnrichmentOptions options, InternalLogger? logger, CancellationToken cancellationToken)
    {
        if (options.WebStaticScanOverride != null)
        {
            return await options.WebStaticScanOverride(domain, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new WebStaticScanAnalysis
        {
            DnsConfiguration = DnsConfiguration,
            GetRegistrableDomain = GetRegistrableDomain
        };
        await analysis.Analyze($"https://{domain}", logger ?? new InternalLogger(), cancellationToken).ConfigureAwait(false);
        return analysis;
    }

    private async Task<ThreatIntelAnalysis?> BuildThreatIntelAsync(string domain, TyposquattingEnrichmentOptions options, InternalLogger? logger, CancellationToken cancellationToken)
    {
        if (options.ThreatIntelOverride != null)
        {
            return await options.ThreatIntelOverride(domain, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new ThreatIntelAnalysis();
        await analysis.Analyze(
            domain,
            options.GoogleSafeBrowsingApiKey,
            options.PhishTankApiKey,
            options.VirusTotalApiKey,
            logger ?? new InternalLogger(),
            cancellationToken).ConfigureAwait(false);
        return analysis;
    }

    private async Task<IpEnrichmentAnalysis?> BuildIpEnrichmentAsync(string domain, TyposquattingEnrichmentOptions options, InternalLogger? logger, CancellationToken cancellationToken)
    {
        if (options.IpEnrichmentOverride != null)
        {
            return await options.IpEnrichmentOverride(domain, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new IpEnrichmentAnalysis
        {
            DnsConfiguration = DnsConfiguration
        };
        await analysis.AnalyzeAsync(domain, additionalIpAddresses: null, logger: logger, cancellationToken: cancellationToken).ConfigureAwait(false);
        return analysis;
    }
}
