using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Options for comparing candidate web content with the source domain.
/// </summary>
public sealed class TyposquattingContentSimilarityOptions
{
    /// <summary>When true, content similarity comparison is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>When true, optional static web scans are collected for richer title and technology comparison.</summary>
    public bool IncludeWebStaticScan { get; set; }

    /// <summary>Optional override for building the source-domain HTTP profile.</summary>
    public Func<string, CancellationToken, Task<HttpAnalysis?>>? HttpOverride { get; set; }

    /// <summary>Optional override for building the source-domain static web profile.</summary>
    public Func<string, CancellationToken, Task<WebStaticScanAnalysis?>>? WebStaticScanOverride { get; set; }

    /// <summary>Custom request options used when HTTP profiling is performed.</summary>
    public HttpRequestOptions HttpRequestOptions { get; } = new();
}

/// <summary>
/// Reusable source-domain web fingerprint for content comparison.
/// </summary>
public sealed class TyposquattingSourceContentProfile
{
    public string Domain { get; init; } = string.Empty;
    public string BodySha256 { get; init; } = string.Empty;
    public int? BodyLength { get; init; }
    public string PageTitle { get; init; } = string.Empty;
    public string FinalHost { get; init; } = string.Empty;
    public IReadOnlyList<string> TechDetections { get; init; } = Array.Empty<string>();
    public bool HasAnySignals =>
        !string.IsNullOrWhiteSpace(BodySha256)
        || BodyLength.HasValue
        || !string.IsNullOrWhiteSpace(PageTitle)
        || !string.IsNullOrWhiteSpace(FinalHost)
        || TechDetections.Count > 0;
}

/// <summary>
/// Content similarity result for a single candidate.
/// </summary>
public sealed class TyposquattingContentSimilarityMatch
{
    public int Score { get; init; }
    public bool LikelyImpersonating { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Signals { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Compares candidate web content against the source domain using existing DD analyses.
/// </summary>
public static class TyposquattingContentSimilarityAnalyzer
{
    public static async Task<TyposquattingSourceContentProfile?> BuildProfileAsync(
        string domain,
        DnsConfiguration dnsConfiguration,
        Func<string, string>? getRegistrableDomain,
        TyposquattingContentSimilarityOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain) || options == null || !options.Enabled)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var url = "https://" + domain.Trim();
        var http = await BuildHttpAsync(url, options, cancellationToken).ConfigureAwait(false);

        WebStaticScanAnalysis? webStaticScan = null;
        if (options.IncludeWebStaticScan)
        {
            webStaticScan = await BuildWebStaticScanAsync(url, dnsConfiguration, getRegistrableDomain, options, cancellationToken).ConfigureAwait(false);
        }

        return new TyposquattingSourceContentProfile
        {
            Domain = domain,
            BodySha256 = http?.BodySha256 ?? string.Empty,
            BodyLength = http?.BodyLength,
            PageTitle = FirstNonEmpty(webStaticScan?.PageTitle, ExtractPageTitle(http?.Body)),
            FinalHost = GetFinalHost(http),
            TechDetections = NormalizeList(webStaticScan?.TechDetections)
        };
    }

    public static void CompareCandidates(IReadOnlyList<TyposquattingCandidate>? candidates, TyposquattingSourceContentProfile? profile)
    {
        if (candidates == null || candidates.Count == 0 || profile == null || !profile.HasAnySignals)
        {
            return;
        }

        foreach (var candidate in candidates)
        {
            candidate.ContentSimilarity = CompareCandidate(candidate, profile);
        }
    }

    public static TyposquattingContentSimilarityMatch CompareCandidate(TyposquattingCandidate candidate, TyposquattingSourceContentProfile profile)
    {
        if (candidate == null)
        {
            throw new ArgumentNullException(nameof(candidate));
        }

        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        var signals = new List<string>();
        var score = 0;
        var http = candidate.Enrichment?.Http;
        var web = candidate.Enrichment?.WebStaticScan;
        var candidateBodySha256 = http?.BodySha256;

        if (!string.IsNullOrWhiteSpace(profile.BodySha256)
            && !string.IsNullOrWhiteSpace(candidateBodySha256)
            && string.Equals(candidateBodySha256, profile.BodySha256, StringComparison.OrdinalIgnoreCase))
        {
            score += 60;
            signals.Add("matches source page body hash");
        }

        if (profile.BodyLength.HasValue
            && http?.BodyLength is int candidateBodyLength
            && profile.BodyLength.Value > 0)
        {
            var delta = Math.Abs(candidateBodyLength - profile.BodyLength.Value);
            var ratio = (double)delta / profile.BodyLength.Value;
            if (ratio <= 0.10d)
            {
                score += 10;
                signals.Add("body length closely matches source");
            }
        }

        var candidateTitle = FirstNonEmpty(web?.PageTitle, ExtractPageTitle(http?.Body));
        var titleSignal = CompareTitles(profile.PageTitle, candidateTitle);
        if (titleSignal.Score > 0)
        {
            score += titleSignal.Score;
            signals.Add(titleSignal.Signal);
        }

        var sourceFinalHost = NormalizeHost(profile.FinalHost);
        var candidateFinalHost = NormalizeHost(GetFinalHost(http));
        if (!string.IsNullOrWhiteSpace(sourceFinalHost)
            && !string.IsNullOrWhiteSpace(candidateFinalHost)
            && string.Equals(sourceFinalHost, candidateFinalHost, StringComparison.OrdinalIgnoreCase))
        {
            score += 8;
            signals.Add("lands on the same final host as the source");
        }

        var sourceTech = profile.TechDetections;
        var candidateTech = NormalizeList(web?.TechDetections);
        if (sourceTech.Count > 0 && candidateTech.Count > 0)
        {
            var overlap = candidateTech
                .Intersect(sourceTech, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (overlap.Length >= 3)
            {
                score += 12;
                signals.Add("shares several detected web technologies");
            }
            else if (overlap.Length > 0)
            {
                score += 5;
                signals.Add("shares detected web technologies");
            }
        }

        score = Math.Max(0, Math.Min(100, score));
        return new TyposquattingContentSimilarityMatch
        {
            Score = score,
            LikelyImpersonating = score >= 35,
            Signals = signals.ToArray(),
            Summary = signals.Count > 0 ? string.Join(", ", signals) : "no meaningful content similarity detected"
        };
    }

    private static async Task<HttpAnalysis?> BuildHttpAsync(string url, TyposquattingContentSimilarityOptions options, CancellationToken cancellationToken)
    {
        if (options.HttpOverride != null)
        {
            return await options.HttpOverride(url, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new HttpAnalysis
        {
            Subject = url
        };
        await analysis.AnalyzeUrl(
            url,
            checkHsts: false,
            logger: new InternalLogger(),
            collectHeaders: false,
            captureBody: true,
            cancellationToken: cancellationToken,
            requestOptions: options.HttpRequestOptions).ConfigureAwait(false);
        return analysis;
    }

    private static async Task<WebStaticScanAnalysis?> BuildWebStaticScanAsync(
        string url,
        DnsConfiguration dnsConfiguration,
        Func<string, string>? getRegistrableDomain,
        TyposquattingContentSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        if (options.WebStaticScanOverride != null)
        {
            return await options.WebStaticScanOverride(url, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new WebStaticScanAnalysis
        {
            DnsConfiguration = dnsConfiguration,
            GetRegistrableDomain = getRegistrableDomain
        };
        await analysis.Analyze(url, new InternalLogger(), cancellationToken).ConfigureAwait(false);
        return analysis;
    }

    private static (int Score, string Signal) CompareTitles(string sourceTitle, string candidateTitle)
    {
        var normalizedSource = NormalizeTitle(sourceTitle);
        var normalizedCandidate = NormalizeTitle(candidateTitle);
        if (string.IsNullOrWhiteSpace(normalizedSource) || string.IsNullOrWhiteSpace(normalizedCandidate))
        {
            return (0, string.Empty);
        }

        if (string.Equals(normalizedSource, normalizedCandidate, StringComparison.OrdinalIgnoreCase))
        {
            return (22, "matches source page title");
        }

        if (normalizedSource.Contains(normalizedCandidate, StringComparison.OrdinalIgnoreCase)
            || normalizedCandidate.Contains(normalizedSource, StringComparison.OrdinalIgnoreCase))
        {
            return (12, "title closely resembles the source");
        }

        var distance = StringAlgorithms.LevenshteinDistance(normalizedSource, normalizedCandidate);
        var threshold = Math.Max(3, Math.Min(normalizedSource.Length, normalizedCandidate.Length) / 5);
        if (distance <= threshold)
        {
            return (12, "title closely resembles the source");
        }

        return (0, string.Empty);
    }

    private static string ExtractPageTitle(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return string.Empty;
        }

        var match = Regex.Match(body, "<title>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (!match.Success)
        {
            return string.Empty;
        }

        return System.Net.WebUtility.HtmlDecode((match.Groups[1].Value ?? string.Empty).Trim());
    }

    private static string NormalizeTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return string.Empty;
        }

        var trimmedTitle = title!.Trim();
        var normalized = Regex.Replace(trimmedTitle.ToLowerInvariant(), @"\s+", " ");
        normalized = Regex.Replace(normalized, @"[^\p{L}\p{N}\s]", string.Empty);
        return normalized.Trim();
    }

    private static string GetFinalHost(HttpAnalysis? http)
    {
        if (http?.VisitedUrls == null || http.VisitedUrls.Count == 0)
        {
            return string.Empty;
        }

        return NormalizeHost(http.VisitedUrls[http.VisitedUrls.Count - 1]);
    }

    private static string NormalizeHost(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return uri.Host.Trim().TrimEnd('.').ToLowerInvariant();
        }

        var trimmedValue = value!.Trim();
        return trimmedValue.TrimEnd('.').ToLowerInvariant();
    }

    private static IReadOnlyList<string> NormalizeList(IEnumerable<string>? values)
    {
        if (values == null)
        {
            return Array.Empty<string>();
        }

        return values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                var trimmedValue = value!.Trim();
                return trimmedValue;
            }
        }

        return string.Empty;
    }
}
