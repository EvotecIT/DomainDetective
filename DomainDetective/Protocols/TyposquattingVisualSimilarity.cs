using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
#if NET8_0_OR_GREATER
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
#endif

namespace DomainDetective;

/// <summary>
/// Options for source-vs-candidate visual comparison in typosquatting analysis.
/// </summary>
public sealed class TyposquattingVisualSimilarityOptions
{
    /// <summary>When true, visual similarity is enabled.</summary>
    public bool Enabled { get; set; }

    /// <summary>When true, favicon and social-image discovery can be used as the default visual capture path.</summary>
    public bool EnableStaticAssetCapture { get; set; } = true;

    /// <summary>Maximum number of candidates visually fingerprinted per analysis run.</summary>
    public int MaxCandidates { get; set; } = 5;

    /// <summary>Maximum number of visual captures performed in parallel.</summary>
    public int MaxParallelism { get; set; } = 2;

    /// <summary>When true, only candidates with a DNS footprint are considered.</summary>
    public bool RegisteredOnly { get; set; } = true;

    /// <summary>Maximum Hamming distance still considered a likely visual clone.</summary>
    public int CloneDistanceThreshold { get; set; } = 10;

    /// <summary>Maximum Hamming distance still considered visually similar.</summary>
    public int SimilarDistanceThreshold { get; set; } = 18;

    /// <summary>Maximum number of bytes downloaded for a single visual asset.</summary>
    public int MaxAssetBytes { get; set; } = 1024 * 1024;

    /// <summary>Maximum number of visual assets collected per page before comparison.</summary>
    public int MaxAssetsPerPage { get; set; } = 3;

    /// <summary>Optional capture override returning one or more screenshots or precomputed fingerprints for a URL.</summary>
    public Func<string, CancellationToken, Task<IReadOnlyList<TyposquattingVisualArtifact>>>? CaptureManyOverride { get; set; }

    /// <summary>Optional capture override returning a screenshot or precomputed fingerprint for a URL.</summary>
    public Func<string, CancellationToken, Task<TyposquattingVisualArtifact?>>? CaptureOverride { get; set; }

    /// <summary>Optional override for fetching page HTML before static visual asset discovery.</summary>
    public Func<string, CancellationToken, Task<HttpAnalysis?>>? PageHttpOverride { get; set; }

    /// <summary>Optional override for downloading the selected visual asset.</summary>
    public Func<string, CancellationToken, Task<TyposquattingVisualArtifact?>>? AssetDownloadOverride { get; set; }

    /// <summary>Custom request options used when default page and asset fetching is performed.</summary>
    public HttpRequestOptions HttpRequestOptions { get; } = new();
}

/// <summary>
/// Captured visual artifact or precomputed fingerprint used for similarity comparison.
/// </summary>
public enum TyposquattingVisualArtifactKind
{
    Unknown = 0,
    Favicon = 1,
    AppleTouchIcon = 2,
    OpenGraphImage = 3,
    TwitterImage = 4,
    Screenshot = 5
}

/// <summary>
/// Captured visual artifact or precomputed fingerprint used for similarity comparison.
/// </summary>
public sealed class TyposquattingVisualArtifact
{
    public byte[]? ImageBytes { get; init; }
    public string? MimeType { get; init; }
    public string FingerprintHex { get; init; } = string.Empty;
    public int? Width { get; init; }
    public int? Height { get; init; }
    public TyposquattingVisualArtifactKind Kind { get; init; }
    public string SourceUrl { get; init; } = string.Empty;
}

/// <summary>
/// Normalized source-domain visual signal used for multi-artifact comparison.
/// </summary>
public sealed class TyposquattingSourceVisualSignal
{
    public string FingerprintHex { get; init; } = string.Empty;
    public int? Width { get; init; }
    public int? Height { get; init; }
    public TyposquattingVisualArtifactKind Kind { get; init; }
    public string SourceUrl { get; init; } = string.Empty;
}

/// <summary>
/// Source-domain visual fingerprint profile.
/// </summary>
public sealed class TyposquattingSourceVisualProfile
{
    public string Domain { get; init; } = string.Empty;
    public string FingerprintHex { get; init; } = string.Empty;
    public int? Width { get; init; }
    public int? Height { get; init; }
    public IReadOnlyList<TyposquattingSourceVisualSignal> Signals { get; init; } = Array.Empty<TyposquattingSourceVisualSignal>();
    public bool HasAnySignals => Signals.Count > 0 || !string.IsNullOrWhiteSpace(FingerprintHex);
}

/// <summary>
/// Visual similarity result for a single candidate.
/// </summary>
public sealed class TyposquattingVisualSimilarityMatch
{
    public int Score { get; init; }
    public int HammingDistance { get; init; }
    public bool LikelyClone { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Signals { get; init; } = Array.Empty<string>();
    public TyposquattingVisualArtifactKind MatchedArtifactKind { get; init; }
    public string MatchedSourceUrl { get; init; } = string.Empty;
    public string CandidateArtifactUrl { get; init; } = string.Empty;
}

/// <summary>
/// Reusable visual fingerprinting and comparison for typosquatting candidates.
/// </summary>
public static partial class TyposquattingVisualSimilarityAnalyzer
{
    public static async Task<TyposquattingSourceVisualProfile?> BuildProfileAsync(
        string domain,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain) || options == null || !options.Enabled)
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var artifacts = await CaptureVisualArtifactsAsync(BuildUrl(domain), null, options, cancellationToken).ConfigureAwait(false);
        var signals = BuildSignals(artifacts);
        if (signals.Count == 0)
        {
            return null;
        }

        var primary = signals[0];

        return new TyposquattingSourceVisualProfile
        {
            Domain = domain,
            FingerprintHex = primary.FingerprintHex,
            Width = primary.Width,
            Height = primary.Height,
            Signals = signals
        };
    }

    public static async Task CompareCandidatesAsync(
        IReadOnlyList<TyposquattingCandidate>? candidates,
        TyposquattingSourceVisualProfile? profile,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken = default)
    {
        if (candidates == null
            || candidates.Count == 0
            || profile == null
            || !profile.HasAnySignals
            || options == null
            || !options.Enabled
            || (options.CaptureManyOverride == null && options.CaptureOverride == null && !options.EnableStaticAssetCapture))
        {
            return;
        }

        var selected = candidates
            .Where(candidate => candidate != null)
            .Where(candidate => !options.RegisteredOnly || candidate.AppearsRegistered)
            .Where(candidate => candidate.Enrichment?.Http?.IsReachable == true || candidate.Resolves)
            .OrderByDescending(candidate => candidate.Enrichment?.Http?.IsReachable == true)
            .ThenByDescending(candidate => candidate.Resolves)
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
                var artifacts = await CaptureVisualArtifactsAsync(GetCandidateUrl(candidate), candidate, options, cancellationToken).ConfigureAwait(false);
                var match = CompareArtifacts(artifacts, profile, options);
                if (match != null)
                {
                    candidate.VisualSimilarity = match;
                }
            }
            finally
            {
                gate.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    public static TyposquattingVisualSimilarityMatch CompareFingerprint(
        string candidateFingerprintHex,
        TyposquattingSourceVisualProfile profile,
        TyposquattingVisualSimilarityOptions options)
    {
        if (string.IsNullOrWhiteSpace(candidateFingerprintHex))
        {
            throw new ArgumentNullException(nameof(candidateFingerprintHex));
        }

        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        var distance = ComputeHammingDistance(profile.FingerprintHex, candidateFingerprintHex);
        var score = Math.Max(0, 100 - (distance * 100 / 64));
        var signals = new List<string>();

        if (distance <= options.CloneDistanceThreshold)
        {
            signals.Add("visual fingerprint closely matches the source");
        }
        else if (distance <= options.SimilarDistanceThreshold)
        {
            signals.Add("visual fingerprint partially matches the source");
        }
        else
        {
            signals.Add("visual fingerprint differs from the source");
        }

        return new TyposquattingVisualSimilarityMatch
        {
            Score = score,
            HammingDistance = distance,
            LikelyClone = distance <= options.CloneDistanceThreshold,
            Signals = signals.ToArray(),
            Summary = $"{signals[0]} (distance {distance})",
            MatchedArtifactKind = TyposquattingVisualArtifactKind.Unknown
        };
    }

    private static TyposquattingVisualSimilarityMatch? CompareArtifacts(
        IReadOnlyList<TyposquattingVisualArtifact> artifacts,
        TyposquattingSourceVisualProfile profile,
        TyposquattingVisualSimilarityOptions options)
    {
        if (artifacts == null || artifacts.Count == 0 || profile == null || !profile.HasAnySignals)
        {
            return null;
        }

        TyposquattingVisualSimilarityMatch? bestMatch = null;
        foreach (var artifact in artifacts)
        {
            var fingerprint = BuildFingerprint(artifact);
            if (fingerprint == null)
            {
                continue;
            }

            foreach (var sourceSignal in profile.Signals)
            {
                var match = BuildArtifactMatch(sourceSignal, artifact, fingerprint.Value.FingerprintHex, options);

                if (bestMatch == null
                    || match.Score > bestMatch.Score
                    || (match.Score == bestMatch.Score && match.HammingDistance < bestMatch.HammingDistance))
                {
                    bestMatch = match;
                }
            }
        }

        return bestMatch;
    }

    private static TyposquattingVisualSimilarityMatch BuildArtifactMatch(
        TyposquattingSourceVisualSignal sourceSignal,
        TyposquattingVisualArtifact candidateArtifact,
        string candidateFingerprintHex,
        TyposquattingVisualSimilarityOptions options)
    {
        var distance = ComputeHammingDistance(sourceSignal.FingerprintHex, candidateFingerprintHex);
        var score = Math.Max(0, 100 - (distance * 100 / 64));
        var signals = BuildArtifactSignals(sourceSignal, distance, options);

        return new TyposquattingVisualSimilarityMatch
        {
            Score = score,
            HammingDistance = distance,
            LikelyClone = distance <= options.CloneDistanceThreshold,
            Signals = signals,
            Summary = BuildArtifactSummary(sourceSignal, distance, options),
            MatchedArtifactKind = sourceSignal.Kind,
            MatchedSourceUrl = sourceSignal.SourceUrl,
            CandidateArtifactUrl = candidateArtifact.SourceUrl
        };
    }

    private static IReadOnlyList<string> BuildArtifactSignals(
        TyposquattingSourceVisualSignal sourceSignal,
        int distance,
        TyposquattingVisualSimilarityOptions options)
    {
        var label = GetArtifactDisplayName(sourceSignal.Kind);
        if (distance <= options.CloneDistanceThreshold)
        {
            return new[] { $"visual fingerprint closely matches the source {label}" };
        }

        if (distance <= options.SimilarDistanceThreshold)
        {
            return new[] { $"visual fingerprint partially matches the source {label}" };
        }

        return new[] { $"visual fingerprint differs from the source {label}" };
    }

    private static string BuildArtifactSummary(
        TyposquattingSourceVisualSignal sourceSignal,
        int distance,
        TyposquattingVisualSimilarityOptions options)
    {
        var signals = BuildArtifactSignals(sourceSignal, distance, options);
        return $"{signals[0]} (distance {distance})";
    }

    private static string GetArtifactDisplayName(TyposquattingVisualArtifactKind kind)
    {
        return kind switch
        {
            TyposquattingVisualArtifactKind.Favicon => "favicon",
            TyposquattingVisualArtifactKind.AppleTouchIcon => "apple-touch-icon",
            TyposquattingVisualArtifactKind.OpenGraphImage => "og:image",
            TyposquattingVisualArtifactKind.TwitterImage => "twitter:image",
            TyposquattingVisualArtifactKind.Screenshot => "rendered screenshot",
            _ => "visual asset"
        };
    }

    private static IReadOnlyList<TyposquattingSourceVisualSignal> BuildSignals(IReadOnlyList<TyposquattingVisualArtifact> artifacts)
    {
        if (artifacts == null || artifacts.Count == 0)
        {
            return Array.Empty<TyposquattingSourceVisualSignal>();
        }

        return artifacts
            .Select(BuildFingerprintSignal)
            .Where(static signal => signal != null)
            .Cast<TyposquattingSourceVisualSignal>()
            .ToArray();
    }

    private static TyposquattingSourceVisualSignal? BuildFingerprintSignal(TyposquattingVisualArtifact artifact)
    {
        var fingerprint = BuildFingerprint(artifact);
        if (fingerprint == null)
        {
            return null;
        }

        return new TyposquattingSourceVisualSignal
        {
            FingerprintHex = fingerprint.Value.FingerprintHex,
            Width = fingerprint.Value.Width,
            Height = fingerprint.Value.Height,
            Kind = artifact.Kind,
            SourceUrl = artifact.SourceUrl
        };
    }

    private static (string FingerprintHex, int? Width, int? Height)? BuildFingerprint(TyposquattingVisualArtifact? artifact)
    {
        if (artifact == null)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(artifact.FingerprintHex))
        {
            var trimmedFingerprint = artifact.FingerprintHex.Trim();
            return (trimmedFingerprint, artifact.Width, artifact.Height);
        }

        if (artifact.ImageBytes == null || artifact.ImageBytes.Length == 0)
        {
            return null;
        }

#if NET8_0_OR_GREATER
        try
        {
            using var image = Image.Load<Rgba32>(artifact.ImageBytes);
            image.Mutate(ctx => ctx.Resize(new ResizeOptions
            {
                Size = new Size(9, 8),
                Mode = ResizeMode.Stretch,
                Sampler = KnownResamplers.Bicubic
            }).Grayscale());

            ulong hash = 0;
            var bit = 0;
            for (var y = 0; y < 8; y++)
            {
                for (var x = 0; x < 8; x++)
                {
                    var left = image[x, y].R;
                    var right = image[x + 1, y].R;
                    if (left > right)
                    {
                        hash |= 1UL << bit;
                    }

                    bit++;
                }
            }

            return (hash.ToString("x16"), image.Width, image.Height);
        }
        catch
        {
            return null;
        }
#else
        return null;
#endif
    }

    private static int ComputeHammingDistance(string left, string right)
    {
        if (!ulong.TryParse(left, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var leftValue))
        {
            throw new ArgumentException("Value must be a hexadecimal 64-bit fingerprint.", nameof(left));
        }

        if (!ulong.TryParse(right, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var rightValue))
        {
            throw new ArgumentException("Value must be a hexadecimal 64-bit fingerprint.", nameof(right));
        }

        var xor = leftValue ^ rightValue;
        var distance = 0;
        while (xor != 0)
        {
            distance += (int)(xor & 1UL);
            xor >>= 1;
        }

        return distance;
    }

    private static string BuildUrl(string domain)
    {
        return "https://" + domain.Trim();
    }

    private static string GetCandidateUrl(TyposquattingCandidate candidate)
    {
        var finalUrl = candidate.Enrichment?.Http?.VisitedUrls?.LastOrDefault();
        if (!string.IsNullOrWhiteSpace(finalUrl))
        {
            return finalUrl!;
        }

        return BuildUrl(candidate.Domain);
    }
}
