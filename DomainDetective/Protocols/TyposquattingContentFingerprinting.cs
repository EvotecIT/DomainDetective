using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>
/// Reusable text fingerprint for comparing page bodies without requiring exact body matches.
/// </summary>
public sealed class TyposquattingPageContentFingerprint
{
    public ulong SimHash { get; init; }
    public int TokenCount { get; init; }
    public int FeatureCount { get; init; }
    public bool HasValue => TokenCount > 0 && FeatureCount > 0;
}

/// <summary>
/// Fuzzy similarity result between two normalized page-content fingerprints.
/// </summary>
public sealed class TyposquattingPageContentSimilarity
{
    public int SimilarityPercent { get; init; }
    public int HammingDistance { get; init; }
    public bool IsMeaningful => SimilarityPercent > 0;
}

/// <summary>
/// Builds and compares normalized page-content fingerprints.
/// </summary>
public static class TyposquattingContentFingerprinting
{
    private static readonly Regex ScriptRegex = new(@"<script\b[^>]*>.*?</script>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex StyleRegex = new(@"<style\b[^>]*>.*?</style>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex TagRegex = new(@"<[^>]+>", RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex TokenRegex = new(@"[\p{L}\p{N}]{2,}", RegexOptions.Compiled);

    public static TyposquattingPageContentFingerprint? Build(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        var normalizedText = NormalizeHtmlToText(body!);
        if (string.IsNullOrWhiteSpace(normalizedText))
        {
            return null;
        }

        var tokens = Tokenize(normalizedText);
        if (tokens.Count == 0)
        {
            return null;
        }

        var features = BuildFeatures(tokens);
        if (features.Count == 0)
        {
            return null;
        }

        return new TyposquattingPageContentFingerprint
        {
            SimHash = ComputeSimHash(features),
            TokenCount = tokens.Count,
            FeatureCount = features.Count
        };
    }

    public static TyposquattingPageContentSimilarity Compare(
        TyposquattingPageContentFingerprint? source,
        TyposquattingPageContentFingerprint? candidate)
    {
        if (source?.HasValue != true || candidate?.HasValue != true)
        {
            return new TyposquattingPageContentSimilarity();
        }

        var hammingDistance = GetHammingDistance(source.SimHash, candidate.SimHash);
        var similarityPercent = (int)Math.Round((64d - hammingDistance) / 64d * 100d, MidpointRounding.AwayFromZero);
        return new TyposquattingPageContentSimilarity
        {
            SimilarityPercent = Math.Max(0, Math.Min(100, similarityPercent)),
            HammingDistance = hammingDistance
        };
    }

    private static string NormalizeHtmlToText(string body)
    {
        var withoutScripts = ScriptRegex.Replace(body, " ");
        var withoutStyles = StyleRegex.Replace(withoutScripts, " ");
        var withoutTags = TagRegex.Replace(withoutStyles, " ");
        var decoded = System.Net.WebUtility.HtmlDecode(withoutTags);
        if (string.IsNullOrWhiteSpace(decoded))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(decoded.Length);
        foreach (var character in decoded)
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(char.ToLowerInvariant(character));
                continue;
            }

            builder.Append(' ');
        }

        return Regex.Replace(builder.ToString(), @"\s+", " ").Trim();
    }

    private static IReadOnlyList<string> Tokenize(string normalizedText)
    {
        var matches = TokenRegex.Matches(normalizedText);
        if (matches.Count == 0)
        {
            return Array.Empty<string>();
        }

        var tokens = new List<string>(matches.Count);
        foreach (Match match in matches)
        {
            if (!string.IsNullOrWhiteSpace(match.Value))
            {
                tokens.Add(match.Value);
            }
        }

        return tokens;
    }

    private static Dictionary<string, int> BuildFeatures(IReadOnlyList<string> tokens)
    {
        var features = new Dictionary<string, int>(StringComparer.Ordinal);
        if (tokens.Count == 0)
        {
            return features;
        }

        var shingleSize = tokens.Count >= 3 ? 3 : 1;
        var lastIndex = tokens.Count - shingleSize;
        for (var index = 0; index <= lastIndex; index++)
        {
            var feature = shingleSize == 1
                ? tokens[index]
                : string.Join(" ", GetShingle(tokens, index, shingleSize));
            if (features.TryGetValue(feature, out var count))
            {
                features[feature] = count + 1;
            }
            else
            {
                features[feature] = 1;
            }
        }

        return features;
    }

    private static IReadOnlyList<string> GetShingle(IReadOnlyList<string> tokens, int startIndex, int length)
    {
        var shingle = new string[length];
        for (var index = 0; index < length; index++)
        {
            shingle[index] = tokens[startIndex + index];
        }

        return shingle;
    }

    private static ulong ComputeSimHash(Dictionary<string, int> features)
    {
        var weights = new int[64];
        foreach (var feature in features)
        {
            var hash = ComputeFeatureHash(feature.Key);
            for (var bitIndex = 0; bitIndex < 64; bitIndex++)
            {
                var bitSet = ((hash >> bitIndex) & 1UL) == 1UL;
                weights[bitIndex] += bitSet ? feature.Value : -feature.Value;
            }
        }

        ulong simHash = 0;
        for (var bitIndex = 0; bitIndex < 64; bitIndex++)
        {
            if (weights[bitIndex] >= 0)
            {
                simHash |= 1UL << bitIndex;
            }
        }

        return simHash;
    }

    private static ulong ComputeFeatureHash(string value)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = sha256.ComputeHash(bytes);
        return BitConverter.ToUInt64(hash, 0);
    }

    private static int GetHammingDistance(ulong left, ulong right)
    {
        var value = left ^ right;
        var count = 0;
        while (value != 0)
        {
            count++;
            value &= value - 1;
        }

        return count;
    }
}
