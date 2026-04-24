using System;
using System.IO;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// DNS-name normalization and matching helpers shared by certificate transparency providers.
/// </summary>
public static class CertificateTransparencyNameUtility
{
    private static readonly Lazy<PublicSuffixList> EmbeddedPublicSuffixList = new(LoadPublicSuffixList);

    /// <summary>
    /// Normalizes a DNS name for certificate transparency matching.
    /// </summary>
    /// <param name="name">The input DNS name.</param>
    /// <returns>A lower-case DNS name without a trailing root dot, or an empty string.</returns>
    public static string Normalize(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        return (name ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
    }

    /// <summary>
    /// Determines whether a DNS name starts with a wildcard label.
    /// </summary>
    /// <param name="name">The DNS name to inspect.</param>
    /// <returns><see langword="true"/> when the normalized name starts with <c>*.</c>.</returns>
    public static bool IsWildcard(string? name)
    {
        string normalized = Normalize(name);
        return normalized.StartsWith("*.", StringComparison.Ordinal);
    }

    /// <summary>
    /// Removes one or more leading wildcard labels from a DNS name.
    /// </summary>
    /// <param name="name">The DNS name to normalize.</param>
    /// <returns>The normalized DNS name without leading wildcard labels.</returns>
    public static string StripWildcard(string? name)
    {
        string normalized = Normalize(name);
        while (normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            normalized = normalized.Substring(2);
        }

        return normalized;
    }

    /// <summary>
    /// Normalizes a search name while preserving an explicit leading wildcard label.
    /// </summary>
    /// <param name="name">The DNS name to normalize for an exact storage predicate.</param>
    /// <returns>The normalized exact search name.</returns>
    public static string BuildExactSearchName(string? name)
    {
        string normalized = Normalize(name);
        return IsWildcard(normalized) ? normalized : StripWildcard(normalized);
    }

    /// <summary>
    /// Builds the wildcard DNS name that can cover exactly one left-most label of a host.
    /// </summary>
    /// <param name="name">The DNS host name to inspect.</param>
    /// <returns>The immediate wildcard name, or <see langword="null"/> when the input is not a multi-label host.</returns>
    public static string? BuildImmediateWildcardName(string? name)
    {
        string normalized = StripWildcard(name);
        string[] labels = normalized.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 3)
        {
            return null;
        }

        return "*." + string.Join(".", labels.Skip(1));
    }

    /// <summary>
    /// Builds an implicit wildcard candidate for a host lookup, but not for literal wildcard searches.
    /// </summary>
    /// <param name="name">The DNS name to inspect.</param>
    /// <returns>The immediate wildcard name, or <see langword="null"/> when no implicit candidate applies.</returns>
    public static string? BuildImplicitWildcardCandidateName(string? name)
        => IsWildcard(name) ? null : BuildImmediateWildcardName(name);

    /// <summary>
    /// Reverses DNS labels so suffix queries can use prefix-like indexes.
    /// </summary>
    /// <param name="name">The DNS name to normalize and reverse.</param>
    /// <returns>The reversed-label DNS name.</returns>
    public static string ReverseLabels(string? name)
    {
        string normalized = StripWildcard(name);
        if (normalized.Length == 0)
        {
            return string.Empty;
        }

        string[] labels = normalized.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
        Array.Reverse(labels);
        return string.Join(".", labels);
    }

    /// <summary>
    /// Builds the reversed-label exact match used by suffix-aware storage queries.
    /// </summary>
    /// <param name="name">The DNS name to normalize and reverse.</param>
    /// <returns>The reversed-label exact match value.</returns>
    public static string BuildReversedExactMatch(string? name)
        => ReverseLabels(name);

    /// <summary>
    /// Builds the reversed-label prefix match used by suffix-aware storage queries.
    /// </summary>
    /// <param name="name">The DNS name to normalize and reverse.</param>
    /// <returns>The escaped reversed-label prefix match value.</returns>
    public static string BuildReversedPrefixMatch(string? name)
    {
        string reversed = ReverseLabels(name);
        return reversed.Length == 0 ? string.Empty : EscapeLikePattern(reversed) + ".%";
    }

    /// <summary>
    /// Determines whether a certificate DNS name covers a host using exact and single-label wildcard semantics.
    /// </summary>
    /// <param name="hostName">The concrete host being queried.</param>
    /// <param name="certificateName">The certificate DNS name.</param>
    /// <returns><see langword="true"/> when the certificate name covers the host.</returns>
    public static bool CertificateNameMatchesHost(string? hostName, string? certificateName)
    {
        string normalizedHost = Normalize(hostName);
        if (normalizedHost.Length == 0 || string.IsNullOrWhiteSpace(certificateName))
        {
            return false;
        }

        string normalizedCandidate = Normalize(certificateName);
        if (string.Equals(normalizedCandidate, normalizedHost, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!normalizedCandidate.StartsWith("*.", StringComparison.Ordinal))
        {
            return false;
        }

        string suffix = normalizedCandidate.Substring(2);
        if (string.IsNullOrWhiteSpace(suffix) ||
            normalizedHost.Length <= suffix.Length + 1 ||
            !normalizedHost.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string wildcardLabel = normalizedHost.Substring(0, normalizedHost.Length - suffix.Length - 1);
        return wildcardLabel.Length > 0 && wildcardLabel.IndexOf('.') < 0;
    }

    /// <summary>
    /// Resolves a host to its registrable domain when the embedded public suffix list is available.
    /// </summary>
    /// <param name="candidate">The host name to inspect.</param>
    /// <returns>The registrable domain, or a conservative last-two-label fallback.</returns>
    public static string GetRegistrableDomainOrSelf(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return candidate;
        }

        try
        {
            return EmbeddedPublicSuffixList.Value.GetRegistrableDomain(candidate);
        }
        catch
        {
            string[] labels = candidate.Split('.');
            if (labels.Length <= 2)
            {
                return candidate;
            }

            return string.Join(".", labels.Skip(labels.Length - 2));
        }
    }

    private static string EscapeLikePattern(string value)
    {
        if (value.Length == 0)
        {
            return value;
        }

        return value
            .Replace(@"\", @"\\")
            .Replace("%", @"\%")
            .Replace("_", @"\_")
            .Replace("[", @"\[");
    }

    private static PublicSuffixList LoadPublicSuffixList()
    {
        try
        {
            using Stream? stream = typeof(CertificateTransparencyNameUtility).Assembly
                .GetManifestResourceStream("DomainDetective.public_suffix_list.dat");
            if (stream != null)
            {
                return PublicSuffixList.Load(stream);
            }
        }
        catch
        {
            // Best-effort only; fallback callers still preserve host-level behavior.
        }

        return new PublicSuffixList();
    }
}
