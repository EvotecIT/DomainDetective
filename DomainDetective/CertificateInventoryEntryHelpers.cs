using System;
using System.Collections.Generic;
using System.Net;
using DomainDetective.Network;

namespace DomainDetective;

internal static class CertificateInventoryEntryHelpers
{
    public static void NormalizeRemoteAddressEvidence(CertificateInventoryEntry entry)
    {
        if (entry == null)
        {
            return;
        }

        if (IPAddress.TryParse((entry.RemoteAddress ?? string.Empty).Trim(), out IPAddress? address) && address != null)
        {
            IPAddress normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
            entry.RemoteAddress = normalized.ToString();
            entry.RemoteAddressFamily = IpAddressClassifier.GetAddressFamilyLabel(normalized);
            return;
        }

        if (!string.IsNullOrWhiteSpace(entry.RemoteAddressFamily))
        {
            entry.RemoteAddressFamily = IpAddressClassifier.GetAddressFamilyLabel(null, entry.RemoteAddressFamily);
        }
    }

    public static DateTimeOffset ResolveCapturedAtUtc(
        IEnumerable<CertificateInventoryEntry>? entries,
        DateTimeOffset candidate)
    {
        DateTimeOffset resolved = candidate == default ? DateTimeOffset.UtcNow : candidate;
        if (entries == null)
        {
            return resolved;
        }

        foreach (CertificateInventoryEntry entry in entries)
        {
            if (entry == null)
            {
                continue;
            }
            resolved = Max(resolved, entry.ObservedAtUtc);
            resolved = Max(resolved, entry.DnsObservedAtUtc);
            resolved = Max(resolved, entry.Attribution?.EvaluatedAtUtc);
        }
        return resolved;
    }

    private static DateTimeOffset Max(DateTimeOffset current, DateTimeOffset? candidate) =>
        candidate.HasValue && candidate.Value > current ? candidate.Value : current;

    public static string ResolveAuthenticationProfile(CertificateInventoryEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(entry.AuthenticationProfile))
        {
            return entry.AuthenticationProfile!;
        }

        return CertificateAuthenticationProfileClassifier.Classify(
            entry.HasEnhancedKeyUsageExtension,
            entry.HasAnyExtendedKeyUsageOid,
            entry.AllowsServerAuthentication,
            entry.AllowsClientAuthentication,
            entry.AllowsSecureEmail,
            entry.ExtendedKeyUsageOids);
    }

    public static IEnumerable<string> EnumerateChainSources(CertificateInventoryEntry entry)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(entry.CertificateChainSource))
        {
            var primary = entry.CertificateChainSource!.Trim();
            if (seen.Add(primary))
            {
                yield return primary;
            }
        }

        if (entry.CertificateChainSources == null)
        {
            yield break;
        }

        foreach (var source in entry.CertificateChainSources)
        {
            if (string.IsNullOrWhiteSpace(source))
            {
                continue;
            }

            var normalized = source.Trim();
            if (seen.Add(normalized))
            {
                yield return normalized;
            }
        }
    }

    public static string PickChainSource(CertificateInventoryEntry entry)
    {
        foreach (var source in EnumerateChainSources(entry))
        {
            return source;
        }

        return "unknown";
    }

    public static IEnumerable<string> EnumerateCtTemplateFormatErrors(CertificateInventoryEntry entry)
    {
        if (entry.CtTemplateFormatErrors == null)
        {
            yield break;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var error in entry.CtTemplateFormatErrors)
        {
            if (string.IsNullOrWhiteSpace(error))
            {
                continue;
            }

            var normalized = error.Trim();
            if (seen.Add(normalized))
            {
                yield return normalized;
            }
        }
    }
}
