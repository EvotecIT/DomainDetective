using System;
using System.Collections.Generic;

namespace DomainDetective;

internal static class CertificateInventoryEntryHelpers
{
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
        if (!string.IsNullOrWhiteSpace(entry.CertificateChainSource))
        {
            yield return entry.CertificateChainSource!;
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

            yield return source;
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
}
