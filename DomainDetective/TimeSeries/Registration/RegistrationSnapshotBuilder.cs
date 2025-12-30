using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.TimeSeries.Registration;

public static class RegistrationSnapshotBuilder
{
    public static RegistrationSnapshot Build(string domain, RdapAnalysis? rdap, WhoisAnalysis? whois, DateTimeOffset? capturedAtUtc = null)
    {
        var subject = (domain ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(subject))
        {
            subject = (rdap?.DomainName ?? whois?.DomainName ?? string.Empty).Trim();
        }

        var snapshot = new RegistrationSnapshot
        {
            Domain = subject,
            CapturedAtUtc = capturedAtUtc ?? DateTimeOffset.UtcNow,
            HasRdap = rdap?.DomainData != null,
            HasWhois = !string.IsNullOrWhiteSpace(whois?.WhoisData),
            WhoisServerUsed = whois?.WhoisServerUsed,
            WhoisLookupSource = whois?.WhoisLookupSource,
            Registrar = FirstNonEmpty(rdap?.Registrar, whois?.Registrar),
            RegistrarId = FirstNonEmpty(rdap?.RegistrarId, whois?.RegistrarId),
            PrivacyProtected = whois != null ? whois.PrivacyProtected : null,
            RegistrarLocked = whois != null ? whois.RegistrarLocked : null
        };

        snapshot.CreatedAtRaw = FirstNonEmpty(rdap?.CreationDate, whois?.CreationDate);
        snapshot.CreatedAtUtc = TryParseUtc(snapshot.CreatedAtRaw);

        snapshot.UpdatedAtRaw = whois?.LastUpdated;
        snapshot.UpdatedAtUtc = TryParseUtc(snapshot.UpdatedAtRaw);

        snapshot.ExpiresAtRaw = FirstNonEmpty(rdap?.ExpiryDate, whois?.ExpiryDate);
        snapshot.ExpiresAtUtc = TryParseUtc(snapshot.ExpiresAtRaw);

        snapshot.NameServers = MergeStringLists(rdap?.NameServers, whois?.NameServers, NormalizeNameServer)
            .ToList();

        snapshot.Status = (rdap?.Status ?? new List<RdapDomainStatus>())
            .Where(s => s != RdapDomainStatus.Unknown)
            .Select(s => s.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return snapshot;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values ?? Array.Empty<string?>())
        {
            if (!string.IsNullOrWhiteSpace(v))
            {
                return v!.Trim();
            }
        }
        return null;
    }

    private static DateTimeOffset? TryParseUtc(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        // Prefer invariant parsing for common RFC3339/ISO8601 strings.
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
        {
            return dto;
        }

        // Fall back to current culture (some WHOIS formats are locale-ish).
        if (DateTimeOffset.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out dto))
        {
            return dto;
        }

        return null;
    }

    private static IEnumerable<string> MergeStringLists(IEnumerable<string>? a, IEnumerable<string>? b, Func<string, string?> normalize)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddAll(IEnumerable<string>? list)
        {
            foreach (var x in list ?? Array.Empty<string>())
            {
                var n = normalize(x);
                if (string.IsNullOrWhiteSpace(n))
                {
                    continue;
                }
                set.Add(n!);
            }
        }

        AddAll(a);
        AddAll(b);

        return set.OrderBy(x => x, StringComparer.OrdinalIgnoreCase);
    }

    private static string? NormalizeNameServer(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var t = value.Trim().TrimEnd('.');
        if (t.Length == 0)
        {
            return null;
        }

        return t.ToLowerInvariant();
    }
}

