using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.TimeSeries.Registration;

/// <summary>Provides registration drift detector functionality.</summary>
public static class RegistrationDriftDetector
{
    /// <summary>Executes the compute operation.</summary>
    public static RegistrationDrift Compute(RegistrationSnapshot previous, RegistrationSnapshot current)
    {
        if (previous == null) throw new ArgumentNullException(nameof(previous));
        if (current == null) throw new ArgumentNullException(nameof(current));

        var domain = !string.IsNullOrWhiteSpace(current.Domain) ? current.Domain : previous.Domain;
        var drift = new RegistrationDrift
        {
            Domain = domain,
            FromCapturedAtUtc = previous.CapturedAtUtc,
            ToCapturedAtUtc = current.CapturedAtUtc
        };

        AddScalarChange(drift, RegistrationChangeKind.RegistrarChanged, previous.Registrar, current.Registrar);
        AddScalarChange(drift, RegistrationChangeKind.RegistrarIdChanged, previous.RegistrarId, current.RegistrarId);
        AddScalarChange(drift, RegistrationChangeKind.CreatedAtChanged, NormalizeTime(previous.CreatedAtUtc, previous.CreatedAtRaw), NormalizeTime(current.CreatedAtUtc, current.CreatedAtRaw));
        AddScalarChange(drift, RegistrationChangeKind.UpdatedAtChanged, NormalizeTime(previous.UpdatedAtUtc, previous.UpdatedAtRaw), NormalizeTime(current.UpdatedAtUtc, current.UpdatedAtRaw));
        AddScalarChange(drift, RegistrationChangeKind.ExpiresAtChanged, NormalizeTime(previous.ExpiresAtUtc, previous.ExpiresAtRaw), NormalizeTime(current.ExpiresAtUtc, current.ExpiresAtRaw));

        AddScalarChange(drift, RegistrationChangeKind.PrivacyProtectedChanged, NormalizeBool(previous.PrivacyProtected), NormalizeBool(current.PrivacyProtected));
        AddScalarChange(drift, RegistrationChangeKind.RegistrarLockedChanged, NormalizeBool(previous.RegistrarLocked), NormalizeBool(current.RegistrarLocked));

        AddScalarChange(drift, RegistrationChangeKind.RdapAvailabilityChanged, previous.HasRdap.ToString(), current.HasRdap.ToString());
        AddScalarChange(drift, RegistrationChangeKind.WhoisAvailabilityChanged, previous.HasWhois.ToString(), current.HasWhois.ToString());

        AddListChange(drift, RegistrationChangeKind.NameServersChanged, previous.NameServers, current.NameServers);
        AddListChange(drift, RegistrationChangeKind.StatusChanged, previous.Status, current.Status);

        drift.Changes = drift.Changes
            .OrderBy(c => c.Kind)
            .ThenBy(c => c.Before ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return drift;
    }

    private static void AddScalarChange(RegistrationDrift drift, RegistrationChangeKind kind, string? before, string? after)
    {
        var b = NormalizeText(before);
        var a = NormalizeText(after);
        if (string.Equals(b, a, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        drift.Changes.Add(new RegistrationChange
        {
            Kind = kind,
            Before = b,
            After = a
        });
    }

    private static void AddListChange(RegistrationDrift drift, RegistrationChangeKind kind, IEnumerable<string>? before, IEnumerable<string>? after)
    {
        var b = new HashSet<string>((before ?? Array.Empty<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(NormalizeText)!, StringComparer.OrdinalIgnoreCase);
        var a = new HashSet<string>((after ?? Array.Empty<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(NormalizeText)!, StringComparer.OrdinalIgnoreCase);

        var added = a.Except(b, StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        var removed = b.Except(a, StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();

        if (added.Count == 0 && removed.Count == 0)
        {
            return;
        }

        drift.Changes.Add(new RegistrationChange
        {
            Kind = kind,
            Added = added,
            Removed = removed
        });
    }

    private static string? NormalizeText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        return value!.Trim();
    }

    private static string? NormalizeBool(bool? value)
    {
        if (!value.HasValue)
        {
            return null;
        }
        return value.Value ? "true" : "false";
    }

    private static string? NormalizeTime(DateTimeOffset? utc, string? raw)
    {
        if (utc.HasValue)
        {
            return utc.Value.ToUniversalTime().ToString("O");
        }
        return NormalizeText(raw);
    }
}
