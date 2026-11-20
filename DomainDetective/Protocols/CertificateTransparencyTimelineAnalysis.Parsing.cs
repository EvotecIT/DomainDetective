using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;

namespace DomainDetective;

public sealed partial class CertificateTransparencyTimelineAnalysis
{
    private static string? GetString(JsonElement obj, string prop)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!obj.TryGetProperty(prop, out var p))
        {
            return null;
        }

        return p.ValueKind == JsonValueKind.String ? p.GetString() : p.ToString();
    }

    private static int? GetInt(JsonElement obj, string prop)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!obj.TryGetProperty(prop, out var p))
        {
            return null;
        }

        if (p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out var i))
        {
            return i;
        }

        if (p.ValueKind == JsonValueKind.String &&
            int.TryParse(p.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var si))
        {
            return si;
        }

        return null;
    }

    private static DateTimeOffset? ParseTimestamp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var dt))
        {
            return dt;
        }

        return DateTimeOffset.TryParse(value, out dt) ? dt : null;
    }

    private static int YearMonthKey(DateTimeOffset dt)
    {
        try
        {
            return (dt.Year * 100) + dt.Month;
        }
        catch
        {
            return 0;
        }
    }

    // A precertificate and its final certificate are two CT entries, with two provider ids, for one issuance.
    // Key the issuance by what both entries share: the TBS hash without the poison and SCT extensions, then the
    // issuer and serial number. The provider id only identifies a single entry, so it is a fallback.
    private static string BuildCertificateKey(CtRow row)
    {
        var tbs = CtCertificateRecord.NormalizeHex(row.TbsSha256);
        if (!string.IsNullOrEmpty(tbs))
        {
            return "tbs:" + tbs;
        }

        var issuer = (row.IssuerName ?? string.Empty).Trim();
        var serial = NormalizeSerial(row.SerialNumber);
        if (issuer.Length > 0 && serial.Length > 0)
        {
            return "serial:" + issuer + "|" + serial;
        }

        var keyId = (row.Id ?? string.Empty).Trim();
        if (keyId.Length > 0)
        {
            return "id:" + keyId;
        }

        var nb = row.NotBeforeUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
        var na = row.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
        var cn = (row.CommonName ?? string.Empty).Trim();
        var nv = (row.NameValue ?? string.Empty).Trim();

        // Fallback key: issuer + serial + validity window + CN + SAN blob (capped)
        if (nv.Length > 512)
        {
            nv = nv.Substring(0, 512);
        }
        if (cn.Length > 256)
        {
            cn = cn.Substring(0, 256);
        }

        return $"{issuer}|{serial}|{nb}|{na}|{cn}|{nv}";
    }

    // Serial numbers are integers: ignore separators, case and leading zeros so "00:4A:05" and "4a05" match.
    private static string NormalizeSerial(string? serial)
    {
        var hex = CtCertificateRecord.NormalizeHex(serial) ?? string.Empty;
        var trimmed = hex.TrimStart('0');
        return trimmed.Length == 0 && hex.Length > 0 ? "0" : trimmed;
    }

    private static string? GetIssuerName(JsonElement item)
    {
        var direct = GetString(item, "issuer_name");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("issuer", out var issuer))
        {
            return null;
        }

        if (issuer.ValueKind == JsonValueKind.String)
        {
            return issuer.GetString();
        }

        if (issuer.ValueKind == JsonValueKind.Object)
        {
            return GetString(issuer, "name") ??
                   GetString(issuer, "common_name") ??
                   GetString(issuer, "organization");
        }

        return null;
    }

    private static string? GetCommonName(JsonElement item)
    {
        var commonName = GetString(item, "common_name");
        if (!string.IsNullOrWhiteSpace(commonName))
        {
            return commonName;
        }

        if (item.ValueKind == JsonValueKind.Object &&
            item.TryGetProperty("dns_names", out var dnsNames) &&
            dnsNames.ValueKind == JsonValueKind.Array)
        {
            foreach (var dnsName in dnsNames.EnumerateArray())
            {
                if (dnsName.ValueKind == JsonValueKind.String)
                {
                    var value = dnsName.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        return value;
                    }
                }
            }
        }

        return null;
    }

    private static string? GetNameValue(JsonElement item)
    {
        var nameValue = GetString(item, "name_value");
        if (!string.IsNullOrWhiteSpace(nameValue))
        {
            return nameValue;
        }

        if (item.ValueKind != JsonValueKind.Object ||
            !item.TryGetProperty("dns_names", out var dnsNames) ||
            dnsNames.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var values = new List<string>();
        foreach (var dnsName in dnsNames.EnumerateArray())
        {
            if (dnsName.ValueKind == JsonValueKind.String)
            {
                var value = dnsName.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    values.Add(value!);
                }
            }
        }

        if (values.Count == 0)
        {
            return null;
        }

        return string.Join("\n", values);
    }

    private static bool DetectWildcard(string? commonName, string? nameValue)
    {
        if (!string.IsNullOrWhiteSpace(commonName) &&
            commonName!.TrimStart().StartsWith("*.", StringComparison.Ordinal))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(nameValue))
        {
            foreach (var name in nameValue!.Split('\n'))
            {
                var normalized = name.TrimStart();
                if (normalized.StartsWith("*.", StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
