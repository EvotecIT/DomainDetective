using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Helpers;

namespace DomainDetective.Providers.Dns;

/// <summary>Provides dns caa issuer detector functionality.</summary>
public static class DnsCaaIssuerDetector
{
    /// <summary>Provides match functionality.</summary>
    public sealed class Match
    {
        /// <summary>Gets or sets the issuers value.</summary>
        public DnsCaaIssuers Issuers { get; init; }
        /// <summary>Gets or sets the evidence value.</summary>
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

    /// <summary>Executes the detect operation.</summary>
    public static Match Detect(IEnumerable<string>? caaValues)
    {
        var values = (caaValues ?? Array.Empty<string>())
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (values.Count == 0)
        {
            return new Match { Issuers = DnsCaaIssuers.None };
        }

        var evidence = new List<string>();
        DnsCaaIssuers issuers = DnsCaaIssuers.None;

        foreach (var raw in values)
        {
            if (!TryParseCaa(raw, out var tag, out var issuerOrMarker))
            {
                continue;
            }

            if (issuerOrMarker == ";")
            {
                if (evidence.Count < 10)
                {
                    evidence.Add($"CAA: tag '{tag}' denies issuance (';').");
                }
                continue;
            }

            if (!TryMapIssuer(issuerOrMarker, out var issuer))
            {
                if (evidence.Count < 10)
                {
                    evidence.Add($"CAA: unrecognized issuer '{issuerOrMarker}' (tag '{tag}').");
                }
                continue;
            }

            if (!issuers.HasFlag(issuer))
            {
                issuers |= issuer;
            }

            if (evidence.Count < 10)
            {
                evidence.Add($"CAA: issuer '{issuerOrMarker}' (tag '{tag}').");
            }
        }

        return new Match { Issuers = issuers, Evidence = evidence };
    }

    private static bool TryParseCaa(string raw, out string tag, out string issuerOrMarker)
    {
        tag = string.Empty;
        issuerOrMarker = string.Empty;

        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var parts = raw
            .Trim()
            .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length < 2)
        {
            return false;
        }

        int tagIndex = 0;
        if (parts.Length >= 3 && int.TryParse(parts[0], out _))
        {
            tagIndex = 1;
        }

        if (parts.Length <= tagIndex + 1)
        {
            return false;
        }

        tag = parts[tagIndex].Trim();
        if (tag.Length == 0)
        {
            return false;
        }

        var value = string.Join(" ", parts.Skip(tagIndex + 1)).Trim();
        if (value.Length == 0)
        {
            return false;
        }

        issuerOrMarker = NormalizeIssuerValue(value);
        return issuerOrMarker.Length > 0;
    }

    private static string NormalizeIssuerValue(string value)
    {
        var v = (value ?? string.Empty).Trim();
        if (v.Length == 0)
        {
            return string.Empty;
        }

        // Handle single quoted-string values: "letsencrypt.org; accounturi=..."
        if (v.Length >= 2 && v[0] == '"' && v[v.Length - 1] == '"')
        {
            v = v.Substring(1, v.Length - 2);
        }

        v = v.Trim();
        if (v.Length == 0)
        {
            return string.Empty;
        }

        // Use only the issuer domain (strip parameters).
        var semi = v.IndexOf(';');
        if (semi >= 0)
        {
            v = v.Substring(0, semi).Trim();
        }

        if (v == ";")
        {
            return ";";
        }

        return v.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static bool TryMapIssuer(string issuerDomain, out DnsCaaIssuers issuer)
    {
        issuer = DnsCaaIssuers.None;

        var d = issuerDomain.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.Length == 0 || d == ";")
        {
            return false;
        }

        if (IsDomainOrSubdomainOf(d, "letsencrypt.org")) { issuer = DnsCaaIssuers.LetsEncrypt; return true; }
        if (IsDomainOrSubdomainOf(d, "digicert.com")) { issuer = DnsCaaIssuers.DigiCert; return true; }
        if (IsDomainOrSubdomainOf(d, "comodoca.com") || IsDomainOrSubdomainOf(d, "sectigo.com")) { issuer = DnsCaaIssuers.Sectigo; return true; }
        if (IsDomainOrSubdomainOf(d, "globalsign.com")) { issuer = DnsCaaIssuers.GlobalSign; return true; }
        if (IsDomainOrSubdomainOf(d, "pki.goog")) { issuer = DnsCaaIssuers.GoogleTrustServices; return true; }
        if (IsDomainOrSubdomainOf(d, "amazontrust.com") || IsDomainOrSubdomainOf(d, "amazon.com")) { issuer = DnsCaaIssuers.AmazonTrustServices; return true; }
        if (IsDomainOrSubdomainOf(d, "ssl.com")) { issuer = DnsCaaIssuers.SslDotCom; return true; }
        if (IsDomainOrSubdomainOf(d, "zerossl.com")) { issuer = DnsCaaIssuers.ZeroSsl; return true; }
        if (IsDomainOrSubdomainOf(d, "buypass.com")) { issuer = DnsCaaIssuers.Buypass; return true; }
        if (IsDomainOrSubdomainOf(d, "entrust.net") || IsDomainOrSubdomainOf(d, "entrust.com")) { issuer = DnsCaaIssuers.Entrust; return true; }
        if (IsDomainOrSubdomainOf(d, "godaddy.com")) { issuer = DnsCaaIssuers.GoDaddy; return true; }
        if (IsDomainOrSubdomainOf(d, "cloudflare.com")) { issuer = DnsCaaIssuers.Cloudflare; return true; }
        if (IsDomainOrSubdomainOf(d, "microsoft.com")) { issuer = DnsCaaIssuers.Microsoft; return true; }

        return false;
    }

    private static bool IsDomainOrSubdomainOf(string host, string domain)
    {
        return DomainHelper.IsDomainOrSubdomainOf(host, domain);
    }
}

/// <summary>Defines values for dns caa issuers.</summary>
[Flags]
public enum DnsCaaIssuers
{
    /// <summary>Represents the none value.</summary>
    None = 0,
    /// <summary>Represents the lets encrypt value.</summary>
    LetsEncrypt = 1,
    /// <summary>Represents the digi cert value.</summary>
    DigiCert = 2,
    /// <summary>Represents the sectigo value.</summary>
    Sectigo = 4,
    /// <summary>Represents the global sign value.</summary>
    GlobalSign = 8,
    /// <summary>Represents the google trust services value.</summary>
    GoogleTrustServices = 16,
    /// <summary>Represents the amazon trust services value.</summary>
    AmazonTrustServices = 32,
    /// <summary>Represents the cloudflare value.</summary>
    Cloudflare = 64,
    /// <summary>Represents the microsoft value.</summary>
    Microsoft = 128,
    /// <summary>Represents the go daddy value.</summary>
    GoDaddy = 256,
    /// <summary>Represents the zero ssl value.</summary>
    ZeroSsl = 512,
    /// <summary>Represents the buypass value.</summary>
    Buypass = 1024,
    /// <summary>Represents the entrust value.</summary>
    Entrust = 2048,
    /// <summary>Represents the ssl dot com value.</summary>
    SslDotCom = 4096
}
