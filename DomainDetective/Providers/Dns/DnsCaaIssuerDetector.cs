using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Providers.Dns;

public static class DnsCaaIssuerDetector
{
    public sealed class Match
    {
        public DnsCaaIssuers Issuers { get; init; }
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

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

        var d = issuerDomain?.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(d) || d == ";")
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
        if (host.Equals(domain, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (host.Length <= domain.Length)
        {
            return false;
        }

        if (!host.EndsWith(domain, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return host[host.Length - domain.Length - 1] == '.';
    }
}

[Flags]
public enum DnsCaaIssuers
{
    None = 0,
    LetsEncrypt = 1,
    DigiCert = 2,
    Sectigo = 4,
    GlobalSign = 8,
    GoogleTrustServices = 16,
    AmazonTrustServices = 32,
    Cloudflare = 64,
    Microsoft = 128,
    GoDaddy = 256,
    ZeroSsl = 512,
    Buypass = 1024,
    Entrust = 2048,
    SslDotCom = 4096
}

