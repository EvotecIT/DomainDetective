using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DomainDetective.Providers.Dns;

public static class DnsCnameTargetDetector
{
    public sealed class Match
    {
        public DnsCnameTargetProvider Provider { get; init; }
        public DnsCnameTargetFlags Flags { get; init; }
        public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
    }

    public static Match Detect(string? cnameTarget)
    {
        var target = NormalizeHost(cnameTarget);
        if (string.IsNullOrWhiteSpace(target))
        {
            return new Match { Provider = DnsCnameTargetProvider.Unknown, Flags = DnsCnameTargetFlags.None };
        }

        var evidence = new List<string>();
        var flags = DnsCnameTargetFlags.None;

        if (IsDomainOrSubdomainOf(target, "cloudflare.net"))
        {
            flags |= DnsCnameTargetFlags.FlatteningService;
            evidence.Add("CNAME target matches cloudflare.net (flattening service)");
        }

        bool takeover = TakeoverDomains.Any(d => IsDomainOrSubdomainOf(target, d));
        if (takeover)
        {
            flags |= DnsCnameTargetFlags.TakeoverRisk;
            evidence.Add("CNAME target matches takeover-risk provider list");
        }

        var provider = DetectProvider(target, evidence);
        return new Match
        {
            Provider = provider,
            Flags = flags,
            Evidence = evidence
        };
    }

    private static DnsCnameTargetProvider DetectProvider(string target, List<string> evidence)
    {
        if (IsDomainOrSubdomainOf(target, "cloudflare.net") ||
            IsDomainOrSubdomainOf(target, "pages.dev") ||
            IsDomainOrSubdomainOf(target, "workers.dev"))
        {
            evidence.Add("Provider: Cloudflare");
            return DnsCnameTargetProvider.Cloudflare;
        }

        if (IsDomainOrSubdomainOf(target, "cloudfront.net") ||
            IsDomainOrSubdomainOf(target, "amazonaws.com"))
        {
            evidence.Add("Provider: Amazon");
            return DnsCnameTargetProvider.Amazon;
        }

        if (IsDomainOrSubdomainOf(target, "azureedge.net") ||
            IsDomainOrSubdomainOf(target, "azurefd.net") ||
            IsDomainOrSubdomainOf(target, "trafficmanager.net"))
        {
            evidence.Add("Provider: Azure");
            return DnsCnameTargetProvider.Azure;
        }

        if (IsDomainOrSubdomainOf(target, "github.io") ||
            IsDomainOrSubdomainOf(target, "githubusercontent.com"))
        {
            evidence.Add("Provider: GitHub");
            return DnsCnameTargetProvider.GitHub;
        }

        if (IsDomainOrSubdomainOf(target, "netlify.app"))
        {
            evidence.Add("Provider: Netlify");
            return DnsCnameTargetProvider.Netlify;
        }

        if (IsDomainOrSubdomainOf(target, "vercel.app"))
        {
            evidence.Add("Provider: Vercel");
            return DnsCnameTargetProvider.Vercel;
        }

        if (IsDomainOrSubdomainOf(target, "herokuapp.com"))
        {
            evidence.Add("Provider: Heroku");
            return DnsCnameTargetProvider.Heroku;
        }

        if (IsDomainOrSubdomainOf(target, "fastly.net"))
        {
            evidence.Add("Provider: Fastly");
            return DnsCnameTargetProvider.Fastly;
        }

        return DnsCnameTargetProvider.Unknown;
    }

    private static string NormalizeHost(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        return trimmed.ToLowerInvariant();
    }

    private static readonly HashSet<string> TakeoverDomains = LoadTakeoverDomains();

    private static HashSet<string> LoadTakeoverDomains()
    {
        try
        {
            using var stream = typeof(DnsCnameTargetDetector).Assembly.GetManifestResourceStream("DomainDetective.takeover.json");
            if (stream == null)
            {
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var entries = JsonSerializer.Deserialize<string[]>(json)
                ?.Where(s => !string.IsNullOrWhiteSpace(s))
                ?.Select(s => s.Trim().TrimStart('.').ToLowerInvariant())
                ?? Enumerable.Empty<string>();
            return new HashSet<string>(entries, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
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
public enum DnsCnameTargetFlags
{
    None = 0,
    FlatteningService = 1,
    TakeoverRisk = 2
}

public enum DnsCnameTargetProvider
{
    Unknown = 0,
    Cloudflare = 1,
    Amazon = 2,
    Azure = 3,
    GitHub = 4,
    Netlify = 5,
    Vercel = 6,
    Heroku = 7,
    Fastly = 8
}
