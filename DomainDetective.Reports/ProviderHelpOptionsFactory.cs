using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

public sealed class ProviderHelpOverrides
{
    public IReadOnlyList<string>? Under { get; set; }
    public IReadOnlyList<string>? Topics { get; set; }
    public bool? ShowSummaries { get; set; }
    public bool? ShowNotes { get; set; }
    public bool? ShowBadges { get; set; }
    public bool? ShowVerified { get; set; }
    public bool? IncludeRestricted { get; set; }
    public bool? IncludeThirdParty { get; set; }
    public int? MaxProviders { get; set; }
}

public static class ProviderHelpOptionsFactory
{
    public static ProviderHelpRenderOptions Build(string? preset, ProviderHelpOverrides? overrides = null)
    {
        var options = BuildFromPreset(preset);
        if (overrides == null)
        {
            return options;
        }

        ApplyOverrides(options, overrides);
        return options;
    }

    public static ProviderHelpRenderOptions Build(string? preset, IDictionary? overrides)
    {
        var options = BuildFromPreset(preset);
        if (overrides == null || overrides.Count == 0)
        {
            return options;
        }

        var mapped = MapOverrides(overrides);
        ApplyOverrides(options, mapped);
        return options;
    }

    private static ProviderHelpRenderOptions BuildFromPreset(string? preset)
    {
        var options = new ProviderHelpRenderOptions();
        switch ((preset ?? "Standard").Trim())
        {
            case "Off":
                options.ShowUnderMx = false;
                options.ShowUnderSpf = false;
                options.ShowUnderDkim = false;
                options.ShowUnderDmarc = false;
                options.ShowUnderBimi = false;
                options.ShowUnderArc = false;
                break;
            case "Minimal":
                options.ShowUnderMx = true;
                options.ShowUnderSpf = false;
                options.ShowUnderDkim = false;
                options.ShowUnderDmarc = false;
                options.ShowUnderBimi = false;
                options.ShowUnderArc = false;
                options.ShowSummaries = false;
                options.ShowNotes = false;
                options.ShowVerified = false;
                options.ShowBadges = false;
                break;
            case "Detailed":
                options.ShowUnderMx = true;
                options.ShowUnderSpf = true;
                options.ShowUnderDkim = true;
                options.ShowUnderDmarc = true;
                options.ShowUnderBimi = true;
                options.ShowUnderArc = true;
                options.ShowSummaries = true;
                options.ShowNotes = true;
                options.ShowVerified = true;
                options.ShowBadges = true;
                break;
            default:
                options.ShowUnderMx = true;
                options.ShowUnderSpf = true;
                options.ShowUnderDkim = true;
                options.ShowUnderDmarc = true;
                options.ShowUnderBimi = true;
                options.ShowUnderArc = true;
                options.ShowSummaries = true;
                options.ShowNotes = true;
                options.ShowVerified = true;
                options.ShowBadges = true;
                break;
        }

        return options;
    }

    private static ProviderHelpOverrides MapOverrides(IDictionary overrides)
    {
        var mapped = new ProviderHelpOverrides();
        foreach (DictionaryEntry entry in overrides)
        {
            var key = (entry.Key?.ToString() ?? string.Empty).Trim();
            var value = entry.Value;
            if (string.Equals(key, "Under", StringComparison.OrdinalIgnoreCase))
            {
                mapped.Under = ToStringList(value);
                continue;
            }
            if (string.Equals(key, "Topics", StringComparison.OrdinalIgnoreCase))
            {
                mapped.Topics = ToStringList(value)?.Select(v => v.ToUpperInvariant()).ToList();
                continue;
            }

            switch (key.ToLowerInvariant())
            {
                case "showsummaries":
                    mapped.ShowSummaries = ToBool(value);
                    break;
                case "shownotes":
                    mapped.ShowNotes = ToBool(value);
                    break;
                case "showbadges":
                    mapped.ShowBadges = ToBool(value);
                    break;
                case "showverified":
                    mapped.ShowVerified = ToBool(value);
                    break;
                case "includerestricted":
                    mapped.IncludeRestricted = ToBool(value);
                    break;
                case "includethirdparty":
                    mapped.IncludeThirdParty = ToBool(value);
                    break;
                case "maxproviders":
                    mapped.MaxProviders = ToInt(value);
                    break;
            }
        }

        return mapped;
    }

    private static void ApplyOverrides(ProviderHelpRenderOptions options, ProviderHelpOverrides overrides)
    {
        if (options == null)
        {
            return;
        }

        if (overrides.Under != null && overrides.Under.Count > 0)
        {
            var set = new HashSet<string>(overrides.Under, StringComparer.OrdinalIgnoreCase);
            options.ShowUnderMx = set.Contains("MX");
            options.ShowUnderSpf = set.Contains("SPF");
            options.ShowUnderDkim = set.Contains("DKIM");
            options.ShowUnderDmarc = set.Contains("DMARC");
            options.ShowUnderBimi = set.Contains("BIMI");
            options.ShowUnderArc = set.Contains("ARC");
        }

        if (overrides.Topics != null && overrides.Topics.Count > 0)
        {
            options.TopicOrder = overrides.Topics.Select(v => v.ToUpperInvariant()).ToArray();
        }

        if (overrides.ShowSummaries.HasValue)
        {
            options.ShowSummaries = overrides.ShowSummaries.Value;
        }
        if (overrides.ShowNotes.HasValue)
        {
            options.ShowNotes = overrides.ShowNotes.Value;
        }
        if (overrides.ShowBadges.HasValue)
        {
            options.ShowBadges = overrides.ShowBadges.Value;
        }
        if (overrides.ShowVerified.HasValue)
        {
            options.ShowVerified = overrides.ShowVerified.Value;
        }
        if (overrides.IncludeRestricted.HasValue)
        {
            options.IncludeRestricted = overrides.IncludeRestricted.Value;
        }
        if (overrides.IncludeThirdParty.HasValue)
        {
            options.IncludeThirdParty = overrides.IncludeThirdParty.Value;
        }
        if (overrides.MaxProviders.HasValue && overrides.MaxProviders.Value > 0)
        {
            options.MaxProviders = overrides.MaxProviders.Value;
        }
    }

    private static IReadOnlyList<string>? ToStringList(object? value)
    {
        if (value == null)
        {
            return null;
        }

        if (value is string single)
        {
            return new List<string> { single };
        }

        if (value is IEnumerable enumerable)
        {
            var list = new List<string>();
            foreach (var item in enumerable)
            {
                if (item == null)
                {
                    continue;
                }
                var text = item.ToString();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    list.Add(text.Trim());
                }
            }
            return list.Count > 0 ? list : null;
        }

        var fallback = value.ToString();
        if (string.IsNullOrWhiteSpace(fallback))
        {
            return null;
        }
        return new List<string> { fallback.Trim() };
    }

    private static bool? ToBool(object? value)
    {
        if (value == null)
        {
            return null;
        }
        if (value is bool b)
        {
            return b;
        }
        try
        {
            return Convert.ToBoolean(value);
        }
        catch
        {
            if (bool.TryParse(value.ToString(), out var parsed))
            {
                return parsed;
            }
        }
        return null;
    }

    private static int? ToInt(object? value)
    {
        if (value == null)
        {
            return null;
        }
        if (value is int i)
        {
            return i;
        }
        if (int.TryParse(value.ToString(), out var parsed))
        {
            return parsed;
        }
        return null;
    }
}
