using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Collection of predefined TLD presets.
/// </summary>
public static class DomainAvailabilityPresets
{
    /// <summary>Mapping of preset names to TLD arrays.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> TldPresets;

    /// <summary>Common TLD alternatives.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> TldAlternatives;

    /// <summary>Complete list of TLDs from the embedded public suffix list.</summary>
    public static readonly string[] All;

    static DomainAvailabilityPresets()
    {
        All = LoadAllTlds();
        TldPresets = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["common"] = new[] { "com", "net", "org", "co", "io", "app", "dev" },
            ["tech"] = new[] { "dev", "io", "app", "ai", "tech" },
            ["fun"] = new[] { "lol", "fun", "xyz", "site" },
            ["all"] = All
        };

        TldAlternatives = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["com"] = new[] { "net", "org", "co", "io" },
            ["net"] = new[] { "com", "org" },
            ["org"] = new[] { "com", "net" },
            ["io"] = new[] { "app", "dev" },
            ["co"] = new[] { "com" }
        };
    }

    private static string[] LoadAllTlds()
    {
        using var stream = typeof(DomainAvailabilityPresets).Assembly
            .GetManifestResourceStream("DomainDetective.public_suffix_list.dat");
        if (stream == null)
        {
            return Array.Empty<string>();
        }

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("//"))
            {
                continue;
            }

            if (trimmed.StartsWith("!"))
            {
                trimmed = trimmed.Substring(1);
            }

            if (trimmed.StartsWith("*."))
            {
                trimmed = trimmed.Substring(2);
            }

            var idx = trimmed.LastIndexOf('.');
            var tld = idx >= 0 ? trimmed.Substring(idx + 1) : trimmed;
            set.Add(tld);
        }

        return set.ToArray();
    }
}

/// <summary>
/// Result of a single domain availability check.
/// </summary>
public sealed record DomainAvailabilityResult(string Domain, bool Available);

/// <summary>
/// Generates domain permutations and checks availability using RDAP.
/// </summary>
public class DomainAvailabilitySearch
{
    /// <summary>Prefixes used to generate permutations.</summary>
    public IReadOnlyList<string> Prefixes { get; set; } = Array.Empty<string>();

    /// <summary>Suffixes used to generate permutations.</summary>
    public IReadOnlyList<string> Suffixes { get; set; } = Array.Empty<string>();

    /// <summary>TLDs used to generate permutations.</summary>
    public IReadOnlyList<string> Tlds { get; set; } = new[] { "com" };

    /// <summary>Name of the active TLD preset.</summary>
    public string? TldPreset
    {
        get => _preset;
        set
        {
            _preset = value;
            if (!string.IsNullOrWhiteSpace(value) && DomainAvailabilityPresets.TldPresets.TryGetValue(value!, out var preset))
            {
                Tlds = preset;
            }
        }
    }

    private string? _preset;

    /// <summary>Minimum length for the domain label.</summary>
    public int MinLength { get; set; }

    /// <summary>Maximum length for the domain label.</summary>
    public int MaxLength { get; set; } = int.MaxValue;

    /// <summary>Maximum concurrent RDAP queries.</summary>
    public int Concurrency { get; set; } = 10;

    /// <summary>Override to simulate RDAP queries for testing.</summary>
    internal Func<string, CancellationToken, Task<bool>>? AvailabilityOverride { private get; set; }
        

    /// <summary>
    /// Generates domain permutations for specified keywords.
    /// </summary>
    /// <param name="keywords">Keywords used to build domain names.</param>
    /// <returns>Enumeration of domain names.</returns>
    public IEnumerable<string> Generate(IEnumerable<string> keywords)
    {
        foreach (var keyword in keywords.Where(k => !string.IsNullOrWhiteSpace(k)))
        {
            var key = keyword.Trim().ToLowerInvariant();
            foreach (var tld in Tlds)
            {
                foreach (var domain in EnumerateForKeyword(key, tld))
                {
                    yield return domain;
                }
            }
        }
    }

    /// <summary>
    /// Generates alternative domains for a given name using <see cref="DomainAvailabilityPresets.TldAlternatives"/>.
    /// </summary>
    /// <param name="domain">Domain with TLD.</param>
    /// <returns>Enumeration of alternative domains.</returns>
    public IEnumerable<string> GenerateTldAlternatives(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        var idx = domain.LastIndexOf('.');
        if (idx < 0)
        {
            yield break;
        }

        var label = domain.Substring(0, idx);
        var tld = domain.Substring(idx + 1);
        if (DomainAvailabilityPresets.TldAlternatives.TryGetValue(tld, out var alternatives))
        {
            foreach (var alt in alternatives)
            {
                yield return $"{label}.{alt}";
            }
        }
    }

    private IEnumerable<string> EnumerateForKeyword(string keyword, string tld)
    {
        var baseLabel = keyword;
        yield return $"{baseLabel}.{tld}";

        foreach (var prefix in Prefixes)
        {
            yield return $"{prefix}{baseLabel}.{tld}";
        }

        foreach (var suffix in Suffixes)
        {
            yield return $"{baseLabel}{suffix}.{tld}";
        }

        foreach (var prefix in Prefixes)
        {
            foreach (var suffix in Suffixes)
            {
                yield return $"{prefix}{baseLabel}{suffix}.{tld}";
            }
        }
    }

    private static readonly RdapClient _rdapClient = new();

    private async Task<bool> IsAvailableAsync(string domain, CancellationToken ct)
    {
        if (AvailabilityOverride != null)
        {
            return await AvailabilityOverride(domain, ct).ConfigureAwait(false);
        }

        try
        {
            var result = await _rdapClient.QueryDomainAsync(domain, ct).ConfigureAwait(false);
            return result == null;
        }
        catch (HttpRequestException ex)
        {
#if NET8_0_OR_GREATER
            if (ex.StatusCode == HttpStatusCode.NotFound)
            {
                return true;
            }
            throw;
#else
            if (ex.Message.Contains("404"))
            {
                return true;
            }
            throw;
#endif
        }
    }

    /// <summary>
    /// Checks RDAP availability for a single domain.
    /// </summary>
    /// <param name="domain">Domain name to query.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Availability result for <paramref name="domain"/>.</returns>
    public async Task<DomainAvailabilityResult> CheckAsync(string domain, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        var normalized = DomainHelper.ValidateIdn(domain.Trim());
        var available = await IsAvailableAsync(normalized, ct).ConfigureAwait(false);
        return new DomainAvailabilityResult(normalized, available);
    }

    /// <summary>
    /// Checks RDAP availability for the current <see cref="Tlds"/> list.
    /// </summary>
    /// <param name="label">Domain label without the TLD.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Stream of availability results.</returns>
    public async IAsyncEnumerable<DomainAvailabilityResult> CheckTldsAsync(
        string label,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var r in CheckTldsAsync(label, Tlds, ct))
        {
            yield return r;
        }
    }

    private async IAsyncEnumerable<DomainAvailabilityResult> CheckTldsAsync(
        string label,
        IEnumerable<string> tlds,
        [EnumeratorCancellation] CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(label))
        {
            throw new ArgumentNullException(nameof(label));
        }

        var normalized = label.Trim().ToLowerInvariant();
        var domains = new Queue<string>(tlds
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => $"{normalized}.{t.Trim()}"));

        var tasks = new List<Task<DomainAvailabilityResult>>();

        async Task<DomainAvailabilityResult> Check(string dom)
        {
            var normalizedDomain = DomainHelper.ValidateIdn(dom);
            var available = await IsAvailableAsync(normalizedDomain, ct).ConfigureAwait(false);
            return new DomainAvailabilityResult(normalizedDomain, available);
        }

        for (var i = 0; i < Concurrency && domains.Count > 0; i++)
        {
            tasks.Add(Check(domains.Dequeue()));
        }

        while (tasks.Count > 0)
        {
            var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
            tasks.Remove(finished);
            yield return await finished.ConfigureAwait(false);
            if (domains.Count > 0)
            {
                tasks.Add(Check(domains.Dequeue()));
            }
        }
    }

    /// <summary>
    /// Checks alternative TLDs for the provided domain name.
    /// </summary>
    /// <param name="domain">Domain with TLD.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Stream of availability results.</returns>
    public async IAsyncEnumerable<DomainAvailabilityResult> CheckTldAlternativesAsync(
        string domain,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        var idx = domain.LastIndexOf('.');
        if (idx < 0)
        {
            yield break;
        }

        var label = domain.Substring(0, idx);
        var tld = domain.Substring(idx + 1);
        if (!DomainAvailabilityPresets.TldAlternatives.TryGetValue(tld, out var alternatives))
        {
            yield break;
        }

        await foreach (var r in CheckTldsAsync(label, alternatives, ct))
        {
            yield return r;
        }
    }

    /// <summary>
    /// Asynchronously checks availability for generated domain names.
    /// </summary>
    /// <param name="keywords">Keywords used to generate domains.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Stream of availability results.</returns>
    public async IAsyncEnumerable<DomainAvailabilityResult> SearchAsync(
        IEnumerable<string> keywords,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var domains = new Queue<string>(Generate(keywords)
            .Where(d =>
            {
                var idx = d.LastIndexOf('.');
                var label = idx > 0 ? d.Substring(0, idx) : d;
                return label.Length >= MinLength && label.Length <= MaxLength;
            })
            .Distinct(StringComparer.OrdinalIgnoreCase));

        var tasks = new List<Task<DomainAvailabilityResult>>();

        async Task<DomainAvailabilityResult> Check(string dom)
        {
            var normalizedDomain = DomainHelper.ValidateIdn(dom);
            var available = await IsAvailableAsync(normalizedDomain, ct).ConfigureAwait(false);
            return new DomainAvailabilityResult(normalizedDomain, available);
        }

        for (var i = 0; i < Concurrency && domains.Count > 0; i++)
        {
            tasks.Add(Check(domains.Dequeue()));
        }

        while (tasks.Count > 0)
        {
            var finished = await Task.WhenAny(tasks).ConfigureAwait(false);
            tasks.Remove(finished);
            yield return await finished.ConfigureAwait(false);
            if (domains.Count > 0)
            {
                tasks.Add(Check(domains.Dequeue()));
            }
        }
    }
}
