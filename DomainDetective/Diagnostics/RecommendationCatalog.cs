using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Defines values for recommendation domain.</summary>
public enum RecommendationDomain {
    /// <summary>Provides recommendation advice functionality.</summary>
    Http,
    /// <summary>Provides recommendation advice functionality.</summary>
    Dkim,
    /// <summary>Provides recommendation advice functionality.</summary>
    Spf,
    /// <summary>Provides recommendation advice functionality.</summary>
    Dmarc,
    /// <summary>Provides recommendation advice functionality.</summary>
    Dnssec,
    /// <summary>Provides recommendation advice functionality.</summary>
    Tls,
    /// <summary>Provides recommendation advice functionality.</summary>
    EmailAuth,
    /// <summary>Provides recommendation advice functionality.</summary>
    ThreatIntel,
    /// <summary>Provides recommendation advice functionality.</summary>
    Infrastructure,
    /// <summary>Provides recommendation advice functionality.</summary>
    Branding,
    /// <summary>Provides recommendation advice functionality.</summary>
    Privacy,
    /// <summary>Provides recommendation advice functionality.</summary>
    Other
}

/// <summary>Provides recommendation advice functionality.</summary>
public sealed class RecommendationAdvice {
    /// <summary>Gets or sets the code value.</summary>
    public string Code { get; init; } = string.Empty;
    /// <summary>Gets or sets the title value.</summary>
    public string Title { get; init; } = string.Empty;
    /// <summary>Gets or sets the why value.</summary>
    public string Why { get; init; } = string.Empty;
    /// <summary>Gets or sets the how value.</summary>
    public string How { get; init; } = string.Empty;
    /// <summary>Gets or sets the links value.</summary>
    public IReadOnlyList<string> Links { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the domain value.</summary>
    public RecommendationDomain Domain { get; init; } = RecommendationDomain.Other;
    /// <summary>Gets or sets the tags value.</summary>
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    /// <summary>Gets or sets the impact value.</summary>
    public string Impact { get; init; } = string.Empty;
    /// <summary>Gets or sets the effort value.</summary>
    public RecommendationEffort Effort { get; init; } = RecommendationEffort.Low;
    /// <summary>Gets or sets the verify value.</summary>
    public string Verify { get; init; } = string.Empty;
}

/// <summary>Defines values for recommendation effort.</summary>
public enum RecommendationEffort {
    /// <summary>Low implementation effort.</summary>
    Low,
    /// <summary>Medium implementation effort.</summary>
    Medium,
    /// <summary>High implementation effort.</summary>
    High
}

/// <summary>Defines the contract for i recommendation provider.</summary>
public interface IRecommendationProvider {
    /// <summary>Executes the register operation.</summary>
    void Register(IDictionary<string, RecommendationAdvice> map);
}

/// <summary>
/// Maps assessment codes to actionable recommendations with title/why/how/links.
/// Providers register their own domain recommendations to keep content modular.
/// </summary>
public static class RecommendationCatalog {
    private static readonly Dictionary<string, RecommendationAdvice> _map = new(StringComparer.OrdinalIgnoreCase);
    private static readonly List<IRecommendationProvider> _providers = new();

    static RecommendationCatalog() {
        AutoRegisterProvidersFromAssembly(typeof(RecommendationCatalog).Assembly);
    }

    private static void AutoRegisterProvidersFromAssembly(System.Reflection.Assembly assembly) {
        try {
            foreach (var type in assembly.GetTypes()) {
                if (type.IsAbstract || type.IsInterface) continue;
                if (!typeof(IRecommendationProvider).IsAssignableFrom(type)) continue;
                try {
                    if (Activator.CreateInstance(type) is IRecommendationProvider provider) {
                        RegisterProvider(provider);
                    }
                } catch {
                    continue;
                }
            }
        } catch {
            // ignore discovery errors to avoid blocking core functionality
        }
    }

    /// <summary>Executes the register provider operation.</summary>
    public static void RegisterProvider(IRecommendationProvider provider) {
        if (provider == null) return;
        _providers.Add(provider);
        provider.Register(_map);
    }

    /// <summary>
    /// Returns advice for an assessment code. Falls back to the assessment message when unmapped.
    /// </summary>
    public static RecommendationAdvice For(Assessment a) {
        if (!string.IsNullOrWhiteSpace(a.Code) && _map.TryGetValue(a.Code!, out var rec)) {
            return rec;
        }
        return new RecommendationAdvice {
            Code = a.Code ?? string.Empty,
            Title = a.Message,
            Why = a.Message,
            How = string.Empty,
            Links = Array.Empty<string>(),
            Domain = RecommendationDomain.Other,
            Tags = Array.Empty<string>(),
            Impact = string.Empty,
            Effort = RecommendationEffort.Low,
            Verify = string.Empty
        };
    }

    /// <summary>Attempts to get.</summary>
    public static bool TryGet(string? code, out RecommendationAdvice advice) {
        if (!string.IsNullOrWhiteSpace(code) && _map.TryGetValue(code!, out advice!)) {
            return true;
        }
        advice = null!;
        return false;
    }

    /// <summary>Gets all.</summary>
    public static IReadOnlyList<RecommendationAdvice> GetAll() => new List<RecommendationAdvice>(_map.Values);
}
