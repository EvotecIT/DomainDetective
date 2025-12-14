using System;
using System.Collections.Generic;

namespace DomainDetective;

public enum RecommendationDomain {
    Http,
    Dkim,
    Spf,
    Dmarc,
    Dnssec,
    Tls,
    EmailAuth,
    ThreatIntel,
    Infrastructure,
    Branding,
    Privacy,
    Other
}

public sealed class RecommendationAdvice {
    public string Code { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Why { get; init; } = string.Empty;
    public string How { get; init; } = string.Empty;
    public IReadOnlyList<string> Links { get; init; } = Array.Empty<string>();
    public RecommendationDomain Domain { get; init; } = RecommendationDomain.Other;
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public string Impact { get; init; } = string.Empty;
    public RecommendationEffort Effort { get; init; } = RecommendationEffort.Low;
    public string Verify { get; init; } = string.Empty;
}

public enum RecommendationEffort { Low, Medium, High }

public interface IRecommendationProvider {
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

    public static bool TryGet(string? code, out RecommendationAdvice advice) {
        if (!string.IsNullOrWhiteSpace(code) && _map.TryGetValue(code!, out advice!)) {
            return true;
        }
        advice = null!;
        return false;
    }

    public static IReadOnlyList<RecommendationAdvice> GetAll() => new List<RecommendationAdvice>(_map.Values);
}
