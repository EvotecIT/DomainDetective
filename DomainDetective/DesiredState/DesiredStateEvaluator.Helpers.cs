using System;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static string? TryGetHost(string? uriString) {
        if (string.IsNullOrWhiteSpace(uriString)) return null;
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri)) return null;
        if (string.IsNullOrWhiteSpace(uri.Host)) return null;
        return uri.Host.Trim().Trim('.');
    }
}

