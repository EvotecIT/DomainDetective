using System;

namespace DomainDetective;

internal static class CertificateInventoryProbeVantage {
    internal const string Default = "default";

    internal static string Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? Default : value!.Trim();

    internal static bool Equals(string? left, string? right) =>
        string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
}
