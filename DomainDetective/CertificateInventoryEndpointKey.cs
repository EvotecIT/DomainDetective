using System.Globalization;

namespace DomainDetective {
    /// <summary>
    /// Provides stable endpoint key construction for certificate inventory datasets.
    /// </summary>
    internal static class CertificateInventoryEndpointKey {
        private const string UnknownHost = "unknown-host";

        internal static string Build(CertificateInventoryEntry entry, bool includeServiceDimension = true) {
            if (entry == null) {
                return Build(null, null, 443, null, null, includeServiceDimension);
            }

            return Build(
                entry.Host,
                entry.ResolvedHost,
                entry.Port,
                entry.Service,
                entry.Scheme,
                includeServiceDimension);
        }

        internal static string Build(CertificateInventoryEndpointPolicy endpoint, bool includeServiceDimension = true) {
            if (endpoint == null) {
                return Build(null, null, 443, null, null, includeServiceDimension);
            }

            return Build(
                endpoint.Host,
                null,
                endpoint.Port,
                endpoint.Service,
                null,
                includeServiceDimension);
        }

        internal static string Build(
            string? host,
            string? resolvedHost,
            int port,
            string? service,
            string? scheme,
            bool includeServiceDimension = true) {
            var normalizedHost = NormalizeHost(resolvedHost, host);
            var normalizedPort = NormalizePort(port);
            if (!includeServiceDimension) {
                return normalizedHost + "|" +
                       normalizedPort.ToString(CultureInfo.InvariantCulture);
            }
            var normalizedService = NormalizeService(service, scheme, normalizedPort);
            return normalizedHost + "|" +
                   normalizedPort.ToString(CultureInfo.InvariantCulture) + "|" +
                   normalizedService;
        }

        private static string NormalizeHost(string? resolvedHost, string? host) {
            var candidate = !string.IsNullOrWhiteSpace(resolvedHost)
                ? resolvedHost
                : host;
            if (string.IsNullOrWhiteSpace(candidate)) {
                return UnknownHost;
            }

            var normalized = (candidate ?? string.Empty).Trim().TrimEnd('.');
            return normalized.Length == 0
                ? UnknownHost
                : normalized.ToLowerInvariant();
        }

        private static int NormalizePort(int port) {
            return port > 0 ? port : 443;
        }

        private static string NormalizeService(string? service, string? scheme, int port) {
            var value = service;
            if (string.IsNullOrWhiteSpace(value)) {
                var effectiveScheme = string.IsNullOrWhiteSpace(scheme) ? "https" : scheme!;
                value = CertificateServiceClassifier.GuessService(
                    effectiveScheme,
                    port);
            }

            var normalized = (value ?? string.Empty).Trim();
            if (normalized.Length == 0) {
                normalized = CertificateServiceClassifier.GuessService("https", port);
            }

            return normalized.ToUpperInvariant();
        }
    }
}
