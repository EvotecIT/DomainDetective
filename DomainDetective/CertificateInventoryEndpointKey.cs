namespace DomainDetective {
    /// <summary>
    /// Provides stable endpoint key construction for certificate inventory datasets.
    /// </summary>
    internal static class CertificateInventoryEndpointKey {
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
            var candidateHost = !string.IsNullOrWhiteSpace(resolvedHost) ? resolvedHost : host;
            var identity = CertificateEndpointIdentity.Create(candidateHost, port, service, scheme);
            if (!includeServiceDimension) {
                return identity.Host + "|" + identity.Port;
            }
            return identity.Key;
        }
    }
}
