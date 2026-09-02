using System;
using System.Globalization;

namespace DomainDetective;

/// <summary>
/// Identifies a certificate-bearing service endpoint independently from any one observation.
/// </summary>
/// <remarks>
/// A hostname alone is not an endpoint. Port and service remain part of the identity so that,
/// for example, HTTPS and SMTP STARTTLS observations on the same host cannot be merged.
/// </remarks>
public sealed class CertificateEndpointIdentity : IEquatable<CertificateEndpointIdentity> {
    private const string UnknownHost = "unknown-host";

    private CertificateEndpointIdentity(string host, int port, string service) {
        Host = host;
        Port = port;
        Service = service;
    }

    /// <summary>Normalized logical hostname used for protocol and certificate identity.</summary>
    public string Host { get; }

    /// <summary>TCP port used by the service.</summary>
    public int Port { get; }

    /// <summary>Normalized service name, such as HTTPS or SMTP-STARTTLS.</summary>
    public string Service { get; }

    /// <summary>Stable key in <c>host|port|service</c> form.</summary>
    public string Key => Host + "|" + Port.ToString(CultureInfo.InvariantCulture) + "|" + Service;

    /// <summary>Creates a normalized endpoint identity.</summary>
    public static CertificateEndpointIdentity Create(
        string? host,
        int port,
        string? service = null,
        string? scheme = null) {
        int normalizedPort = port > 0 ? port : 443;
        string normalizedHost = NormalizeHost(host);
        string normalizedService = NormalizeService(service, scheme, normalizedPort);
        return new CertificateEndpointIdentity(normalizedHost, normalizedPort, normalizedService);
    }

    /// <summary>Creates an endpoint identity from an inventory entry.</summary>
    public static CertificateEndpointIdentity FromEntry(CertificateInventoryEntry? entry) {
        if (entry == null) {
            return Create(null, 443);
        }

        string? host = !string.IsNullOrWhiteSpace(entry.ResolvedHost)
            ? entry.ResolvedHost
            : entry.Host;
        return Create(host, entry.Port, entry.Service, entry.Scheme);
    }

    /// <inheritdoc />
    public bool Equals(CertificateEndpointIdentity? other) {
        return other != null &&
               Port == other.Port &&
               string.Equals(Host, other.Host, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(Service, other.Service, StringComparison.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as CertificateEndpointIdentity);

    /// <inheritdoc />
    public override int GetHashCode() {
        unchecked {
            int hash = StringComparer.OrdinalIgnoreCase.GetHashCode(Host);
            hash = (hash * 397) ^ Port;
            hash = (hash * 397) ^ StringComparer.OrdinalIgnoreCase.GetHashCode(Service);
            return hash;
        }
    }

    /// <inheritdoc />
    public override string ToString() => Key;

    private static string NormalizeHost(string? host) {
        string normalized = EndpointHostNormalizer.Normalize(host);
        return normalized.Length == 0 ? UnknownHost : normalized.ToLowerInvariant();
    }

    private static string NormalizeService(string? service, string? scheme, int port) {
        string? value = service;
        if (string.IsNullOrWhiteSpace(value)) {
            value = CertificateServiceClassifier.GuessService(
                string.IsNullOrWhiteSpace(scheme) ? "https" : scheme!,
                port);
        }

        string normalized = (value ?? string.Empty).Trim();
        if (normalized.Length == 0) {
            normalized = CertificateServiceClassifier.GuessService("https", port);
        }

        return normalized.ToUpperInvariant();
    }
}
