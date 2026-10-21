using System;
using System.Globalization;
using System.Text;

namespace DomainDetective;

/// <summary>Identity of a source assertion. Different endpoints, sources, certificates or observations never deduplicate.</summary>
public sealed class CertificateObservationIdentity : IEquatable<CertificateObservationIdentity> {
    /// <summary>Creates an identity, requiring a source observation id rather than inventing one from a hostname.</summary>
    public CertificateObservationIdentity(string source, string? fingerprint, CertificateEndpointIdentity endpoint, string observationId, string profileId = "", string vantage = "default", bool isEndpointObservation = true) {
        if (string.IsNullOrWhiteSpace(source)) throw new ArgumentException("Source is required.", nameof(source));
        if (string.IsNullOrWhiteSpace(observationId)) throw new ArgumentException("Observation identity is required.", nameof(observationId));
        Endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        Source = source.Trim().ToLowerInvariant();
        Fingerprint = (fingerprint ?? string.Empty).Replace(":", "").Trim().ToUpperInvariant();
        ObservationId = observationId;
        ProfileId = profileId ?? string.Empty;
        Vantage = vantage ?? string.Empty;
        IsEndpointObservation = isEndpointObservation;
        var key = new StringBuilder();
        foreach (string part in new[] { Source, Fingerprint, Endpoint.Key, ObservationId, ProfileId, Vantage, IsEndpointObservation ? "endpoint" : "name" })
            key.Append(part.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(part);
        Key = key.ToString();
    }
    /// <summary>Normalized source system.</summary>
    public string Source { get; }
    /// <summary>Normalized SHA-256 fingerprint, empty when the assertion has no certificate.</summary>
    public string Fingerprint { get; }
    /// <summary>Logical host, port and service identity.</summary>
    public CertificateEndpointIdentity Endpoint { get; }
    /// <summary>Exact source observation identity.</summary>
    public string ObservationId { get; }
    /// <summary>Configured protocol/probe profile.</summary>
    public string ProfileId { get; }
    /// <summary>Observation location, retained independently of endpoint identity.</summary>
    public string Vantage { get; }
    /// <summary>False for issuance/name assertions, which cannot establish a live service or endpoint count.</summary>
    public bool IsEndpointObservation { get; }
    /// <summary>Length-framed identity safe for arbitrary source observation ids.</summary>
    public string Key { get; }
    /// <inheritdoc />
    public bool Equals(CertificateObservationIdentity? other) => other != null && string.Equals(Key, other.Key, StringComparison.Ordinal);
    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as CertificateObservationIdentity);
    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Key);
}
