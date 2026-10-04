namespace DomainDetective;

/// <summary>Authentication of supplied service certificate evidence under a DNSSEC-secured TLSA record.</summary>
public enum DaneAuthenticationStatus {
    /// <summary>No certificate evidence was evaluated.</summary>
    NotChecked,
    /// <summary>The certificate satisfies the TLSA usage, path, and applicable name requirements.</summary>
    Authenticated,
    /// <summary>Available evidence fails an authentication requirement.</summary>
    Failed,
    /// <summary>Required DNSSEC, certificate, PKIX, or name evidence is unavailable.</summary>
    Inconclusive
}
