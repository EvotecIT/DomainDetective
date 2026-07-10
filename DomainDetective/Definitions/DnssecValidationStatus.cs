namespace DomainDetective;

/// <summary>Describes the evidence-backed DNSSEC state for a queried subject.</summary>
public enum DnssecValidationStatus {
    /// <summary>No conclusive validation attempt completed.</summary>
    NotChecked = 0,
    /// <summary>The subject response and enclosing zone evidence were authenticated.</summary>
    Secure = 1,
    /// <summary>The resolver proved or indicated an insecure, unsigned path rather than a bogus signature.</summary>
    Insecure = 2,
    /// <summary>DNSSEC records were present but their authentication or DS/DNSKEY relationship failed.</summary>
    Bogus = 3,
    /// <summary>Network or resolver evidence was insufficient to classify the subject.</summary>
    Indeterminate = 4
}
