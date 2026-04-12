using System;

namespace DomainDetective;

/// <summary>
/// Describes reusable certificate transparency provider capabilities.
/// </summary>
[Flags]
public enum CtProviderCapabilities
{
    /// <summary>The provider does not advertise any CT capability.</summary>
    None = 0,

    /// <summary>The provider can expand a domain into observed subdomains.</summary>
    SubdomainExpansion = 1,

    /// <summary>The provider can query an exact host name.</summary>
    ExactHostLookup = 2,

    /// <summary>The provider can return historical rows for an exact host name.</summary>
    CertificateHistory = 4,

    /// <summary>The provider can return historical rows for a domain tree.</summary>
    DomainTreeHistory = 8,

    /// <summary>The provider can return the full certificate DER bytes.</summary>
    FullCertificateDer = 16,

    /// <summary>The provider can hydrate a metadata row into full certificate DER using a follow-up request.</summary>
    CertificateHydration = 32,

    /// <summary>The provider supports paging or cursor-based continuation.</summary>
    Pagination = 64,

    /// <summary>The provider supports durable cursor-based ingestion.</summary>
    DurableCursor = 128,

    /// <summary>The provider is a direct CT log ingestion source rather than a domain index.</summary>
    NativeLogIngestion = 256,

    /// <summary>The provider usually requires authentication for reliable production-scale use.</summary>
    AuthenticationRecommended = 512
}
