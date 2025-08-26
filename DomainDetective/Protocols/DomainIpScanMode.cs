namespace DomainDetective;

/// <summary>
/// Controls which IPs are resolved and checked when a domain name is provided
/// for DNSBL analysis. Domain-based DNSBL checks are always performed.
/// </summary>
public enum DomainIpScanMode
{
    /// <summary>Resolve MX A and MX AAAA and check those IPs only.</summary>
    MxOnly = 0,
    /// <summary>Resolve MX A records only and check those IPs.</summary>
    MxAOnly = 1,
    /// <summary>Resolve MX AAAA records only and check those IPs.</summary>
    MxAAAAOnly = 2,
    /// <summary>Resolve apex A and AAAA and check those IPs only.</summary>
    ApexOnly = 3,
    /// <summary>Resolve apex A records only and check those IPs.</summary>
    ApexAOnly = 4,
    /// <summary>Resolve apex AAAA records only and check those IPs.</summary>
    ApexAAAAOnly = 5,
    /// <summary>Resolve both MX (A/AAAA) and apex (A/AAAA) and check all IPs.</summary>
    MxAndApex = 6,
    /// <summary>
    /// Default. Resolve MX (A/AAAA) and check those IPs; if none are obtained,
    /// fall back to apex A/AAAA and check those IPs.
    /// </summary>
    MxThenApexFallback = 7,
}

