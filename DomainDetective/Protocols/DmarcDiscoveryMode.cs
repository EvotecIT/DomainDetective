namespace DomainDetective;

/// <summary>Chooses the DMARC discovery and organizational boundary contract.</summary>
public enum DmarcDiscoveryMode {
    /// <summary>RFC 9989 bounded DNS tree walking and explicit PSD boundaries.</summary>
    DnsTreeWalk,
    /// <summary>RFC 7489 exact-domain then public-suffix-list organizational fallback.</summary>
    LegacyPublicSuffix
}
