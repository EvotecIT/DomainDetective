namespace DomainDetective;

/// <summary>
/// Enumerates DNSSEC algorithms used in DS, DNSKEY and RRSIG records.
/// </summary>
public enum DnsAlgorithm {
    /// <summary>Algorithm is unknown.</summary>
    Unknown = -1,
    /// <summary>Delete DNSSEC record.</summary>
    DELETE = 0,
    /// <summary>RSAMD5 algorithm.</summary>
    RSAMD5 = 1,
    /// <summary>DH algorithm.</summary>
    DH = 2,
    /// <summary>DSA algorithm.</summary>
    DSA = 3,
    /// <summary>ECC algorithm.</summary>
    ECC = 4,
    /// <summary>RSASHA1 algorithm.</summary>
    RSASHA1 = 5,
    /// <summary>DSANSEC3SHA1 algorithm.</summary>
    DSANSEC3SHA1 = 6,
    /// <summary>RSASHA1NSEC3SHA1 algorithm.</summary>
    RSASHA1NSEC3SHA1 = 7,
    /// <summary>RSASHA256 algorithm.</summary>
    RSASHA256 = 8,
    /// <summary>Reserved algorithm number 9.</summary>
    RESERVED9 = 9,
    /// <summary>RSASHA512 algorithm.</summary>
    RSASHA512 = 10,
    /// <summary>Reserved algorithm number 11.</summary>
    RESERVED11 = 11,
    /// <summary>ECCGOST algorithm.</summary>
    ECCGOST = 12,
    /// <summary>ECDSAP256SHA256 algorithm.</summary>
    ECDSAP256SHA256 = 13,
    /// <summary>ECDSAP384SHA384 algorithm.</summary>
    ECDSAP384SHA384 = 14,
    /// <summary>ED25519 algorithm.</summary>
    ED25519 = 15,
    /// <summary>ED448 algorithm.</summary>
    ED448 = 16,
    /// <summary>SM2SM3 algorithm.</summary>
    SM2SM3 = 17,
    /// <summary>ECC-GOST12 algorithm.</summary>
    ECC_GOST12 = 23,
    /// <summary>INDIRECT algorithm.</summary>
    INDIRECT = 252,
    /// <summary>PRIVATEDNS algorithm.</summary>
    PRIVATEDNS = 253,
    /// <summary>PRIVATEOID algorithm.</summary>
    PRIVATEOID = 254,
    /// <summary>Reserved algorithm number 255.</summary>
    RESERVED255 = 255
}
