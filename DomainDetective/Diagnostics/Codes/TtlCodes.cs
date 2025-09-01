namespace DomainDetective;

internal static class TtlCodes {
    public const string TooShortForDnssec = "DNS.TTL.TooShortForDNSSEC";
    public const string TooShort = "DNS.TTL.TooShort";
    public const string TooLong = "DNS.TTL.TooLong";
    public const string A_AAAA_Mismatch = "DNS.TTL.A_AAAA.Mismatch";
    public const string NonUniformAcrossNS_A = "DNS.TTL.A.NonUniformAcrossNS";
    public const string NonUniformAcrossNS_AAAA = "DNS.TTL.AAAA.NonUniformAcrossNS";
    public const string NonUniformAcrossNS_NS = "DNS.TTL.NS.NonUniformAcrossNS";
    public const string NonUniformAcrossNS_CNAME = "DNS.TTL.CNAME.NonUniformAcrossNS";
}

