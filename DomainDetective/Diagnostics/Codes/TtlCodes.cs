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
    public const string Optimal = "DNS.TTL.Success.Optimal";
    public const string A_AAAA_Aligned = "DNS.TTL.Success.A_AAAA.Aligned";
    public const string UniformAcrossNS_A = "DNS.TTL.Success.A.UniformAcrossNS";
    public const string UniformAcrossNS_AAAA = "DNS.TTL.Success.AAAA.UniformAcrossNS";
    public const string UniformAcrossNS_NS = "DNS.TTL.Success.NS.UniformAcrossNS";
    public const string UniformAcrossNS_CNAME = "DNS.TTL.Success.CNAME.UniformAcrossNS";
    public const string NonUniformAcrossNS_TXT_SPF = "DNS.TTL.TXT.SPF.NonUniformAcrossNS";
    public const string UniformAcrossNS_TXT_SPF = "DNS.TTL.Success.TXT.SPF.UniformAcrossNS";
    public const string NonUniformAcrossNS_TXT_DMARC = "DNS.TTL.TXT.DMARC.NonUniformAcrossNS";
    public const string UniformAcrossNS_TXT_DMARC = "DNS.TTL.Success.TXT.DMARC.UniformAcrossNS";
    public const string NonUniformAcrossNS_TXT_DKIM = "DNS.TTL.TXT.DKIM.NonUniformAcrossNS";
    public const string UniformAcrossNS_TXT_DKIM = "DNS.TTL.Success.TXT.DKIM.UniformAcrossNS";
}

