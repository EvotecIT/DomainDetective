namespace DomainDetective {
    public enum HealthCheckType {
        DMARC,
        SPF,
        DKIM,
        MX,
        CAA,
        NS,
        DANE,
        DNSBL,
        DNSSEC,
        MTASTS,
        TLSRPT,
        BIMI,
        CERT,
        SECURITYTXT,
        SOA,
        OPENRELAY,
        STARTTLS,
        HTTP
    }
}