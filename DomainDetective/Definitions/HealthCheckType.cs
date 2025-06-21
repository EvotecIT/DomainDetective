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
        CERT,
        SECURITYTXT,
        SOA
    }
}