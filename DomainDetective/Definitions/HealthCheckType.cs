namespace DomainDetective {
    public enum HealthCheckType {
        DMARC,
        SPF,
        DKIM,
        MX,
        CAA,
        DANE,
        DNSBL,
        DNSSEC,
        MTASTS,
        CERT,
        SECURITYTXT
    }
}