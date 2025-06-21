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
        MTASTS,
        CERT,
        SECURITYTXT
    }
}