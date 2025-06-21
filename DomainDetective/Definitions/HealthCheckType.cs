namespace DomainDetective {
    public enum HealthCheckType {
        DMARC,
        SPF,
        DKIM,
        MX,
        CAA,
        DANE,
        DNSBL,
        CERT,
        SECURITYTXT
    }
}