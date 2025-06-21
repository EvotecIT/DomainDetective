namespace DomainDetective {
    public enum HealthCheckType {
        DMARC,
        SPF,
        DKIM,
        MX,
        CAA,
        DANE,
        DNSBL,
        MTASTS,
        CERT,
        SECURITYTXT,
        SOA
    }
}