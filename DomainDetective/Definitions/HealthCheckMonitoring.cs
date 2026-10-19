namespace DomainDetective;

/// <summary>How a check suits continuous monitoring of a domain.</summary>
public enum CheckMonitoring {
    /// <summary>Cheap and meaningful on every monitoring run.</summary>
    Routine,
    /// <summary>Slow, rate-limited or slowly changing; run less often, for example weekly.</summary>
    Slow,
    /// <summary>Actively probes the domain's services (port scans, relay or resolver tests); run only with consent.</summary>
    Intrusive,
    /// <summary>Analyses a message, a log or another input rather than a domain; not monitored.</summary>
    NotPerDomain
}

/// <summary>Which checks suit continuous monitoring, and how often.</summary>
public static class HealthCheckMonitoring {
    /// <summary>
    /// How <paramref name="check"/> suits monitoring a domain: routinely, less often because it is slow or changes
    /// slowly, only for domains whose owner agreed because it actively probes services, or not at all because it
    /// analyses something other than a domain.
    /// </summary>
    public static CheckMonitoring For(HealthCheckType check) => check switch {
        HealthCheckType.MESSAGEHEADER or HealthCheckType.ARC or HealthCheckType.SMIMEA or HealthCheckType.DNSTUNNELING or
            HealthCheckType.MAILCLASSIFICATION => CheckMonitoring.NotPerDomain,
        HealthCheckType.PORTSCAN or HealthCheckType.PORTAVAILABILITY or HealthCheckType.OPENRELAY or HealthCheckType.OPENRESOLVER or
            HealthCheckType.ZONETRANSFER or HealthCheckType.DNSAMPLIFICATION or HealthCheckType.SNMP or
            HealthCheckType.DIRECTORYEXPOSURE => CheckMonitoring.Intrusive,
        HealthCheckType.SUBDOMAINS or HealthCheckType.CTTIMELINE or HealthCheckType.TYPOSQUATTING or HealthCheckType.RDAP or
            HealthCheckType.WHOIS or HealthCheckType.THREATINTEL or HealthCheckType.THREATFEED or HealthCheckType.IPNEIGHBOR or
            HealthCheckType.IPENRICHMENT or HealthCheckType.DNSPROPAGATION or HealthCheckType.DNSTRACE or HealthCheckType.SITEMAP or
            HealthCheckType.AGENTREADINESS or HealthCheckType.WEBSITE or HealthCheckType.MAILLATENCY or HealthCheckType.NTP => CheckMonitoring.Slow,
        _ => CheckMonitoring.Routine
    };
}
