namespace DomainDetective;

/// <summary>
/// Supported threat intelligence sources.
/// </summary>
public enum ThreatIntelSource
{
    /// <summary>Google Safe Browsing service.</summary>
    GoogleSafeBrowsing,
    /// <summary>PhishTank phishing URL database.</summary>
    PhishTank,
    /// <summary>VirusTotal reputation service.</summary>
    VirusTotal,
    /// <summary>AbuseIPDB IP reputation database.</summary>
    AbuseIpDb,
    /// <summary>URLHaus (abuse.ch) URL and host blacklist.</summary>
    UrlHaus,
    /// <summary>OpenPhish phishing feed.</summary>
    OpenPhish
}
