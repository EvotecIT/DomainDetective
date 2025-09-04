namespace DomainDetective;

/// <summary>
/// Describes the ordered methods used when looking up Autodiscover endpoints.
/// </summary>
public enum AutodiscoverMethod {
    /// <summary>Lookup using the _autodiscover._tcp SRV record.</summary>
    SrvRecord,
    /// <summary>Use HTTPS on the autodiscover subdomain.</summary>
    AutodiscoverSubdomainHttps,
    /// <summary>Use HTTPS on the root domain.</summary>
    RootDomainHttps,
    /// <summary>Follow HTTP redirect to an alternate host.</summary>
    HttpRedirect,
    /// <summary>Use HTTPS on the CNAME target revealed for autodiscover.</summary>
    CnameTargetHttps,
    /// <summary>Use HTTPS on the SRV target host:port.</summary>
    SrvTargetHttps,
    /// <summary>Use Outlook v2 JSON domain discovery endpoint.</summary>
    OutlookV2Json,
    /// <summary>POST Autodiscover request to URL returned by Outlook v2 JSON.</summary>
    OutlookV2JsonPost
}
