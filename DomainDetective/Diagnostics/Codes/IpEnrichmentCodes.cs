namespace DomainDetective;

internal static class IpEnrichmentCodes
{
    public const string NoIpsFound = "IP.Enrichment.NoIpsFound";
    public const string ResultsPresent = "IP.Enrichment.ResultsPresent";
    public const string ResultsCapped = "IP.Enrichment.ResultsCapped";
    public const string DnsQueryFailed = "IP.Enrichment.DNS.QueryFailed";
    public const string RdapLookupFailed = "IP.Enrichment.RDAP.LookupFailed";
    public const string ReverseDnsFailed = "IP.Enrichment.rDNS.LookupFailed";
    public const string PtrMissing = "IP.Enrichment.rDNS.PtrMissing";
    public const string HighAsnDiversity = "IP.Enrichment.ASN.HighDiversity";
}

