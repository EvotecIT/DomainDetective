namespace DomainDetective;

internal static class DnssecCodes {
    public const string RrsigExpiring = "DNSSEC.RRSIG.Expiring";
    public const string RootAnchorExpired = "DNSSEC.RootAnchor.Expired";
    public const string RootAnchorExpiring = "DNSSEC.RootAnchor.Expiring";
    public const string DsDigestLengthUnexpected = "DNSSEC.DS.DigestLengthUnexpected";
    public const string DsAlgorithmUnknown = "DNSSEC.DS.AlgorithmUnknown";
    public const string DsAlgorithmDeprecated = "DNSSEC.DS.AlgorithmDeprecated";
}

