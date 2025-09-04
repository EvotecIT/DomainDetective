namespace DomainDetective;

internal static class DnssecCodes {
    public const string RrsigExpiring = "DNSSEC.RRSIG.Expiring";
    public const string RootAnchorExpired = "DNSSEC.RootAnchor.Expired";
    public const string RootAnchorExpiring = "DNSSEC.RootAnchor.Expiring";
    public const string DsDigestLengthUnexpected = "DNSSEC.DS.DigestLengthUnexpected";
    public const string DsAlgorithmUnknown = "DNSSEC.DS.AlgorithmUnknown";
    public const string DsAlgorithmDeprecated = "DNSSEC.DS.AlgorithmDeprecated";
    public const string DnskeyNotAuthenticated = "DNSSEC.DNSKEY.NotAuthenticated";
    public const string DsMissing = "DNSSEC.DS.Missing";
    public const string DsNotAuthenticated = "DNSSEC.DS.NotAuthenticated";
    public const string DsMismatch = "DNSSEC.DS.Mismatch";
    public const string Nsec3OptOutRisk = "DNSSEC.NSEC3.OptOutRisk";
    public const string SignaturesValid = "DNSSEC.Signatures.Valid";
    public const string ChainValid = "DNSSEC.Chain.Valid";
}
