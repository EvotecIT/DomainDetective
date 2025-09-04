namespace DomainDetective;

internal static class TlsCodes {
    public const string LegacyEnabled = "TLS.LegacyEnabled";
    public const string LegacyOffered = "TLS.LegacyOffered";
    public const string SctMissing = "TLS.CT.SctMissing";
    public const string OcspMustStapleMissing = "TLS.OCSP.MustStapleMissing";
    public const string WeakCipherNegotiated = "TLS.Cipher.WeakNegotiated";
    public const string WeakKeyExchange = "TLS.Kex.Weak";
    public const string OcspStaplingPresent = "TLS.OCSP.StaplingPresent";
    public const string OcspStaplingMissing = "TLS.OCSP.StaplingMissing";
    public const string StrongProtocol = "TLS.Protocol.Strong";
    public const string PfsCipher = "TLS.Cipher.ForwardSecrecy";
}
